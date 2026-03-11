use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::config::Config;
use crate::pairing::PairingRegistry;
use crate::rate_limit::RateLimitState;
use crate::room::{redact_code, validate_public_key, RoomManager};

/// Shared application state threaded through axum handlers.
pub struct AppState {
    pub room_manager: Arc<RoomManager>,
    pub rate_limit: Arc<RateLimitState>,
    pub config: Config,
    pub pairing: Arc<PairingRegistry>,
    pub desktop_connections: Arc<DashMap<String, mpsc::Sender<Message>>>,
    pub waiting_mobiles: Arc<DashMap<String, Vec<mpsc::Sender<Message>>>>,
}

// ---- Protocol messages ----

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientInit {
    CreateRoom {
        desktop_public_key: String,
    },
    JoinRoom {
        room_code: String,
        mobile_public_key: String,
    },
    RegisterDesktop {
        desktop_device_id: String,
        desktop_public_key: String,
    },
    ReconnectPaired {
        pairing_token: String,
        mobile_public_key: String,
    },
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    RoomCreated { room_code: String },
    PeerJoined { mobile_public_key: String },
    RoomJoined { desktop_public_key: String },
    RelayError { message: String },
    PeerDisconnected {},
    PeerOffline {},
    PeerOnline {},
    PairingEstablished { pairing_id: String },
    PairingRegistered { pairing_id: String },
    PairingRevoked { pairing_id: String },
}

/// Control messages sent by the desktop over an already-established
/// RegisterDesktop WebSocket to manage pairings.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum DesktopControl {
    RegisterPairing {
        pairing_token_hash: String,
        desktop_device_id: String,
        desktop_public_key: String,
        mobile_public_key: String,
        device_name: String,
    },
    RevokePairing {
        pairing_id: String,
    },
    RevokeAllPairings {
        desktop_device_id: String,
    },
}

fn server_msg(event: &ServerEvent) -> Message {
    Message::Text(serde_json::to_string(event).unwrap().into())
}

/// Axum handler that upgrades the HTTP connection to a WebSocket.
pub async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let max_size = state.config.max_message_size;
    ws.max_message_size(max_size)
        .on_upgrade(move |socket| handle_socket(socket, state, addr))
}

/// Top-level WebSocket session handler. Reads the first message to determine
/// the client role (desktop or mobile) and then enters the forwarding loop.
async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>, addr: SocketAddr) {
    let ip = addr.ip();

    // --- connection gate ---
    if let Err(reason) = state.rate_limit.try_add_connection(ip) {
        log::warn!("Rejecting connection from {}: {}", ip, reason);
        let _ = socket.send(server_msg(&ServerEvent::RelayError {
            message: reason,
        })).await;
        return;
    }

    log::info!("New WebSocket connection from {}", addr);

    // Allocate a per-connection id for message-rate limiting.
    let conn_id = state.rate_limit.next_connection_id();

    // Read the first (init) message with a timeout.
    let first_msg = match timeout(Duration::from_secs(10), socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => text,
        Ok(Some(Ok(_))) => {
            // Non-text first message
            state.rate_limit.remove_connection(ip);
            return;
        }
        _ => {
            // Timeout, error, or close
            state.rate_limit.remove_connection(ip);
            return;
        }
    };

    let init_msg = first_msg.to_string();

    let init: ClientInit = match serde_json::from_str(&init_msg) {
        Ok(v) => v,
        Err(e) => {
            let _ = socket.send(server_msg(&ServerEvent::RelayError {
                message: format!("invalid init message: {}", e),
            })).await;
            state.rate_limit.remove_connection(ip);
            return;
        }
    };

    match init {
        ClientInit::CreateRoom { desktop_public_key } => {
            handle_desktop(socket, &state, ip, addr, conn_id, desktop_public_key).await;
        }
        ClientInit::JoinRoom {
            room_code,
            mobile_public_key,
        } => {
            handle_mobile(socket, &state, ip, addr, conn_id, room_code, mobile_public_key).await;
        }
        ClientInit::RegisterDesktop {
            desktop_device_id,
            desktop_public_key,
        } => {
            handle_register_desktop(socket, &state, ip, addr, conn_id, desktop_device_id, desktop_public_key).await;
        }
        ClientInit::ReconnectPaired {
            pairing_token,
            mobile_public_key,
        } => {
            handle_reconnect_paired(socket, &state, ip, addr, conn_id, pairing_token, mobile_public_key).await;
        }
    }

    state.rate_limit.remove_connection(ip);
    log::info!("Connection from {} closed", addr);
}

// ---- Desktop flow (ephemeral room) ----

async fn handle_desktop(
    mut socket: WebSocket,
    state: &Arc<AppState>,
    ip: std::net::IpAddr,
    addr: SocketAddr,
    conn_id: u64,
    desktop_public_key: String,
) {
    // Rate-limit room creation per IP.
    if !state.rate_limit.check_room_creation(ip) {
        let _ = socket.send(server_msg(&ServerEvent::RelayError {
            message: "room creation rate limit exceeded".to_string(),
        })).await;
        return;
    }

    let room_code = match state.room_manager.create_room(desktop_public_key) {
        Ok(code) => code,
        Err(e) => {
            let _ = socket.send(server_msg(&ServerEvent::RelayError {
                message: e.to_string(),
            })).await;
            return;
        }
    };

    // Create the bounded mpsc channel for receiving messages destined for this desktop.
    let (desktop_tx, desktop_rx) = mpsc::channel::<Message>(128);
    state.room_manager.set_desktop_tx(&room_code, desktop_tx);

    // Tell the desktop which code to display.
    if socket.send(server_msg(&ServerEvent::RoomCreated {
        room_code: room_code.clone(),
    })).await.is_err() {
        state.room_manager.remove_room(&room_code);
        return;
    }

    log::info!("Desktop {} created room {}", addr, redact_code(&room_code));

    // Enter the bidirectional relay loop.
    relay_loop(state, &room_code, conn_id, true, socket, desktop_rx).await;

    // Cleanup: close the mobile side if still connected, then remove the room.
    if let Some(mobile_tx) = state.room_manager.get_mobile_tx(&room_code) {
        let disconnect_msg = serde_json::to_string(&ServerEvent::PeerDisconnected {}).unwrap_or_default();
        let _ = mobile_tx.try_send(Message::Text(disconnect_msg.into()));
        let _ = mobile_tx.try_send(Message::Close(None));
    }
    state.room_manager.remove_room(&room_code);
    log::info!("Room {} removed (desktop disconnected)", redact_code(&room_code));
}

// ---- Mobile flow (ephemeral room) ----

async fn handle_mobile(
    mut socket: WebSocket,
    state: &Arc<AppState>,
    ip: std::net::IpAddr,
    addr: SocketAddr,
    conn_id: u64,
    room_code: String,
    mobile_public_key: String,
) {
    // Rate-limit join attempts per IP.
    if !state.rate_limit.check_join_attempt(ip) {
        let _ = socket.send(server_msg(&ServerEvent::RelayError {
            message: "join rate limit exceeded".to_string(),
        })).await;
        return;
    }

    let join_result = match state.room_manager.join_room(&room_code, mobile_public_key.clone()) {
        Ok(r) => r,
        Err(e) => {
            let _ = socket.send(server_msg(&ServerEvent::RelayError {
                message: e.to_string(),
            })).await;
            return;
        }
    };

    // Create the bounded mpsc channel for receiving messages destined for this mobile.
    let (mobile_tx, mobile_rx) = mpsc::channel::<Message>(128);
    state.room_manager.set_mobile_tx(&room_code, mobile_tx);

    // Notify the desktop that the mobile has joined.
    if let Some(desktop_tx) = state.room_manager.get_desktop_tx(&room_code) {
        let _ = desktop_tx.try_send(server_msg(&ServerEvent::PeerJoined {
            mobile_public_key,
        }));
    }

    // Tell the mobile the desktop's public key.
    if socket.send(server_msg(&ServerEvent::RoomJoined {
        desktop_public_key: join_result.desktop_public_key,
    })).await.is_err() {
        state.room_manager.remove_room(&room_code);
        return;
    }

    log::info!("Mobile {} joined room {}", addr, redact_code(&room_code));

    // Enter the bidirectional relay loop.
    relay_loop(state, &room_code, conn_id, false, socket, mobile_rx).await;

    // Cleanup: close the desktop side if still connected, then remove the room.
    if let Some(desktop_tx) = state.room_manager.get_desktop_tx(&room_code) {
        let disconnect_msg = serde_json::to_string(&ServerEvent::PeerDisconnected {}).unwrap_or_default();
        let _ = desktop_tx.try_send(Message::Text(disconnect_msg.into()));
        let _ = desktop_tx.try_send(Message::Close(None));
    }
    state.room_manager.remove_room(&room_code);
    log::info!("Room {} removed (mobile disconnected)", redact_code(&room_code));
}

// ---- Persistent pairing: RegisterDesktop ----

async fn handle_register_desktop(
    mut socket: WebSocket,
    state: &Arc<AppState>,
    _ip: std::net::IpAddr,
    addr: SocketAddr,
    conn_id: u64,
    desktop_device_id: String,
    desktop_public_key: String,
) {
    // Validate public key
    if let Err(e) = validate_public_key(&desktop_public_key) {
        let _ = socket.send(server_msg(&ServerEvent::RelayError { message: e })).await;
        return;
    }

    log::info!(
        "Desktop {} registered as device {} from {}",
        &desktop_device_id,
        addr,
        conn_id
    );

    // Create an mpsc channel so mobiles (and waiting_mobiles) can send to this desktop.
    let (desktop_tx, mut desktop_rx) = mpsc::channel::<Message>(128);

    // Store in desktop_connections (replace any previous connection for this device).
    state.desktop_connections.insert(desktop_device_id.clone(), desktop_tx.clone());

    // Drain any waiting mobiles for this desktop.
    if let Some((_, waiters)) = state.waiting_mobiles.remove(&desktop_device_id) {
        for mobile_tx in waiters {
            let _ = mobile_tx.try_send(server_msg(&ServerEvent::PeerOnline {}));
        }
    }

    // Enter the desktop relay/control loop.
    // The desktop can send:
    //   1. Control messages (RegisterPairing, RevokePairing, RevokeAllPairings)
    //   2. Regular relay messages forwarded to the connected mobile
    loop {
        tokio::select! {
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(msg)) => {
                        match &msg {
                            Message::Close(_) => break,
                            Message::Ping(_) | Message::Pong(_) => continue,
                            _ => {}
                        }

                        // Per-connection message rate limit.
                        if !state.rate_limit.check_message_rate(conn_id) {
                            log::warn!("Message rate limit hit for registered desktop {}", desktop_device_id);
                            continue;
                        }

                        // Try to parse as a control message.
                        let text = match &msg {
                            Message::Text(t) => Some(t.to_string()),
                            _ => None,
                        };

                        if let Some(text) = text {
                            if let Ok(control) = serde_json::from_str::<DesktopControl>(&text) {
                                handle_desktop_control(&mut socket, state, &control).await;
                                continue;
                            }
                        }

                        // Forward non-control message to the connected paired mobile.
                        // The mobile's relay loop (paired_mobile_relay) stores its
                        // mpsc::Sender in waiting_mobiles keyed by desktop_device_id.
                        if let Some(mobiles) = state.waiting_mobiles.get(&desktop_device_id) {
                            let vals = mobiles.value();
                            if vals.len() == 1 {
                                let _ = vals[0].try_send(msg);
                            } else {
                                // Clone for each mobile when multiple are connected
                                for mobile_tx in vals.iter() {
                                    let fwd = match &msg {
                                        Message::Text(t) => Message::Text(t.clone()),
                                        Message::Binary(b) => Message::Binary(b.clone()),
                                        _ => continue,
                                    };
                                    let _ = mobile_tx.try_send(fwd);
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        log::debug!("WebSocket error for registered desktop {}: {}", desktop_device_id, e);
                        break;
                    }
                    None => break,
                }
            }

            // Messages from the peer (mobile) via mpsc channel.
            peer_msg = desktop_rx.recv() => {
                match peer_msg {
                    Some(msg) => {
                        if socket.send(msg).await.is_err() {
                            log::debug!("Failed to send to registered desktop {}", desktop_device_id);
                            break;
                        }
                    }
                    None => {
                        // All senders dropped — this shouldn't normally happen since
                        // we hold a clone in desktop_connections, but handle gracefully.
                        break;
                    }
                }
            }
        }
    }

    // Cleanup: remove from desktop_connections.
    state.desktop_connections.remove(&desktop_device_id);
    log::info!("Registered desktop {} disconnected", desktop_device_id);
}

/// Handle a control message from a registered desktop.
async fn handle_desktop_control(
    socket: &mut WebSocket,
    state: &Arc<AppState>,
    control: &DesktopControl,
) {
    match control {
        DesktopControl::RegisterPairing {
            pairing_token_hash,
            desktop_device_id,
            desktop_public_key,
            mobile_public_key,
            device_name,
        } => {
            match state.pairing.create_pairing(
                pairing_token_hash,
                desktop_device_id,
                desktop_public_key,
                mobile_public_key,
                device_name,
                state.config.pairing_expiry_days,
            ) {
                Ok(pairing_id) => {
                    let _ = socket
                        .send(server_msg(&ServerEvent::PairingRegistered {
                            pairing_id,
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = socket
                        .send(server_msg(&ServerEvent::RelayError { message: e }))
                        .await;
                }
            }
        }
        DesktopControl::RevokePairing { pairing_id } => {
            match state.pairing.revoke(pairing_id) {
                Ok(()) => {
                    let _ = socket
                        .send(server_msg(&ServerEvent::PairingRevoked {
                            pairing_id: pairing_id.clone(),
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = socket
                        .send(server_msg(&ServerEvent::RelayError { message: e }))
                        .await;
                }
            }
        }
        DesktopControl::RevokeAllPairings { desktop_device_id } => {
            match state.pairing.revoke_all_for_desktop(desktop_device_id) {
                Ok(count) => {
                    let _ = socket
                        .send(server_msg(&ServerEvent::RelayError {
                            message: format!("revoked {} pairing(s)", count),
                        }))
                        .await;
                }
                Err(e) => {
                    let _ = socket
                        .send(server_msg(&ServerEvent::RelayError { message: e }))
                        .await;
                }
            }
        }
    }
}

// ---- Persistent pairing: ReconnectPaired ----

async fn handle_reconnect_paired(
    mut socket: WebSocket,
    state: &Arc<AppState>,
    ip: std::net::IpAddr,
    addr: SocketAddr,
    conn_id: u64,
    pairing_token: String,
    _mobile_public_key: String,
) {
    // Rate-limit reconnect attempts using the existing join_attempt_limiter.
    if !state.rate_limit.check_join_attempt(ip) {
        let _ = socket.send(server_msg(&ServerEvent::RelayError {
            message: "reconnect rate limit exceeded".to_string(),
        })).await;
        return;
    }

    // Validate the pairing token.
    let record = match state.pairing.validate_token(&pairing_token) {
        Ok(r) => r,
        Err(e) => {
            let _ = socket.send(server_msg(&ServerEvent::RelayError {
                message: format!("pairing validation failed: {}", e),
            })).await;
            return;
        }
    };

    let desktop_device_id = record.desktop_device_id.clone();
    let pairing_id = record.pairing_id.clone();

    log::info!(
        "Mobile {} reconnecting via pairing {} to desktop {}",
        addr,
        &pairing_id[..8.min(pairing_id.len())],
        desktop_device_id
    );

    // Send pairing established confirmation.
    if socket.send(server_msg(&ServerEvent::PairingEstablished {
        pairing_id: pairing_id.clone(),
    })).await.is_err() {
        return;
    }

    // Check if the desktop is currently online.
    if let Some(desktop_tx) = state.desktop_connections.get(&desktop_device_id) {
        // Desktop is online — notify both sides and bridge.
        let _ = socket.send(server_msg(&ServerEvent::PeerOnline {})).await;

        // Notify the desktop that a paired mobile has connected.
        let _ = desktop_tx.try_send(server_msg(&ServerEvent::PeerJoined {
            mobile_public_key: record.mobile_public_key.clone(),
        }));

        let desktop_tx = desktop_tx.clone();
        drop(state.desktop_connections.get(&desktop_device_id));

        // Create mpsc channel for desktop -> mobile messages.
        let (mobile_tx, mut mobile_rx) = mpsc::channel::<Message>(128);

        // Store mobile_tx so the desktop relay loop can forward to us.
        // We use the desktop_connections entry's sender — messages from the
        // mobile go through the desktop's channel, and the desktop's loop
        // forwards them to the desktop WS. For desktop -> mobile, the desktop
        // loop writes to our mobile_tx... but the desktop doesn't have our
        // mobile_tx directly. We need a different bridging approach:
        //
        // The mobile sends messages through `desktop_tx` (the desktop's mpsc
        // sender stored in desktop_connections). The desktop relay loop reads
        // from its mpsc receiver and writes to the desktop WS. Similarly, the
        // desktop sends messages and the registered desktop handler forwards
        // them... but it doesn't know about this mobile's tx.
        //
        // Solution: We enter a relay loop here where:
        // - Mobile WS -> desktop_tx (desktop's mpsc channel)
        // - desktop sends back via desktop_tx which the desktop handler receives
        //   and writes to the desktop WS... but we need the reverse direction too.
        //
        // The simplest approach: the mobile's relay loop reads from the WS and
        // sends to the desktop via desktop_tx. For the reverse direction, we
        // need the desktop handler to know about mobile_tx. We can't easily
        // modify the desktop handler's loop from here, so instead we store
        // mobile_tx somewhere the desktop can find it.
        //
        // For now, use a direct relay approach: mobile reads from WS and sends
        // to desktop_tx; mobile reads from mobile_rx (which we need the desktop
        // to write to). We'll rely on the desktop_tx channel — when the desktop
        // handler gets a message from its WS, if it has an active paired mobile,
        // it should forward to that mobile's tx. But the current desktop handler
        // doesn't track per-mobile senders.
        //
        // Pragmatic approach: enter a bidirectional relay loop here. Mobile WS
        // messages go to desktop_tx. The desktop handler writes responses to its
        // own WS, and we need a way to get those back. Since the desktop handler
        // already has a relay loop reading from desktop_rx, and we're sending to
        // desktop_tx, the desktop handler will receive our messages and write
        // them to the desktop WS. For the reverse, we need to intercept what the
        // desktop sends. This is inherently tricky without restructuring.
        //
        // The cleanest approach for v1: just relay mobile <-> desktop via the
        // desktop_tx channel. The desktop handler's loop already sends to
        // desktop WS anything it receives from desktop_rx. So mobile -> desktop
        // works. For desktop -> mobile, the desktop handler would need to write
        // to our mobile_tx. We store it in a known location.
        //
        // Let's not over-complicate: we'll enter a simple relay loop.
        // Mobile WS read -> send to desktop_tx
        // mobile_rx read -> send to mobile WS
        // The desktop handler is responsible for writing to our mobile_tx when it
        // wants to send to the mobile. We don't modify the desktop handler's main
        // loop structure; instead we use a dedicated paired mobile approach.

        // We don't have a clean way to make the desktop handler aware of mobile_tx
        // without significant refactoring. For this implementation, we will not
        // use a separate mobile_tx for the desktop-to-mobile direction. Instead,
        // both directions flow through the desktop_tx channel, and the desktop
        // handler's existing loop handles forwarding. The mobile effectively
        // becomes another participant that sends/receives through the desktop's
        // channel.
        //
        // This means the mobile sends messages to desktop_tx (the desktop sees
        // them in its relay loop). The desktop's outgoing messages also go to
        // desktop_tx... no, that doesn't work.
        //
        // Let's take the straightforward approach: run a relay loop where the
        // mobile WS sends to desktop_tx, and we hold mobile_rx open. But we
        // also need to make the desktop handler aware of mobile_tx so it can
        // forward desktop messages to us. We'll store mobile_tx in a new DashMap
        // keyed by desktop_device_id.
        //
        // Actually, the simplest correct approach: don't use the desktop handler's
        // relay loop for forwarding at all. Instead, here in the mobile handler,
        // we directly hold desktop_tx and use our own mobile_rx. The desktop
        // handler doesn't need to know about us at all — it just reads from its
        // desktop_rx and writes to its WS. When we send to desktop_tx, the
        // desktop handler picks it up. For the reverse direction, we need the
        // desktop to write to mobile_tx. But the desktop handler writes everything
        // it reads from its WS to... nowhere specific for paired mobiles.
        //
        // OK, final clean approach: Store the mobile_tx in a DashMap keyed by
        // desktop_device_id. The desktop handler's loop checks this map when it
        // gets a non-control message from the desktop WS and forwards to the
        // mobile_tx. Let's use the waiting_mobiles map repurposed, or a new map.
        // Actually, let's keep it simple and store it in waiting_mobiles with a
        // single-element vec.

        // Store mobile_tx so the desktop handler can find it when it needs to
        // forward messages to the paired mobile.
        state.waiting_mobiles
            .entry(desktop_device_id.clone())
            .or_default()
            .push(mobile_tx);

        // Relay loop: mobile WS <-> desktop
        paired_mobile_relay(state, &desktop_device_id, conn_id, &mut socket, &mut mobile_rx, &desktop_tx).await;

        // Cleanup: remove our mobile_tx from the waiting list.
        // (It's already been consumed/closed, but clean up the entry.)
        state.waiting_mobiles.remove(&desktop_device_id);

        // Notify desktop that mobile disconnected.
        let _ = desktop_tx.try_send(server_msg(&ServerEvent::PeerDisconnected {}));

        log::info!(
            "Paired mobile {} disconnected from desktop {}",
            addr,
            desktop_device_id
        );
    } else {
        // Desktop is offline — notify mobile and wait.
        let _ = socket.send(server_msg(&ServerEvent::PeerOffline {})).await;

        log::info!(
            "Desktop {} offline, mobile {} waiting",
            desktop_device_id,
            addr
        );

        // Create a channel so the desktop can notify us when it comes online.
        let (notify_tx, mut notify_rx) = mpsc::channel::<Message>(16);

        // Add to waiting_mobiles.
        state.waiting_mobiles
            .entry(desktop_device_id.clone())
            .or_default()
            .push(notify_tx);

        // Wait for either: desktop comes online (PeerOnline via notify_rx),
        // mobile disconnects, or periodic ping to keep the connection alive.
        let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            tokio::select! {
                // Message from notify channel (desktop came online).
                notify_msg = notify_rx.recv() => {
                    match notify_msg {
                        Some(msg) => {
                            // Forward the PeerOnline message to the mobile.
                            if socket.send(msg).await.is_err() {
                                break;
                            }

                            // Desktop is now online — check if we can bridge.
                            if let Some(desktop_tx) = state.desktop_connections.get(&desktop_device_id) {
                                // Notify desktop that mobile is here.
                                let _ = desktop_tx.try_send(server_msg(&ServerEvent::PeerJoined {
                                    mobile_public_key: record.mobile_public_key.clone(),
                                }));

                                let desktop_tx = desktop_tx.clone();
                                drop(state.desktop_connections.get(&desktop_device_id));

                                // Create new mobile channel for the relay.
                                let (mobile_tx, mut mobile_rx) = mpsc::channel::<Message>(128);

                                state.waiting_mobiles
                                    .entry(desktop_device_id.clone())
                                    .or_default()
                                    .push(mobile_tx);

                                // Enter relay loop.
                                paired_mobile_relay(state, &desktop_device_id, conn_id, &mut socket, &mut mobile_rx, &desktop_tx).await;

                                state.waiting_mobiles.remove(&desktop_device_id);

                                let _ = desktop_tx.try_send(server_msg(&ServerEvent::PeerDisconnected {}));
                            }
                            break;
                        }
                        None => break,
                    }
                }

                // Mobile WebSocket message while waiting.
                ws_msg = socket.recv() => {
                    match ws_msg {
                        Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        Some(Ok(Message::Pong(_))) => continue,
                        Some(Ok(_)) => {
                            // Mobile sending messages while desktop is offline — drop them.
                            continue;
                        }
                    }
                }

                // Periodic ping to keep the connection alive.
                _ = ping_interval.tick() => {
                    if socket.send(Message::Ping(vec![].into())).await.is_err() {
                        break;
                    }
                }
            }
        }

        // Remove from waiting list.
        state.waiting_mobiles.remove(&desktop_device_id);

        log::info!("Waiting mobile {} disconnected", addr);
    }
}

/// Bidirectional relay between a paired mobile's WS and the desktop's mpsc channel.
async fn paired_mobile_relay(
    state: &Arc<AppState>,
    _desktop_device_id: &str,
    conn_id: u64,
    socket: &mut WebSocket,
    mobile_rx: &mut mpsc::Receiver<Message>,
    desktop_tx: &mpsc::Sender<Message>,
) {
    loop {
        tokio::select! {
            // Mobile WS -> desktop channel.
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(msg)) => {
                        match &msg {
                            Message::Close(_) => break,
                            Message::Ping(_) | Message::Pong(_) => continue,
                            _ => {}
                        }

                        if !state.rate_limit.check_message_rate(conn_id) {
                            continue;
                        }

                        match desktop_tx.try_send(msg) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                log::warn!("Desktop channel full — disconnecting paired mobile");
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                // Desktop disconnected.
                                let _ = socket.send(server_msg(&ServerEvent::PeerDisconnected {})).await;
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        log::debug!("Paired mobile WS error: {}", e);
                        break;
                    }
                    None => break,
                }
            }

            // Desktop -> mobile via mpsc channel.
            peer_msg = mobile_rx.recv() => {
                match peer_msg {
                    Some(msg) => {
                        if socket.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
}

// ---- Relay loop (for ephemeral rooms) ----

/// Bidirectional relay: reads from the WebSocket and forwards to the peer via
/// the room manager, while simultaneously reading from the mpsc channel and
/// writing to the WebSocket. Uses `tokio::select!` so that no `futures_util`
/// split is required.
async fn relay_loop(
    state: &Arc<AppState>,
    room_code: &str,
    conn_id: u64,
    is_desktop: bool,
    mut socket: WebSocket,
    mut from_peer_rx: mpsc::Receiver<Message>,
) {
    loop {
        tokio::select! {
            // Incoming message from the WebSocket (this client).
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(msg)) => {
                        match &msg {
                            Message::Close(_) => break,
                            Message::Ping(_) | Message::Pong(_) => continue,
                            _ => {}
                        }

                        // Per-connection message rate limit.
                        if !state.rate_limit.check_message_rate(conn_id) {
                            log::warn!(
                                "Message rate limit hit for conn {} in room {}",
                                conn_id, room_code
                            );
                            continue; // drop the message silently
                        }

                        // Touch the room so it doesn't expire while active.
                        state.room_manager.touch(room_code);

                        // Forward to the peer.
                        let peer_tx = if is_desktop {
                            state.room_manager.get_mobile_tx(room_code)
                        } else {
                            state.room_manager.get_desktop_tx(room_code)
                        };

                        if let Some(tx) = peer_tx {
                            match tx.try_send(msg) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::warn!(
                                        "Peer channel full in room {} — disconnecting slow consumer",
                                        room_code
                                    );
                                    break;
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    log::debug!("Peer channel closed in room {}", room_code);
                                    break;
                                }
                            }
                        }
                        // If the peer hasn't connected yet, messages are silently dropped.
                    }
                    Some(Err(e)) => {
                        log::debug!("WebSocket error in room {}: {}", room_code, e);
                        break;
                    }
                    None => {
                        // Stream ended.
                        break;
                    }
                }
            }

            // Incoming message from the peer (via mpsc channel).
            peer_msg = from_peer_rx.recv() => {
                match peer_msg {
                    Some(msg) => {
                        if socket.send(msg).await.is_err() {
                            log::debug!("Failed to send to WebSocket in room {}", room_code);
                            break;
                        }
                    }
                    None => {
                        // Channel closed (peer dropped their sender).
                        break;
                    }
                }
            }
        }
    }
}

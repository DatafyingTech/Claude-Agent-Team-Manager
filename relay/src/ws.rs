use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, State, WebSocketUpgrade};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::config::Config;
use crate::rate_limit::RateLimitState;
use crate::room::RoomManager;

/// Shared application state threaded through axum handlers.
pub struct AppState {
    pub room_manager: Arc<RoomManager>,
    pub rate_limit: Arc<RateLimitState>,
    pub config: Config,
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
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    RoomCreated { room_code: String },
    PeerJoined { mobile_public_key: String },
    RoomJoined { desktop_public_key: String },
    RelayError { message: String },
    PeerDisconnected {},
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
    }

    state.rate_limit.remove_connection(ip);
    log::info!("Connection from {} closed", addr);
}

// ---- Desktop flow ----

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

    log::info!("Desktop {} created room {}", addr, room_code);

    // Enter the bidirectional relay loop.
    relay_loop(state, &room_code, conn_id, true, socket, desktop_rx).await;

    // Cleanup: close the mobile side if still connected, then remove the room.
    if let Some(mobile_tx) = state.room_manager.get_mobile_tx(&room_code) {
        let disconnect_msg = serde_json::to_string(&ServerEvent::PeerDisconnected {}).unwrap_or_default();
        let _ = mobile_tx.try_send(Message::Text(disconnect_msg.into()));
        let _ = mobile_tx.try_send(Message::Close(None));
    }
    state.room_manager.remove_room(&room_code);
    log::info!("Room {} removed (desktop disconnected)", room_code);
}

// ---- Mobile flow ----

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

    log::info!("Mobile {} joined room {}", addr, room_code);

    // Enter the bidirectional relay loop.
    relay_loop(state, &room_code, conn_id, false, socket, mobile_rx).await;

    // Cleanup: close the desktop side if still connected, then remove the room.
    if let Some(desktop_tx) = state.room_manager.get_desktop_tx(&room_code) {
        let disconnect_msg = serde_json::to_string(&ServerEvent::PeerDisconnected {}).unwrap_or_default();
        let _ = desktop_tx.try_send(Message::Text(disconnect_msg.into()));
        let _ = desktop_tx.try_send(Message::Close(None));
    }
    state.room_manager.remove_room(&room_code);
    log::info!("Room {} removed (mobile disconnected)", room_code);
}

// ---- Relay loop ----

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

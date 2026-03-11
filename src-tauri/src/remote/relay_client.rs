use std::sync::Arc;
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures::{SinkExt, StreamExt};
use tauri::{AppHandle, Emitter};

/// Relay client connection state
pub struct RelayClient {
    /// Channel to send messages to the relay WebSocket
    tx: mpsc::UnboundedSender<String>,
    /// Shutdown signal
    shutdown: Arc<Notify>,
    /// Room code assigned by relay
    pub room_code: String,
}

/// Status returned to frontend
#[derive(serde::Serialize, Clone)]
pub struct RelayStatus {
    pub connected: bool,
    pub room_code: Option<String>,
    pub client_connected: bool,
}

impl RelayClient {
    /// Connect to the relay server, create a room, and start message forwarding.
    pub async fn connect(
        relay_url: &str,
        public_key: &str,
        app: AppHandle,
    ) -> Result<Self, String> {
        let url = format!("{}/ws", relay_url.trim_end_matches('/'));

        let (ws_stream, _) = connect_async(&url)
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let shutdown = Arc::new(Notify::new());

        // Send create_room message
        let create_msg = serde_json::json!({
            "type": "create_room",
            "desktop_public_key": public_key,
        });
        write
            .send(Message::Text(create_msg.to_string().into()))
            .await
            .map_err(|e| format!("Failed to send create_room: {}", e))?;

        // Wait for room_created response
        let room_code = loop {
            match read.next().await {
                Some(Ok(Message::Text(text))) => {
                    let msg: serde_json::Value = serde_json::from_str(&text)
                        .map_err(|e| format!("Invalid JSON from relay: {}", e))?;

                    match msg.get("type").and_then(|t| t.as_str()) {
                        Some("room_created") => {
                            let code = msg
                                .get("room_code")
                                .and_then(|c| c.as_str())
                                .ok_or("Missing room_code")?
                                .to_string();
                            break code;
                        }
                        Some("relay_error") => {
                            let error_msg = msg
                                .get("message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("Unknown relay error");
                            return Err(format!("Relay error: {}", error_msg));
                        }
                        _ => continue,
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    return Err("Connection closed before room creation".to_string());
                }
                Some(Err(e)) => {
                    return Err(format!("WebSocket error: {}", e));
                }
                _ => continue,
            }
        };

        let app_read = app.clone();
        let shutdown_read = shutdown.clone();
        let shutdown_write = shutdown.clone();

        // Spawn task to read from relay and emit Tauri events
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_read.notified() => break,
                    msg = read.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                // Try to parse as relay protocol message
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                                    match parsed.get("type").and_then(|t| t.as_str()) {
                                        Some("peer_joined") => {
                                            let _ = app_read.emit("relay:peer-joined", serde_json::json!({
                                                "mobile_public_key": parsed.get("mobile_public_key")
                                                    .and_then(|k| k.as_str())
                                                    .unwrap_or("")
                                            }));
                                            continue;
                                        }
                                        Some("peer_disconnected") => {
                                            let _ = app_read.emit("relay:peer-disconnected", serde_json::json!({}));
                                            continue;
                                        }
                                        Some("relay_error") => {
                                            log::warn!("Relay error: {:?}", parsed.get("message"));
                                            continue;
                                        }
                                        _ => {
                                            // Forward encrypted blob to frontend
                                            let _ = app_read.emit("relay:message", serde_json::json!({
                                                "data": text.to_string()
                                            }));
                                        }
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                let _ = app_read.emit("relay:disconnected", serde_json::json!({}));
                                break;
                            }
                            Some(Err(e)) => {
                                log::warn!("Relay read error: {}", e);
                                let _ = app_read.emit("relay:disconnected", serde_json::json!({}));
                                break;
                            }
                            _ => continue,
                        }
                    }
                }
            }
            // Signal the write task to stop when the read task exits
            shutdown_read.notify_waiters();
        });

        // Spawn task to write from channel to relay
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_write.notified() => break,
                    msg = rx.recv() => {
                        match msg {
                            Some(data) => {
                                if let Err(e) = write.send(Message::Text(data.into())).await {
                                    log::warn!("Relay write error: {}", e);
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            // Signal the read task to stop when the write task exits
            shutdown_write.notify_waiters();
        });

        Ok(RelayClient {
            tx,
            shutdown,
            room_code,
        })
    }

    /// Send an encrypted blob to the relay (forwarded to the mobile peer)
    pub fn send(&self, data: &str) -> Result<(), String> {
        self.tx
            .send(data.to_string())
            .map_err(|e| format!("Failed to send to relay: {}", e))
    }

    /// Disconnect from the relay
    pub fn disconnect(&self) {
        self.shutdown.notify_waiters();
    }
}

// ── Persistent Relay Client ─────────────────────────────────────────

/// Paired device info stored locally on the desktop.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PairedDeviceInfo {
    pub pairing_id: String,
    pub device_name: String,
    pub mobile_public_key: String,
    pub paired_at: u64,
    pub expires_at: u64,
    pub last_used: u64,
}

/// Persistent relay client for registered desktop mode.
///
/// Unlike `RelayClient` (ephemeral rooms), this maintains a long-lived
/// connection to the relay so paired mobiles can reconnect at any time
/// without needing a room code.
pub struct PersistentRelayClient {
    /// Channel to send messages to the relay WebSocket
    tx: mpsc::UnboundedSender<String>,
    /// Shutdown signal
    shutdown: Arc<Notify>,
    /// Desktop device ID (SHA-256 of public key)
    pub desktop_device_id: String,
    /// Locally tracked paired devices
    paired_devices: Arc<tokio::sync::Mutex<Vec<PairedDeviceInfo>>>,
    /// Public key of the currently connected mobile peer
    current_mobile_key: Arc<tokio::sync::Mutex<Option<String>>>,
    /// Oneshot for awaiting pairing_registered response
    pairing_response: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>>>,
}

impl PersistentRelayClient {
    /// Connect to the relay server in persistent (registered desktop) mode.
    pub async fn connect(
        relay_url: &str,
        desktop_device_id: &str,
        public_key: &str,
        app: AppHandle,
    ) -> Result<Self, String> {
        let url = format!("{}/ws", relay_url.trim_end_matches('/'));

        let (ws_stream, _) = connect_async(&url)
            .await
            .map_err(|e| format!("WebSocket connection failed: {}", e))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let shutdown = Arc::new(Notify::new());

        // Send register_desktop message
        let register_msg = serde_json::json!({
            "type": "register_desktop",
            "desktop_device_id": desktop_device_id,
            "desktop_public_key": public_key,
        });
        write
            .send(Message::Text(register_msg.to_string().into()))
            .await
            .map_err(|e| format!("Failed to send register_desktop: {}", e))?;

        let paired_devices = Arc::new(tokio::sync::Mutex::new(Vec::<PairedDeviceInfo>::new()));
        let current_mobile_key = Arc::new(tokio::sync::Mutex::new(None::<String>));
        let pairing_response = Arc::new(tokio::sync::Mutex::new(
            None::<tokio::sync::oneshot::Sender<String>>,
        ));

        let app_read = app.clone();
        let shutdown_read = shutdown.clone();
        let shutdown_write = shutdown.clone();
        let mobile_key_clone = current_mobile_key.clone();
        let pairing_resp_clone = pairing_response.clone();
        let paired_devs_clone = paired_devices.clone();

        // Emit registered event
        let _ = app.emit("relay:registered", serde_json::json!({}));

        // Spawn task to read from relay and emit Tauri events
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_read.notified() => break,
                    msg = read.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                                    match parsed.get("type").and_then(|t| t.as_str()) {
                                        Some("peer_joined") => {
                                            let key = parsed.get("mobile_public_key")
                                                .and_then(|k| k.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            *mobile_key_clone.lock().await = Some(key.clone());
                                            let _ = app_read.emit("relay:peer-joined", serde_json::json!({
                                                "mobile_public_key": key
                                            }));
                                        }
                                        Some("peer_disconnected") => {
                                            *mobile_key_clone.lock().await = None;
                                            let _ = app_read.emit("relay:peer-disconnected", serde_json::json!({}));
                                        }
                                        Some("pairing_registered") => {
                                            let pid = parsed.get("pairing_id")
                                                .and_then(|p| p.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            if let Some(sender) = pairing_resp_clone.lock().await.take() {
                                                let _ = sender.send(pid.clone());
                                            }
                                            let _ = app_read.emit("relay:pairing-registered", serde_json::json!({
                                                "pairing_id": pid
                                            }));
                                        }
                                        Some("pairing_revoked") => {
                                            let pid = parsed.get("pairing_id")
                                                .and_then(|p| p.as_str())
                                                .unwrap_or("")
                                                .to_string();
                                            paired_devs_clone.lock().await.retain(|d| d.pairing_id != pid);
                                            let _ = app_read.emit("relay:pairing-revoked", serde_json::json!({
                                                "pairing_id": pid
                                            }));
                                        }
                                        Some("relay_error") => {
                                            log::warn!("Persistent relay error: {:?}", parsed.get("message"));
                                        }
                                        _ => {
                                            // Forward encrypted blobs or unknown messages to frontend
                                            let _ = app_read.emit("relay:message", serde_json::json!({
                                                "data": text.to_string()
                                            }));
                                        }
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                let _ = app_read.emit("relay:disconnected", serde_json::json!({}));
                                break;
                            }
                            Some(Err(e)) => {
                                log::warn!("Persistent relay read error: {}", e);
                                let _ = app_read.emit("relay:disconnected", serde_json::json!({}));
                                break;
                            }
                            _ => continue,
                        }
                    }
                }
            }
            shutdown_read.notify_waiters();
        });

        // Spawn task to write from channel to relay
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_write.notified() => break,
                    msg = rx.recv() => {
                        match msg {
                            Some(data) => {
                                if let Err(e) = write.send(Message::Text(data.into())).await {
                                    log::warn!("Persistent relay write error: {}", e);
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
            shutdown_write.notify_waiters();
        });

        Ok(PersistentRelayClient {
            tx,
            shutdown,
            desktop_device_id: desktop_device_id.to_string(),
            paired_devices,
            current_mobile_key,
            pairing_response,
        })
    }

    /// Send an encrypted blob to the relay (forwarded to the paired mobile peer).
    pub fn send(&self, data: &str) -> Result<(), String> {
        self.tx
            .send(data.to_string())
            .map_err(|e| format!("Failed to send to relay: {}", e))
    }

    /// Issue a pairing token: generates a 256-bit random token, registers it
    /// with the relay (SHA-256 hash), and returns (raw_token, pairing_id, expires_at_ms).
    pub async fn issue_pairing_token(
        &self,
        desktop_public_key: &str,
        device_name: &str,
    ) -> Result<(String, String, u64), String> {
        // Generate token before any async operations to avoid Send issues
        let (token, token_hash) = {
            use sha2::{Digest, Sha256};
            let mut rng = rand::rng();
            let token_bytes: [u8; 32] = rand::Rng::random(&mut rng);
            let token = hex::encode(token_bytes);
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let token_hash = hex::encode(hasher.finalize());
            (token, token_hash)
        };

        let mobile_key = self
            .current_mobile_key
            .lock()
            .await
            .clone()
            .ok_or("No mobile peer currently connected")?;

        // Calculate expires_at (90 days from now, in ms)
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let expires_at = now_ms + (90 * 24 * 60 * 60 * 1000);

        // Set up oneshot to receive pairing_id from relay response
        let (sender, receiver) = tokio::sync::oneshot::channel::<String>();
        *self.pairing_response.lock().await = Some(sender);

        // Send register_pairing control message
        let control = serde_json::json!({
            "type": "register_pairing",
            "pairing_token_hash": token_hash,
            "desktop_device_id": self.desktop_device_id,
            "desktop_public_key": desktop_public_key,
            "mobile_public_key": mobile_key,
            "device_name": device_name,
        });
        self.tx
            .send(serde_json::to_string(&control).unwrap())
            .map_err(|e| format!("Failed to send register_pairing: {}", e))?;

        // Wait for pairing_registered response with 10s timeout
        let pairing_id = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            receiver,
        )
        .await
        .map_err(|_| "Pairing registration timed out".to_string())?
        .map_err(|_| "Pairing response channel closed".to_string())?;

        // Store in local paired devices list
        self.paired_devices.lock().await.push(PairedDeviceInfo {
            pairing_id: pairing_id.clone(),
            device_name: device_name.to_string(),
            mobile_public_key: mobile_key,
            paired_at: now_ms,
            expires_at,
            last_used: now_ms,
        });

        Ok((token, pairing_id, expires_at))
    }

    /// List locally tracked paired devices.
    pub async fn list_paired_devices(&self) -> Vec<PairedDeviceInfo> {
        self.paired_devices.lock().await.clone()
    }

    /// Revoke a pairing (sends control message to relay).
    pub fn revoke_pairing(&self, pairing_id: &str) -> Result<(), String> {
        let control = serde_json::json!({
            "type": "revoke_pairing",
            "pairing_id": pairing_id,
        });
        self.tx
            .send(serde_json::to_string(&control).unwrap())
            .map_err(|e| format!("Failed to send revoke_pairing: {}", e))
    }

    /// Disconnect from the relay.
    pub fn disconnect(&self) {
        self.shutdown.notify_waiters();
    }
}

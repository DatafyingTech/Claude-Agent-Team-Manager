use axum::extract::ws::Message;
use base64::Engine;
use dashmap::DashMap;
use rand::Rng;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

/// Base58 alphabet (Bitcoin-style, no 0/O/I/l).
const BASE58_CHARS: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ROOM_CODE_LEN: usize = 6;
const ROOM_CODE_PREFIX: &str = "ATM-";

/// A relay room that pairs exactly one desktop and one mobile client.
pub struct Room {
    /// Full room code including the "ATM-" prefix.
    pub code: String,
    /// Sender half for pushing messages to the desktop WebSocket task.
    pub desktop_tx: Option<mpsc::Sender<Message>>,
    /// Sender half for pushing messages to the mobile WebSocket task.
    pub mobile_tx: Option<mpsc::Sender<Message>>,
    /// Desktop's X25519 public key, base64-encoded.
    pub desktop_public_key: String,
    /// Mobile's X25519 public key, base64-encoded (set on join).
    pub mobile_public_key: Option<String>,
    /// When the room was created.
    pub created_at: Instant,
    /// Last time a message was forwarded through this room.
    pub last_activity: Instant,
    /// Whether a mobile client has joined.
    pub paired: bool,
}

/// Result returned when a mobile client successfully joins a room.
pub struct JoinResult {
    /// The desktop's public key so the mobile can derive a shared secret.
    pub desktop_public_key: String,
}

/// Validate that a public key string is valid base64 decoding to exactly 32 bytes.
pub fn validate_public_key(key: &str) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|e| format!("invalid public key: bad base64: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!(
            "invalid public key: expected 32 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(())
}

/// Redact a room code for logging, showing only the first 7 characters.
pub fn redact_code(code: &str) -> String {
    if code.len() > 7 {
        format!("{}...", &code[..7])
    } else {
        code.to_string()
    }
}

/// Thread-safe manager for all active rooms.
pub struct RoomManager {
    rooms: DashMap<String, Room>,
    /// Maximum number of rooms allowed.
    max_rooms: usize,
}

impl RoomManager {
    pub fn new(max_rooms: usize) -> Arc<Self> {
        Arc::new(Self {
            rooms: DashMap::new(),
            max_rooms,
        })
    }

    /// Generate a random base58 room code with the ATM- prefix.
    fn generate_code() -> String {
        let mut rng = rand::rng();
        let suffix: String = (0..ROOM_CODE_LEN)
            .map(|_| {
                let idx = rng.random_range(0..BASE58_CHARS.len());
                BASE58_CHARS[idx] as char
            })
            .collect();
        format!("{}{}", ROOM_CODE_PREFIX, suffix)
    }

    /// Create a new room for a desktop client. Returns the room code on
    /// success, or an error string if the server is at capacity.
    pub fn create_room(&self, desktop_public_key: String) -> Result<String, String> {
        validate_public_key(&desktop_public_key)?;

        if self.rooms.len() >= self.max_rooms {
            return Err("server at maximum room capacity".to_string());
        }

        // Generate a collision-free code with a retry limit.
        let mut code = None;
        for _ in 0..100 {
            let candidate = Self::generate_code();
            if !self.rooms.contains_key(&candidate) {
                code = Some(candidate);
                break;
            }
        }
        let code = code.ok_or_else(|| {
            "room code generation failed, server at capacity".to_string()
        })?;

        let now = Instant::now();
        let room = Room {
            code: code.clone(),
            desktop_tx: None,
            mobile_tx: None,
            desktop_public_key,
            mobile_public_key: None,
            created_at: now,
            last_activity: now,
            paired: false,
        };

        self.rooms.insert(code.clone(), room);
        Ok(code)
    }

    /// A mobile client joins an existing room by code. Returns the desktop's
    /// public key on success.
    pub fn join_room(&self, code: &str, mobile_public_key: String) -> Result<JoinResult, String> {
        validate_public_key(&mobile_public_key)?;

        let mut entry = self
            .rooms
            .get_mut(code)
            .ok_or_else(|| "room not found".to_string())?;

        let room = entry.value_mut();

        if room.paired {
            return Err("room already has two participants".to_string());
        }

        room.mobile_public_key = Some(mobile_public_key);
        room.paired = true;
        room.last_activity = Instant::now();

        Ok(JoinResult {
            desktop_public_key: room.desktop_public_key.clone(),
        })
    }

    /// Set the desktop's mpsc sender for a room.
    pub fn set_desktop_tx(&self, code: &str, tx: mpsc::Sender<Message>) {
        if let Some(mut entry) = self.rooms.get_mut(code) {
            entry.value_mut().desktop_tx = Some(tx);
        }
    }

    /// Set the mobile's mpsc sender for a room.
    pub fn set_mobile_tx(&self, code: &str, tx: mpsc::Sender<Message>) {
        if let Some(mut entry) = self.rooms.get_mut(code) {
            entry.value_mut().mobile_tx = Some(tx);
        }
    }

    /// Get a clone of the desktop's sender channel for a room.
    pub fn get_desktop_tx(&self, code: &str) -> Option<mpsc::Sender<Message>> {
        self.rooms
            .get(code)
            .and_then(|r| r.value().desktop_tx.clone())
    }

    /// Get a clone of the mobile's sender channel for a room.
    pub fn get_mobile_tx(&self, code: &str) -> Option<mpsc::Sender<Message>> {
        self.rooms
            .get(code)
            .and_then(|r| r.value().mobile_tx.clone())
    }

    /// Get the mobile public key for a room (set after join).
    #[allow(dead_code)]
    pub fn get_mobile_public_key(&self, code: &str) -> Option<String> {
        self.rooms
            .get(code)
            .and_then(|r| r.value().mobile_public_key.clone())
    }

    /// Check whether a room exists.
    #[allow(dead_code)]
    pub fn room_exists(&self, code: &str) -> bool {
        self.rooms.contains_key(code)
    }

    /// Remove a room by code.
    pub fn remove_room(&self, code: &str) {
        self.rooms.remove(code);
    }

    /// Touch the room's last-activity timestamp.
    pub fn touch(&self, code: &str) {
        if let Some(mut entry) = self.rooms.get_mut(code) {
            entry.value_mut().last_activity = Instant::now();
        }
    }

    /// Remove expired rooms:
    /// - Unpaired rooms older than `room_ttl`
    /// - Paired rooms idle longer than `idle_timeout`
    pub fn cleanup_expired(&self, room_ttl_secs: u64, idle_timeout_secs: u64) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for entry in self.rooms.iter() {
            let room = entry.value();
            let dominated = if room.paired {
                now.duration_since(room.last_activity).as_secs() > idle_timeout_secs
            } else {
                now.duration_since(room.created_at).as_secs() > room_ttl_secs
            };
            if dominated {
                to_remove.push(room.code.clone());
            }
        }

        for code in &to_remove {
            log::info!("Reaping expired room {}", redact_code(code));
            self.rooms.remove(code);
        }

        if !to_remove.is_empty() {
            log::info!("Cleaned up {} expired room(s)", to_remove.len());
        }
    }

    /// Number of active rooms.
    pub fn room_count(&self) -> usize {
        self.rooms.len()
    }

    /// Approximate number of connected WebSocket clients (each paired room
    /// counts as 2, each unpaired room as 1).
    pub fn connection_count(&self) -> usize {
        self.rooms
            .iter()
            .map(|entry| {
                let r = entry.value();
                let mut n = 0usize;
                if r.desktop_tx.is_some() {
                    n += 1;
                }
                if r.mobile_tx.is_some() {
                    n += 1;
                }
                n
            })
            .sum()
    }
}

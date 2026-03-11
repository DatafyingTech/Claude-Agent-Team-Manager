use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;

/// Relay server configuration, loaded from TOML.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Address to bind the server to.
    pub listen_addr: String,
    /// Maximum number of active rooms.
    pub max_rooms: usize,
    /// Maximum total WebSocket connections.
    pub max_connections: usize,
    /// Seconds before an unpaired room expires.
    pub room_ttl_secs: u64,
    /// Seconds of inactivity before a paired room is reaped.
    pub idle_timeout_secs: u64,
    /// Maximum WebSocket message size in bytes.
    pub max_message_size: usize,
    /// Maximum concurrent connections from a single IP.
    pub per_ip_max_connections: u32,
    /// Maximum rooms a single IP may create per hour.
    pub per_ip_max_rooms_per_hour: u32,
    /// Maximum forwarded messages per second per connection.
    pub msg_rate_limit_per_sec: u32,
    /// How many days a pairing token remains valid.
    pub pairing_expiry_days: u64,
    /// Directory for persistent data (SQLite, etc.).
    pub data_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_string(),
            max_rooms: 500,
            max_connections: 2000,
            room_ttl_secs: 300,
            idle_timeout_secs: 1800,
            max_message_size: 65_536,
            per_ip_max_connections: 5,
            per_ip_max_rooms_per_hour: 10,
            msg_rate_limit_per_sec: 100,
            pairing_expiry_days: 90,
            data_dir: "./data".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from the path given by `RELAY_CONFIG`, or from
    /// `relay-config.toml` in the current working directory. If neither file
    /// exists, fall back to compiled-in defaults.
    pub fn load() -> Self {
        // 1. Try RELAY_CONFIG env var
        if let Ok(path) = env::var("RELAY_CONFIG") {
            if let Some(cfg) = Self::from_file(&path) {
                log::info!("Loaded config from RELAY_CONFIG={}", path);
                return cfg;
            }
            log::warn!(
                "RELAY_CONFIG={} could not be read; trying relay-config.toml",
                path
            );
        }

        // 2. Try relay-config.toml in cwd
        let default_path = "relay-config.toml";
        if Path::new(default_path).exists() {
            if let Some(cfg) = Self::from_file(default_path) {
                log::info!("Loaded config from {}", default_path);
                return cfg;
            }
        }

        // 3. Defaults
        log::info!("No config file found; using built-in defaults");
        Self::default()
    }

    fn from_file(path: &str) -> Option<Self> {
        let contents = fs::read_to_string(path).ok()?;
        match toml::from_str::<Config>(&contents) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                log::error!("Failed to parse config file {}: {}", path, e);
                None
            }
        }
    }
}

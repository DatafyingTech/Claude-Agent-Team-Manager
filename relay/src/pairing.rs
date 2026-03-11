use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// A persistent pairing record stored in SQLite.
#[allow(dead_code)]
pub struct PairingRecord {
    pub pairing_id: String,
    pub token_hash: String,
    pub desktop_device_id: String,
    pub desktop_public_key: String,
    pub mobile_public_key: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used: i64,
    pub device_name: String,
    pub revoked: bool,
}

/// Thread-safe pairing registry backed by SQLite.
pub struct PairingRegistry {
    db: Mutex<Connection>,
}

impl PairingRegistry {
    /// Open (or create) the SQLite database at `data_dir/pairings.db` and
    /// ensure the schema exists.
    pub fn new(data_dir: &str) -> Self {
        let db_path = format!("{}/pairings.db", data_dir);
        let conn = Connection::open(&db_path)
            .unwrap_or_else(|e| panic!("Failed to open pairing database at {}: {}", db_path, e));

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pairings (
                pairing_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                desktop_device_id TEXT NOT NULL,
                desktop_public_key TEXT NOT NULL,
                mobile_public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_used INTEGER NOT NULL,
                device_name TEXT NOT NULL DEFAULT '',
                revoked INTEGER NOT NULL DEFAULT 0
            )",
        )
        .expect("Failed to create pairings table");

        Self {
            db: Mutex::new(conn),
        }
    }

    /// SHA-256 hash a token string, returning the hex digest.
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn now_epoch() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Insert a new pairing record. Returns the generated pairing_id.
    pub fn create_pairing(
        &self,
        token_hash: &str,
        desktop_device_id: &str,
        desktop_public_key: &str,
        mobile_public_key: &str,
        device_name: &str,
        expiry_days: u64,
    ) -> Result<String, String> {
        let pairing_id = uuid::Uuid::new_v4().to_string();
        let now = Self::now_epoch();
        let expires_at = now + (expiry_days as i64 * 86400);

        let db = self.db.lock().map_err(|e| format!("db lock error: {}", e))?;
        db.execute(
            "INSERT INTO pairings (pairing_id, token_hash, desktop_device_id, desktop_public_key, mobile_public_key, created_at, expires_at, last_used, device_name, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
            rusqlite::params![
                pairing_id,
                token_hash,
                desktop_device_id,
                desktop_public_key,
                mobile_public_key,
                now,
                expires_at,
                now,
                device_name,
            ],
        )
        .map_err(|e| format!("failed to insert pairing: {}", e))?;

        log::info!(
            "Created pairing {} for desktop {}",
            &pairing_id[..8],
            desktop_device_id
        );
        Ok(pairing_id)
    }

    /// Look up a pairing by raw token, check expiry and revocation, and
    /// update `last_used`. Returns the record on success.
    pub fn validate_token(&self, token: &str) -> Result<PairingRecord, String> {
        let hash = Self::hash_token(token);
        let db = self.db.lock().map_err(|e| format!("db lock error: {}", e))?;

        let record = db
            .query_row(
                "SELECT pairing_id, token_hash, desktop_device_id, desktop_public_key, mobile_public_key, created_at, expires_at, last_used, device_name, revoked
                 FROM pairings WHERE token_hash = ?1",
                rusqlite::params![hash],
                |row| {
                    Ok(PairingRecord {
                        pairing_id: row.get(0)?,
                        token_hash: row.get(1)?,
                        desktop_device_id: row.get(2)?,
                        desktop_public_key: row.get(3)?,
                        mobile_public_key: row.get(4)?,
                        created_at: row.get(5)?,
                        expires_at: row.get(6)?,
                        last_used: row.get(7)?,
                        device_name: row.get(8)?,
                        revoked: row.get::<_, i32>(9)? != 0,
                    })
                },
            )
            .map_err(|_| "pairing not found".to_string())?;

        if record.revoked {
            return Err("pairing has been revoked".to_string());
        }

        let now = Self::now_epoch();
        if now > record.expires_at {
            return Err("pairing has expired".to_string());
        }

        // Touch last_used
        let _ = db.execute(
            "UPDATE pairings SET last_used = ?1 WHERE pairing_id = ?2",
            rusqlite::params![now, record.pairing_id],
        );

        Ok(record)
    }

    /// Revoke a single pairing by id.
    pub fn revoke(&self, pairing_id: &str) -> Result<(), String> {
        let db = self.db.lock().map_err(|e| format!("db lock error: {}", e))?;
        let updated = db
            .execute(
                "UPDATE pairings SET revoked = 1 WHERE pairing_id = ?1",
                rusqlite::params![pairing_id],
            )
            .map_err(|e| format!("revoke failed: {}", e))?;

        if updated == 0 {
            return Err("pairing not found".to_string());
        }
        log::info!("Revoked pairing {}", &pairing_id[..8.min(pairing_id.len())]);
        Ok(())
    }

    /// Revoke all pairings for a given desktop device. Returns how many were revoked.
    pub fn revoke_all_for_desktop(&self, desktop_device_id: &str) -> Result<u64, String> {
        let db = self.db.lock().map_err(|e| format!("db lock error: {}", e))?;
        let updated = db
            .execute(
                "UPDATE pairings SET revoked = 1 WHERE desktop_device_id = ?1 AND revoked = 0",
                rusqlite::params![desktop_device_id],
            )
            .map_err(|e| format!("revoke_all failed: {}", e))?;

        log::info!(
            "Revoked {} pairing(s) for desktop {}",
            updated,
            desktop_device_id
        );
        Ok(updated as u64)
    }

    /// List all pairings for a given desktop device (including revoked/expired).
    #[allow(dead_code)]
    pub fn list_for_desktop(&self, desktop_device_id: &str) -> Result<Vec<PairingRecord>, String> {
        let db = self.db.lock().map_err(|e| format!("db lock error: {}", e))?;
        let mut stmt = db
            .prepare(
                "SELECT pairing_id, token_hash, desktop_device_id, desktop_public_key, mobile_public_key, created_at, expires_at, last_used, device_name, revoked
                 FROM pairings WHERE desktop_device_id = ?1 ORDER BY created_at DESC",
            )
            .map_err(|e| format!("query failed: {}", e))?;

        let rows = stmt
            .query_map(rusqlite::params![desktop_device_id], |row| {
                Ok(PairingRecord {
                    pairing_id: row.get(0)?,
                    token_hash: row.get(1)?,
                    desktop_device_id: row.get(2)?,
                    desktop_public_key: row.get(3)?,
                    mobile_public_key: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    last_used: row.get(7)?,
                    device_name: row.get(8)?,
                    revoked: row.get::<_, i32>(9)? != 0,
                })
            })
            .map_err(|e| format!("query failed: {}", e))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| format!("row error: {}", e))?);
        }
        Ok(records)
    }

    /// Delete all expired records from the database. Returns how many were removed.
    pub fn cleanup_expired(&self) -> usize {
        let now = Self::now_epoch();
        let db = match self.db.lock() {
            Ok(db) => db,
            Err(_) => return 0,
        };
        match db.execute(
            "DELETE FROM pairings WHERE expires_at < ?1",
            rusqlite::params![now],
        ) {
            Ok(n) => {
                if n > 0 {
                    log::info!("Cleaned up {} expired pairing(s)", n);
                }
                n
            }
            Err(e) => {
                log::error!("Failed to cleanup expired pairings: {}", e);
                0
            }
        }
    }

    /// Count of active (non-revoked, non-expired) pairings.
    pub fn active_pairing_count(&self) -> usize {
        let now = Self::now_epoch();
        let db = match self.db.lock() {
            Ok(db) => db,
            Err(_) => return 0,
        };
        db.query_row(
            "SELECT COUNT(*) FROM pairings WHERE revoked = 0 AND expires_at >= ?1",
            rusqlite::params![now],
            |row| row.get::<_, usize>(0),
        )
        .unwrap_or(0)
    }
}

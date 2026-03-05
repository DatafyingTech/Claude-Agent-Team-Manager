use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Centralized rate-limiting and connection-tracking state.
pub struct RateLimitState {
    /// Per-IP room creation limiter (N per hour).
    room_creation_limiter:
        RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>,

    /// Per-connection message rate limiter, keyed by a unique connection id.
    message_limiter:
        RateLimiter<u64, DashMapStateStore<u64>, DefaultClock>,

    /// Per-IP join attempt limiter (10 per minute).
    join_attempt_limiter:
        RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>,

    /// Global connection counter.
    global_connections: AtomicUsize,

    /// Per-IP connection counter.
    ip_connections: DashMap<IpAddr, u32>,

    /// Limits from config.
    pub max_connections: usize,
    pub per_ip_max_connections: u32,

    /// Monotonic connection id generator.
    next_conn_id: AtomicUsize,
}

impl RateLimitState {
    pub fn new(
        per_ip_max_rooms_per_hour: u32,
        msg_rate_limit_per_sec: u32,
        max_connections: usize,
        per_ip_max_connections: u32,
    ) -> Arc<Self> {
        let room_quota = Quota::per_hour(
            NonZeroU32::new(per_ip_max_rooms_per_hour).unwrap_or(NonZeroU32::new(10).unwrap()),
        );
        let msg_quota = Quota::per_second(
            NonZeroU32::new(msg_rate_limit_per_sec).unwrap_or(NonZeroU32::new(100).unwrap()),
        );

        let join_quota = Quota::per_minute(NonZeroU32::new(10).unwrap());

        Arc::new(Self {
            room_creation_limiter: RateLimiter::dashmap(room_quota),
            message_limiter: RateLimiter::dashmap(msg_quota),
            join_attempt_limiter: RateLimiter::dashmap(join_quota),
            global_connections: AtomicUsize::new(0),
            ip_connections: DashMap::new(),
            max_connections,
            per_ip_max_connections,
            next_conn_id: AtomicUsize::new(1),
        })
    }

    /// Allocate a unique connection id.
    pub fn next_connection_id(&self) -> u64 {
        self.next_conn_id.fetch_add(1, Ordering::Relaxed) as u64
    }

    // ---- room creation rate limiting ----

    /// Returns `true` if the IP is allowed to create another room right now.
    pub fn check_room_creation(&self, ip: IpAddr) -> bool {
        self.room_creation_limiter.check_key(&ip).is_ok()
    }

    // ---- join attempt rate limiting ----

    /// Returns `true` if the IP is allowed another join attempt right now.
    /// Consumes a rate-limit token on each call.
    pub fn check_join_attempt(&self, ip: IpAddr) -> bool {
        self.join_attempt_limiter.check_key(&ip).is_ok()
    }

    // ---- message rate limiting ----

    /// Returns `true` if this connection may send another message right now.
    pub fn check_message_rate(&self, conn_id: u64) -> bool {
        self.message_limiter.check_key(&conn_id).is_ok()
    }

    // ---- connection tracking ----

    /// Try to register a new connection from `ip`. Returns `Ok(())` if allowed,
    /// or `Err(reason)` if the connection should be rejected.
    pub fn try_add_connection(&self, ip: IpAddr) -> Result<(), String> {
        let prev = self.global_connections.fetch_add(1, Ordering::AcqRel);
        if prev >= self.max_connections {
            self.global_connections.fetch_sub(1, Ordering::AcqRel);
            return Err("Server at maximum capacity".into());
        }

        let mut over_limit = false;
        self.ip_connections
            .entry(ip)
            .and_modify(|count| {
                if *count >= self.per_ip_max_connections {
                    over_limit = true;
                } else {
                    *count += 1;
                }
            })
            .or_insert(1);

        if over_limit {
            self.global_connections.fetch_sub(1, Ordering::AcqRel);
            return Err("Too many connections from this IP".into());
        }

        Ok(())
    }

    /// Release a connection slot for `ip`.
    pub fn remove_connection(&self, ip: IpAddr) {
        self.global_connections.fetch_sub(1, Ordering::AcqRel);
        let should_remove = {
            if let Some(mut entry) = self.ip_connections.get_mut(&ip) {
                let v = entry.value_mut();
                if *v <= 1 {
                    true
                } else {
                    *v -= 1;
                    false
                }
            } else {
                false
            }
        };
        if should_remove {
            self.ip_connections.remove(&ip);
        }
    }
}

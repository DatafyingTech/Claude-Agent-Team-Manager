mod config;
mod health;
mod rate_limit;
mod room;
mod ws;

use axum::Router;
use axum::routing::get;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_http::cors::CorsLayer;

use crate::config::Config;
use crate::health::{HealthState, health_handler};
use crate::rate_limit::RateLimitState;
use crate::room::RoomManager;
use crate::ws::{AppState, ws_upgrade};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let config = Config::load();
    log::info!("ATM Relay v{}", env!("CARGO_PKG_VERSION"));
    log::info!("Listening on {}", config.listen_addr);
    log::info!(
        "Max rooms: {}, Max connections: {}, Room TTL: {}s, Idle timeout: {}s",
        config.max_rooms,
        config.max_connections,
        config.room_ttl_secs,
        config.idle_timeout_secs,
    );

    let room_manager = RoomManager::new(config.max_rooms);
    let rate_limit = RateLimitState::new(
        config.per_ip_max_rooms_per_hour,
        config.msg_rate_limit_per_sec,
        config.max_connections,
        config.per_ip_max_connections,
    );

    let started_at = Instant::now();

    // Shared state for the WebSocket handler.
    let app_state = Arc::new(AppState {
        room_manager: Arc::clone(&room_manager),
        rate_limit: Arc::clone(&rate_limit),
        config: config.clone(),
    });

    // Shared state for the health endpoint.
    let health_state = Arc::new(HealthState {
        room_manager: Arc::clone(&room_manager),
        started_at,
    });

    // Background task: periodically reap expired rooms.
    {
        let rm = Arc::clone(&room_manager);
        let room_ttl = config.room_ttl_secs;
        let idle_timeout = config.idle_timeout_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                rm.cleanup_expired(room_ttl, idle_timeout);
            }
        });
    }

    // /health gets no CORS layer; /ws gets permissive CORS for mobile web clients.
    let health_router = Router::new()
        .route("/health", get(health_handler).with_state(health_state));

    let ws_router = Router::new()
        .route("/ws", get(ws_upgrade).with_state(app_state))
        .layer(CorsLayer::permissive());

    let app = health_router.merge(ws_router);

    let addr: SocketAddr = config
        .listen_addr
        .parse()
        .expect("invalid listen_addr in config");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    log::info!("Server ready");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}

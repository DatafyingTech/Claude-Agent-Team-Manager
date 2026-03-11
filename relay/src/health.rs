use axum::extract::State;
use axum::extract::ws::Message;
use axum::response::Json;
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

use crate::pairing::PairingRegistry;
use crate::room::RoomManager;

/// Shared state needed by the health endpoint.
pub struct HealthState {
    pub room_manager: Arc<RoomManager>,
    pub pairing: Arc<PairingRegistry>,
    pub desktop_connections: Arc<DashMap<String, mpsc::Sender<Message>>>,
    pub started_at: Instant,
}

/// JSON body returned by `GET /health`.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub rooms: usize,
    pub connections: usize,
    pub active_pairings: usize,
    pub registered_desktops: usize,
    pub uptime_seconds: u64,
}

/// Handler for `GET /health`.
pub async fn health_handler(
    State(state): State<Arc<HealthState>>,
) -> Json<HealthResponse> {
    let uptime = Instant::now()
        .duration_since(state.started_at)
        .as_secs();

    Json(HealthResponse {
        status: "ok",
        rooms: state.room_manager.room_count(),
        connections: state.room_manager.connection_count(),
        active_pairings: state.pairing.active_pairing_count(),
        registered_desktops: state.desktop_connections.len(),
        uptime_seconds: uptime,
    })
}

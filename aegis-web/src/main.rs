use axum::{routing::{get, post}, Json, Router, extract::State};
use std::sync::Arc;
use tokio::sync::broadcast;
use aegis_common::{SecurityEvent, AegisCommand};

struct WebState {
    pub tx: broadcast::Sender<AegisCommand>,
}

#[tokio::main]
async fn main() {
    let (tx, _) = broadcast::channel::<AegisCommand>(100);
    let shared_state = Arc::new(WebState { tx });

    let app = Router::new()
        .route("/api/events", get(stream_events)) // WebSocket for live feed
        .route("/api/command", post(handle_command))
        .route("/api/policy", get(get_active_policy))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:9000").await.unwrap();
    println!("[AEGIS-WEB] Dashboard API live at http://127.0.0.1:9000");
    axum::serve(listener, app).await.unwrap();
}

async fn handle_command(
    State(state): State<Arc<WebState>>,
    Json(cmd): Json<AegisCommand>,
) -> &'static str {
    // Send the command down to the Daemon
    let _ = state.tx.send(cmd);
    "Command Sent"
}

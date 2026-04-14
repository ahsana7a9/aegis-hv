use ax_core::extract::State;
use axum::{routing::{get, post}, Json, Router};
use std::sync::Arc;
use tokio::sync::broadcast;
use aegis_common::AegisCommand;

// Shared state between different API routes
pub struct WebState {
    pub tx: broadcast::Sender<AegisCommand>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Initialize the internal communication channel
    let (tx, _) = broadcast::channel::<AegisCommand>(1024);
    let shared_state = Arc::new(WebState { tx });

    // 2. Build our REST API
    let app = Router::new()
        // Command route: Send 'Kill' or 'SwitchMode' from the Web UI
        .route("/api/command", post(handle_command))
        // Policy route: View the current guard rules
        .route("/api/policy", get(|| async { "Policy View Not Implemented" }))
        .with_state(shared_state);

    // 3. Launch the Server
    let addr = "127.0.0.1:9000";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!(" [AEGIS-WEB] Dashboard API online at http://{}", addr);
    
    axum::serve(listener, app).await?;
    
    Ok(())
}

/// Receives JSON commands from the frontend and broadcasts them to the Daemon
async fn handle_command(
    State(state): State<Arc<WebState>>,
    Json(cmd): Json<AegisCommand>,
) -> Json<serde_json::Value> {
    println!("[AEGIS-WEB] Received Remote Command: {:?}", cmd);
    
    match state.tx.send(cmd) {
        Ok(_) => Json(serde_json::json!({ "status": "success", "message": "Command dispatched to Daemon" })),
        Err(_) => Json(serde_json::json!({ "status": "error", "message": "Daemon communication channel closed" })),
    }
}

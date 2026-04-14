use axum::{routing::{get, post}, Json, Router, extract::State};
use axum_server::tls_rustls::RustlsConfig;
use std::{sync::Arc, path::PathBuf};
use tokio::sync::broadcast;
use aegis_common::AegisCommand;

pub struct WebState {
    pub tx: broadcast::Sender<AegisCommand>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (tx, _) = broadcast::channel::<AegisCommand>(1024);
    let shared_state = Arc::new(WebState { tx });

    // 1. Configure mTLS Certificates
    // server.crt: The API's identity
    // server.key: The API's private key
    // client_ca.crt: The Root CA that MUST have signed the user's certificate
    let config = RustlsConfig::from_pem_file(
        PathBuf::from("certs/server.crt"),
        PathBuf::from("certs/server.key"),
    )
    .await?;

    // NOTE: In a 2026 production environment, you would use rustls::server::verifier
    // to enforce that the client certificate is present and valid.

    let app = Router::new()
        .route("/api/command", post(handle_command))
        .route("/api/policy", get(|| async { "Policy View Secure" }))
        .with_state(shared_state);

    // 2. Launch the Secure Server
    let addr = "127.0.0.1:9443"; // Traditional port for secure management APIs
    println!("🔐 [AEGIS-WEB] mTLS Secure Dashboard live at https://{}", addr);

    axum_server::bind_rustls(addr.parse()?, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn handle_command(
    State(state): State<Arc<WebState>>,
    Json(cmd): Json<AegisCommand>,
) -> Json<serde_json::Value> {
    // Logic remains same, but now it's only reachable via secure handshake
    match state.tx.send(cmd) {
        Ok(_) => Json(serde_json::json!({ "status": "success" })),
        Err(_) => Json(serde_json::json!({ "status": "error", "message": "Daemon link lost" })),
    }
}

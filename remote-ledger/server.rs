use axum::{
    routing::post,
    Router,
    Json,
    extract::State,
    http::StatusCode,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use anyhow::{Result, anyhow};
use ed25519_dalek::PublicKey;

mod store;
mod verify;

use store::LedgerStore;
use verify::{LedgerEnvelope, verify_entry};

// ─────────────────────────────────────────────
// SHARED STATE
// ─────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    store: Arc<LedgerStore>,
    state: Arc<Mutex<(u64, String)>>, // (last_index, last_hash)
    pubkey: PublicKey,
}

// ─────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────

#[tokio::main]
async fn main() {

    // 🔐 Load public key (must match supervisor signer)
    let pubkey_bytes = std::fs::read("pubkey.bin")
        .expect("Missing pubkey.bin");
    let pubkey = PublicKey::from_bytes(&pubkey_bytes)
        .expect("Invalid public key");

    let store = Arc::new(LedgerStore::new("ledger.db").unwrap());

    // Load last known state from DB
    let (last_index, last_hash) = store.get_last_state().unwrap_or((0, String::new()));

    let app_state = AppState {
        store,
        state: Arc::new(Mutex::new((last_index, last_hash))),
        pubkey,
    };

    let app = Router::new()
        .route("/append", post(append_handler))
        .with_state(app_state);

    println!("[LEDGER] Listening on :8080");

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// ─────────────────────────────────────────────
// HANDLER
// ─────────────────────────────────────────────

async fn append_handler(
    State(app): State<AppState>,
    Json(envelope): Json<LedgerEnvelope>,
) -> Result<StatusCode, StatusCode> {

    let mut state = app.state.lock().await;
    let (last_index, last_hash) = &mut *state;

    // 🔐 VERIFY FIRST (ZERO TRUST)
    if let Err(e) = verify_entry(
        &envelope,
        *last_index,
        last_hash,
        &app.pubkey,
    ) {
        eprintln!("[LEDGER] REJECTED: {}", e);
        return Err(StatusCode::BAD_REQUEST);
    }

    // 🧱 APPEND TO STORE
    if let Err(e) = app.store.append(&envelope) {
        eprintln!("[LEDGER] STORE ERROR: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // 🔄 UPDATE STATE (ONLY AFTER SUCCESS)
    *last_index = envelope.index;
    *last_hash = envelope.hash.clone();

    println!(
        "[LEDGER] ✓ Appended index {}",
        envelope.index
    );

    Ok(StatusCode::OK)
}

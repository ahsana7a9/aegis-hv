use axum::{routing::post, Router, Json};
use std::sync::Arc;
use anyhow::Result;

mod store;
mod verify;

use store::LedgerStore;

#[tokio::main]
async fn main() {

    let store = Arc::new(LedgerStore::new("ledger.db").unwrap());

    let app = Router::new()
        .route("/append", post({
            let store = store.clone();
            move |Json(entry)| append_handler(store.clone(), entry)
        }));

    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn append_handler(
    store: Arc<LedgerStore>,
    entry: serde_json::Value,
) -> Result<&'static str> {

    store.append(entry)?;

    Ok("OK")
}

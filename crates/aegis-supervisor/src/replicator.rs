use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct LogReplicator {
    client: Client,
    endpoint: String,
    counter: AtomicU64,
}

#[derive(Serialize)]
struct ReplicatedLog<'a, T> {
    index: u64,
    payload: &'a T,
}

impl LogReplicator {
    pub fn new(endpoint: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
            counter: AtomicU64::new(0),
        }
    }

    pub async fn send<T: Serialize>(&self, log: &T) -> Result<()> {
        let index = self.counter.fetch_add(1, Ordering::SeqCst);

        let payload = ReplicatedLog { index, payload: log };

        self.client
            .post(&self.endpoint)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

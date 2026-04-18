use anyhow::Result;
use reqwest::Client;
use serde::Serialize;

pub struct LogReplicator {
    client: Client,
    endpoint: String,
}

impl LogReplicator {
    pub fn new(endpoint: String) -> Self {
        Self {
            client: Client::new(),
            endpoint,
        }
    }

    pub async fn send<T: Serialize>(&self, log: &T) -> Result<()> {
        self.client
            .post(&self.endpoint)
            .json(log)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

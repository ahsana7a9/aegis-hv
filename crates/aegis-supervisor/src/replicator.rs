use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use futures::future::join_all;

use crate::quorum::require_quorum;

pub struct LogReplicator {
    client: Client,
    nodes: Vec<String>,
}

impl LogReplicator {
    pub fn new(nodes: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            nodes,
        }
    }

    pub async fn replicate<T: Serialize>(&self, log: &T) -> Result<()> {

        let futures = self.nodes.iter().map(|node| {
            self.client
                .post(format!("{}/append", node))
                .json(log)
                .send()
        });

        let results = join_all(futures).await;

        let mut success = 0;

        for res in results {
            if let Ok(r) = res {
                if r.status().is_success() {
                    success += 1;
                }
            }
        }

        require_quorum(success, self.nodes.len())?;

        Ok(())
    }
}

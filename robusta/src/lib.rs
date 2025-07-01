mod config;
pub mod types;

use std::time::Duration;

pub use config::{Config, ConfigBuilder};
use reqwest::{StatusCode, Url};
use serde_json as json;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::types::{Transaction, TxHash, TxInfo};

/// A client for the Espresso network.
#[derive(Debug)]
pub struct Client {
    config: Config,
    client: reqwest::Client,
}

impl Client {
    pub fn new(c: Config) -> Self {
        let r = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("TLS and DNS resolver work");
        Self {
            config: c,
            client: r,
        }
    }

    /// Submit an Espresso transaction and await its availability.
    pub async fn submit(&mut self, trx: Transaction<'_>) -> Result<(), Error> {
        enum State {
            // We are submitting `trx`.
            Sending,
            // We are awaiting availability of the `trx`.
            Awaiting(TxHash, Url),
        }

        let mut state = State::Sending;
        let mut delay = self.config.delay_iter();

        loop {
            match &state {
                State::Sending => match self.submit_once(&trx).await {
                    Ok(hash) => {
                        debug!(%hash, "received transaction hash");
                        let str = json::to_string(&hash)?;
                        let url = self.config.check_url.join(&str)?;
                        state = State::Awaiting(hash, url);
                        delay = self.config.delay_iter();
                    }
                    Err(err) => {
                        warn!(%err, "failed to submit transaction");
                        sleep(delay.next().expect("infinite delay sequence")).await;
                    }
                },
                State::Awaiting(hash, url) => match self.check_once(url).await {
                    Ok(info) => {
                        debug!(%hash, height = %info.block_height, "transaction available");
                        return Ok(());
                    }
                    Err(err) => {
                        warn!(%hash, %err, "failed to check transaction");
                        sleep(delay.next().expect("infinite delay sequence")).await;
                    }
                },
            }
        }
    }

    async fn submit_once(&mut self, t: &Transaction<'_>) -> Result<TxHash, InternalError> {
        let res = self
            .client
            .post(self.config.submit_url.clone())
            .json(&t)
            .send()
            .await?;

        if !res.status().is_success() {
            return Err(InternalError::Status(res.status()));
        }

        let hash = res.json().await?;
        Ok(hash)
    }

    async fn check_once(&mut self, url: &Url) -> Result<TxInfo<json::Value>, InternalError> {
        let res = self.client.get(url.clone()).send().await?;

        if !res.status().is_success() {
            return Err(InternalError::Status(res.status()));
        }

        // TODO: verification

        Ok(res.json().await?)
    }
}

/// Errors `Client` can not recover from.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("json error: {0}")]
    Json(#[from] json::Error),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
}

/// Internal, hopefully transient errors.
#[derive(Debug, thiserror::Error)]
enum InternalError {
    #[error("json error: {0}")]
    Json(#[from] json::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("api status: {0}")]
    Status(StatusCode),
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_URL: &str = "https://query.decaf.testnet.espresso.network/v0";

    #[tokio::test]
    async fn check_once() {
        let trx = "TX~pUqxrpKI10FFVs8S0CooqTdLsXv1AE2eIF9GX7CltXgQ".to_string();
        let blk = "BLOCK~b5xqZwSbRlbFXonm8jDmTLOBvQVol8bWQM0NXOoj5xq3".to_string();

        let cfg = Config::builder()
            .submit_url(&format!("{BASE_URL}/submit/submit"))
            .unwrap()
            .check_url(&format!("{BASE_URL}/availability/transaction/hash/"))
            .unwrap()
            .build();

        let mut clt = Client::new(cfg.clone());
        let url = cfg.check_url.join(&trx).unwrap();
        let info = clt.check_once(&url).await.unwrap();

        assert_eq!(info.hash.to_string(), trx);
        assert_eq!(info.block_hash.to_string(), blk);
    }
}

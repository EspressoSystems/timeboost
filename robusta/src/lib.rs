mod config;
mod multiwatcher;
mod types;
mod watcher;

use std::iter::empty;
use std::time::Duration;

use either::Either;
use espresso_types::{Header, NamespaceId, Transaction};
use multisig::{Unchecked, Validated};
use reqwest::{StatusCode, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json as json;
use timeboost_types::sailfish::CommitteeVec;
use timeboost_types::{BlockNumber, CertifiedBlock};
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::types::{TX, TaggedBase64, TransactionsWithProof, VidCommonResponse};

pub use crate::multiwatcher::Multiwatcher;
pub use crate::types::Height;
pub use crate::watcher::{WatchError, Watcher};
pub use config::{Config, ConfigBuilder};
pub use espresso_types;

/// A client for the Espresso network.
#[derive(Debug, Clone)]
pub struct Client {
    config: Config,
    client: reqwest::Client,
}

impl Client {
    pub fn new(c: Config) -> Self {
        let r = reqwest::Client::builder()
            .https_only(c.https_only)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("TLS and DNS resolver work");
        Self {
            config: c,
            client: r,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub async fn height(&self) -> Result<Height, Error> {
        let u = self.config.base_url.join("status/block-height")?;
        self.get_with_retry(u).await
    }

    pub async fn submit<N>(&self, nsid: N, cb: &CertifiedBlock<Validated>) -> Result<(), Error>
    where
        N: Into<NamespaceId>,
    {
        let trx = Transaction::new(nsid.into(), serialize(cb)?);
        let url = self.config.base_url.join("submit/submit")?;
        self.post_with_retry::<_, TaggedBase64<TX>>(url, &trx)
            .await?;
        Ok(())
    }

    pub async fn verified<N, const C: usize>(
        &self,
        nsid: N,
        hdr: &Header,
        cvec: &CommitteeVec<C>,
    ) -> impl Iterator<Item = BlockNumber>
    where
        N: Into<NamespaceId>,
    {
        let nsid = nsid.into();
        debug!(node = %self.config.label, %nsid, height = %hdr.height(), "verifying blocks");
        let Ok(trxs) = self.transactions(hdr.height(), nsid).await else {
            debug!(node = %self.config.label, %nsid, height = %hdr.height(), "no transactions");
            return Either::Left(empty());
        };
        let Some(proof) = trxs.proof else {
            debug!(node = %self.config.label, %nsid, height = %hdr.height(), "no proof");
            return Either::Left(empty());
        };
        let Ok(vidc) = self.vid_common(hdr.height()).await else {
            debug!(node = %self.config.label, height = %hdr.height(), "no vid common");
            return Either::Left(empty());
        };
        let Some((trxs, ns)) =
            proof.verify(hdr.ns_table(), &hdr.payload_commitment(), &vidc.common)
        else {
            warn!(node = %self.config.label, %nsid, height = %hdr.height(), "proof verification failed");
            return Either::Left(empty());
        };
        if ns != nsid {
            warn!(node = %self.config.label, a = %nsid, b = %ns, height = %hdr.height(), "namespace mismatch");
            return Either::Left(empty());
        }
        Either::Right(trxs.into_iter().filter_map(move |t| {
            match deserialize::<CertifiedBlock<Unchecked>>(t.payload()) {
                Ok(b) => {
                    let Some(c) = cvec.get(b.committee()) else {
                        warn!(
                            node      = %self.config.label,
                            height    = %hdr.height(),
                            committee = %b.committee(),
                            "unknown committee"
                        );
                        return None;
                    };
                    if let Some(b) = b.validated(c) {
                        Some(b.cert().data().num())
                    } else {
                        warn!(node = %self.config.label, height = %hdr.height(), "invalid block");
                        None
                    }
                }
                Err(err) => {
                    warn!(
                        node   = %self.config.label,
                        nsid   = %nsid,
                        height = %hdr.height(),
                        err    = %err,
                        "could not deserialize block"
                    );
                    None
                }
            }
        }))
    }

    async fn transactions<H, N>(&self, height: H, nsid: N) -> Result<TransactionsWithProof, Error>
    where
        H: Into<Height>,
        N: Into<NamespaceId>,
    {
        let h = height.into();
        let n = nsid.into();
        let u = self
            .config
            .base_url
            .join(&format!("availability/block/{h}/namespace/{n}"))?;
        self.get_with_retry(u).await
    }

    async fn vid_common<H>(&self, height: H) -> Result<VidCommonResponse, Error>
    where
        H: Into<Height>,
    {
        let h = height.into();
        let u = self
            .config
            .base_url
            .join(&format!("availability/vid/common/{h}"))?;
        self.get_with_retry(u).await
    }

    async fn get_with_retry<A>(&self, url: Url) -> Result<A, Error>
    where
        A: DeserializeOwned,
    {
        let mut delay = self.config.delay_iter();
        loop {
            match self.get(url.clone()).await {
                Ok(a) => return Ok(a),
                Err(err) => {
                    warn!(node = %self.config.label, %url, %err, "failed to get response");
                    sleep(delay.next().expect("infinite delay sequence")).await;
                }
            }
        }
    }

    async fn post_with_retry<A, B>(&self, url: Url, a: &A) -> Result<B, Error>
    where
        A: Serialize,
        B: DeserializeOwned,
    {
        let mut delay = self.config.delay_iter();
        loop {
            match self.post(url.clone(), a).await {
                Ok(b) => return Ok(b),
                Err(err) => {
                    warn!(node = %self.config.label, %url, %err, "failed to post request");
                    sleep(delay.next().expect("infinite delay sequence")).await;
                }
            }
        }
    }

    async fn get<A>(&self, url: Url) -> Result<A, InternalError>
    where
        A: DeserializeOwned,
    {
        let res = self.client.get(url).send().await?;

        if !res.status().is_success() {
            return Err(InternalError::Status(res.status()));
        }

        Ok(res.json().await?)
    }

    async fn post<A, B>(&self, u: Url, t: &A) -> Result<B, InternalError>
    where
        A: Serialize,
        B: DeserializeOwned,
    {
        let res = self.client.post(u).json(t).send().await?;

        if !res.status().is_success() {
            return Err(InternalError::Status(res.status()));
        }

        Ok(res.json().await?)
    }
}

/// Errors `Client` can not recover from.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("json error: {0}")]
    Json(#[from] json::Error),

    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("proof error: {0}")]
    Proof(#[from] ProofError),

    #[error("transaction not found")]
    TransactionNotFound,
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("no proof term")]
    NoProof,
    #[error("proof verification failed")]
    InvalidProof,
    #[error("namespace mismatch: {0} != {1}")]
    NamespaceMismatch(NamespaceId, NamespaceId),
    #[error("transaction not found in proof")]
    TransactionNotInProof,
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

fn serialize<T: Serialize>(d: &T) -> Result<Vec<u8>, Error> {
    let v = bincode::serde::encode_to_vec(d, bincode::config::standard())?;
    Ok(v)
}

fn deserialize<T: DeserializeOwned>(d: &[u8]) -> Result<T, Error> {
    bincode::serde::decode_from_slice(d, bincode::config::standard())
        .map(|(msg, _)| msg)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{Client, Config, Watcher};

    #[tokio::test]
    async fn decaf_smoke() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("robusta=debug")
            .try_init();

        let cfg = Config::builder()
            .base_url(
                "https://query.decaf.testnet.espresso.network/v1/"
                    .parse()
                    .unwrap(),
            )
            .wss_base_url(
                "wss://query.decaf.testnet.espresso.network/v1/"
                    .parse()
                    .unwrap(),
            )
            .label("decaf_smoke")
            .https_only(true)
            .build();

        let clt = Client::new(cfg.clone());
        let height = clt.height().await.unwrap();
        let mut watcher = Watcher::new(cfg, height, None);
        let header = watcher.next().await.unwrap_right();
        assert_eq!(u64::from(height), header.height());
    }
}

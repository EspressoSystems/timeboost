mod config;
mod types;

use std::time::Duration;

use espresso_types::{Header, NamespaceId, Transaction};
use reqwest::{StatusCode, Url};
use serde::{Serialize, de::DeserializeOwned};
use serde_json as json;
use timeboost_types::CertifiedBlock;
use tokio::time::sleep;
use tracing::warn;

use crate::types::{Height, TX, TaggedBase64, TransactionsWithProof, VidCommonResponse};

pub use config::{Config, ConfigBuilder};

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

    pub async fn submit(&mut self, cb: &CertifiedBlock) -> Result<(), Error> {
        let nid = NamespaceId::from(u64::from(u32::from(cb.data().namespace())));
        let trx = Transaction::new(nid, serialize(cb)?);
        let url = self.config.base_url.join("/submit/submit")?;
        self.post_with_retry::<_, TaggedBase64<TX>>(url, &trx)
            .await?;
        Ok(())
    }

    pub async fn validate<N>(&mut self, h: &Header, cb: &CertifiedBlock) -> Result<(), Error> {
        let nsid = NamespaceId::from(u64::from(u32::from(cb.data().namespace())));

        let trxs = self.transactions(h.height(), nsid).await?;
        let Some(proof) = trxs.proof else {
            return Err(ProofError::NoProof.into());
        };
        if !trxs.transactions.iter().any(|t| matches(t.payload(), cb)) {
            return Err(Error::TransactionNotFound);
        }

        let vidc = self.vid_common(h.height()).await?;

        let Some((trxs, ns)) = proof.verify(h.ns_table(), &h.payload_commitment(), &vidc.common)
        else {
            return Err(ProofError::InvalidProof.into());
        };
        if ns != nsid {
            return Err(ProofError::NamespaceMismatch(ns, nsid).into());
        }
        if !trxs.iter().any(|t| matches(t.payload(), cb)) {
            return Err(ProofError::TransactionNotInProof.into());
        }

        Ok(())
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
            .join(&format!("/availability/block/{h}/namespace/{n}"))?;
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
            .join(&format!("/availability/vid/common/{h}"))?;
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
                    warn!(%url, %err, "failed to get response");
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
                    warn!(%url, %err, "failed to post request");
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

fn matches(a: &[u8], b: &CertifiedBlock) -> bool {
    let Ok(a) = deserialize::<CertifiedBlock>(a) else {
        return false;
    };
    a.data().hash() == b.data().hash()
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

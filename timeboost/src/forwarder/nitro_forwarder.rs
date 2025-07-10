mod worker;

use std::io;

use cliquenet::Address;
use multisig::PublicKey;
use timeboost_proto::forward::forward_api_client::ForwardApiClient;
use timeboost_proto::inclusion::InclusionList;
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;
use worker::Worker;

pub struct NitroForwarder {
    incls_tx: Sender<InclusionList>,
    jh: JoinHandle<()>,
}

impl Drop for NitroForwarder {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl NitroForwarder {
    pub async fn connect(key: PublicKey, addr: Address) -> Result<Self, Error> {
        let uri = format!("http://{addr}");
        let endpoint = Endpoint::from_shared(uri).map_err(|e| Error::InvalidUri(e.to_string()))?;
        let chan = endpoint.connect().await?;
        let c = ForwardApiClient::new(chan);
        let (tx, rx) = channel(100_000);
        let w = Worker::new(key, c, rx);
        Ok(Self {
            incls_tx: tx,
            jh: tokio::spawn(w.go()),
        })
    }

    pub async fn enqueue(&self, d: InclusionList) -> Result<(), Error> {
        self.incls_tx
            .send(d)
            .await
            .map_err(|_| Error::WorkerStopped)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),

    #[error("invalid uri: {0}")]
    InvalidUri(String),

    #[error("transport error: {0}")]
    TransportError(#[from] tonic::transport::Error),

    #[error("nitro forwarder worker stopped")]
    WorkerStopped,
}

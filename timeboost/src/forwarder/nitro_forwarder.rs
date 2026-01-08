mod worker;

use std::io;

use alloy::eips::Encodable2718;
use cliquenet::Address;
use multisig::PublicKey;
use prost::bytes::Bytes;
use sailfish::types::RoundNumber;
use timeboost_proto::forward::CatchupRound;
use timeboost_proto::{forward::forward_api_client::ForwardApiClient, inclusion::InclusionList};
use timeboost_types::{DelayedInboxIndex, Timestamp, Transaction};
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinHandle;
use tonic::transport::Endpoint;
use worker::Worker;

#[derive(Debug)]
pub enum Output {
    Inclusion(InclusionList),
    Catchup(CatchupRound),
}

pub struct NitroForwarder {
    tx: Sender<Output>,
    jh: JoinHandle<()>,
}

impl Drop for NitroForwarder {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl NitroForwarder {
    pub fn new(key: PublicKey, addr: Address) -> Result<Self, Error> {
        let uri = format!("http://{addr}");
        let endpoint = Endpoint::from_shared(uri).map_err(|e| Error::InvalidUri(e.to_string()))?;
        let chan = endpoint.connect_lazy();
        let c = ForwardApiClient::new(chan);
        let (tx, rx) = channel(100_000);
        let w = Worker::new(key, c.clone(), rx);
        Ok(Self {
            tx,
            jh: tokio::spawn(w.go()),
        })
    }

    pub async fn enqueue(
        &self,
        round: RoundNumber,
        timestamp: Timestamp,
        txns: &[Transaction],
        index: DelayedInboxIndex,
    ) -> Result<(), Error> {
        let incl = InclusionList {
            round: *round,
            encoded_txns: txns
                .iter()
                .map(|tx| Bytes::from(tx.encoded_2718()))
                .collect(),
            consensus_timestamp: timestamp.into(),
            // we need to add 1 to the index
            // eg index 0 is really 1 delayed message read
            delayed_messages_read: u64::from(index) + 1,
        };
        self.tx
            .send(Output::Inclusion(incl))
            .await
            .map_err(|_| Error::WorkerStopped)?;
        Ok(())
    }

    pub async fn catchup(&mut self, round: RoundNumber) -> Result<(), Error> {
        let r = CatchupRound {
            round: round.into(),
        };
        self.tx
            .send(Output::Catchup(r))
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

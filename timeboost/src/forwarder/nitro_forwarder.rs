mod worker;

use std::io;

use alloy::eips::Encodable2718;
use cliquenet::Address;
use multisig::PublicKey;
use sailfish::types::RoundNumber;
use timeboost_proto::forward::forward_api_client::ForwardApiClient;
use timeboost_proto::inclusion::InclusionList;
use timeboost_types::{DelayedInboxIndex, Timestamp, Transaction};
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tonic::transport::Endpoint;
use tracing::error;
use worker::Worker;

const MAX_RETRIES: usize = 10;
const RETRY_DELAY: Duration = Duration::from_secs(5);

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
        let chan = 'retry_loop: {
            for i in 1..=MAX_RETRIES {
                match endpoint.connect().await {
                    Ok(chan) => break 'retry_loop chan,
                    Err(err) => {
                        if i == MAX_RETRIES {
                            error!(%err, %addr, "failed to connect to nitro node after {} attempts", MAX_RETRIES);
                            return Err(err.into());
                        }
                        error!(%err, %addr, retry = i, "failed to connect to nitro node, retrying...");
                        sleep(RETRY_DELAY).await;
                    }
                }
            }
            unreachable!("loop should always break early with success or return error");
        };
        let c = ForwardApiClient::new(chan);
        let (tx, rx) = channel(100_000);
        let w = Worker::new(key, c, rx);
        Ok(Self {
            incls_tx: tx,
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
                .map(|tx| timeboost_proto::inclusion::Transaction {
                    encoded_txn: tx.encoded_2718().into(),
                    address: tx.address().as_slice().to_vec(),
                    timestamp: **tx.time(),
                })
                .collect(),
            consensus_timestamp: timestamp.into(),
            // we need to add 1 to the index
            // eg index 0 is really 1 delayed message read
            delayed_messages_read: u64::from(index) + 1,
        };
        self.incls_tx
            .send(incl)
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

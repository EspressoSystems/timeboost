mod worker;

use std::io;

use cliquenet::Address;
use multisig::PublicKey;
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinHandle;
use worker::Worker;

use crate::forwarder::data::Data;

pub struct NitroForwarder {
    incls_tx: Sender<Data>,
    jh: JoinHandle<()>,
}

impl Drop for NitroForwarder {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl NitroForwarder {
    pub async fn connect(key: PublicKey, addr: Address) -> Result<Self, Error> {
        let (tx, rx) = channel(100_000);
        let w = Worker::connect(key, addr, rx).await?;
        Ok(Self {
            incls_tx: tx,
            jh: tokio::spawn(w.go()),
        })
    }

    pub async fn enqueue(&self, d: Data) -> Result<(), Error> {
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

    #[error("nitro forwarder worker stopped")]
    WorkerStopped,
}

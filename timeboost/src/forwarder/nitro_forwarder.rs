use cliquenet::Address;
use std::io::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinHandle;

use crate::forwarder::data::Data;
use crate::forwarder::worker::Worker;

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
    pub async fn connect(addr: &Address) -> Result<Self, Error> {
        let (tx, rx) = channel(100);
        let w = Worker::connect(addr, rx).await?;
        Ok(Self {
            incls_tx: tx,
            jh: tokio::spawn(w.go()),
        })
    }

    pub async fn enqueue(&self, d: Data) -> Result<(), SendError<Data>> {
        self.incls_tx.send(d).await?;
        Ok(())
    }
}

use cliquenet::Address;
use multisig::PublicKey;
use std::io::Error;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{Sender, channel};
use tokio::task::JoinHandle;

use crate::forwarder::data::Data;
use crate::forwarder::worker::Worker;

pub(crate) enum Command {
    Send(Data),
}

pub struct NitroForwarder {
    incls_tx: Sender<Command>,
    jh: JoinHandle<()>,
}

impl Drop for NitroForwarder {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl NitroForwarder {
    pub async fn connect(key: PublicKey, addr: &Address) -> Result<Self, Error> {
        let (tx, rx) = channel(100);
        let w = Worker::connect(key, addr, rx).await?;
        Ok(Self {
            incls_tx: tx,
            jh: tokio::spawn(w.go()),
        })
    }

    pub(crate) async fn enqueue(&self, d: Data) -> Result<(), SendError<Command>> {
        self.incls_tx.send(Command::Send(d)).await?;
        Ok(())
    }
}

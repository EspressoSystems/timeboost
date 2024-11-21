use std::borrow::Cow;

use async_trait::async_trait;
use hotshot::traits::implementations::Libp2pNetwork;
use serde::{Deserialize, Serialize};
use timeboost_core::traits::comm::Comm;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::{Envelope, Validated};
use timeboost_core::types::message::Message;
use timeboost_core::types::{Keypair, PublicKey};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod digest;
mod worker;

use digest::Digest;
use worker::{RbcError, Worker};

#[derive(Debug, Serialize, Deserialize)]
enum RbcMsg<'a, Status: Clone> {
    Propose(Cow<'a, Message<Status>>),
    Vote(Envelope<Digest, Status>),
    Cert(Envelope<Certificate<Digest>, Status>),
    Get(Envelope<Digest, Status>),
}

enum Command {
    Send(PublicKey, Message<Validated>),
    Broadcast(Message<Validated>),
    Shutdown(oneshot::Sender<()>)
}

#[derive(Debug)]
pub struct Rbc {
    rx: mpsc::Receiver<Message<Validated>>,
    tx: mpsc::Sender<Command>,
    jh: JoinHandle<()>,
    closed: bool
}

impl Drop for Rbc {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl Rbc {
    pub fn new(n: Libp2pNetwork<PublicKey>, k: Keypair, c: StaticCommittee) -> Self {
        let (obound_tx, obound_rx) = mpsc::channel(2 * c.size().get());
        let (ibound_tx, ibound_rx) = mpsc::channel(3 * c.size().get());
        let worker = Worker::new(ibound_tx, obound_rx, k, n, c);
        Self {
            rx: ibound_rx,
            tx: obound_tx,
            jh: tokio::spawn(worker.go()),
            closed: false
        }
    }
}

#[async_trait]
impl Comm for Rbc {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        if self.closed {
            return Err(RbcError::Shutdown)
        }
        self.tx.send(Command::Broadcast(msg)).await.map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        if self.closed {
            return Err(RbcError::Shutdown)
        }
        self.tx.send(Command::Send(to, msg)).await.map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err> {
        Ok(self.rx.recv().await.unwrap())
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        if self.closed {
            return Ok(())
        }
        self.closed = true;
        let (tx, rx) = oneshot::channel();
        if self.tx.send(Command::Shutdown(tx)).await.is_ok() {
            let _ = rx.await;
        }
        self.rx.close();
        Ok(())
    }
}

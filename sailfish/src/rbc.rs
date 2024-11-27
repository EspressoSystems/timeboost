use std::borrow::Cow;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use timeboost_core::traits::comm::Comm;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::{Envelope, Validated};
use timeboost_core::types::message::Message;
use timeboost_core::types::{Keypair, PublicKey};
use timeboost_networking::network::client::Libp2pNetwork;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod digest;
mod worker;

use digest::Digest;
use worker::{RbcError, Worker};

/// The message type exchanged during RBC.
#[derive(Debug, Serialize, Deserialize)]
enum Protocol<'a, Status: Clone> {
    /// A message that is sent and received on a best-effort basis.
    Bypass(Cow<'a, Message<Status>>),
    /// An RBC proposal.
    Propose(Cow<'a, Message<Status>>),
    /// A vote for an RBC proposal.
    Vote(Envelope<Digest, Status>),
    /// A quorum certificate for an RBC proposal.
    Cert(Envelope<Certificate<Digest>, Status>),
    /// A direct request to retrieve a message, identified by the given digest.
    Get(Envelope<Digest, Status>),
}

/// Worker command
enum Command {
    /// Send message to a party identified by the given public key.
    Send(PublicKey, Message<Validated>),
    /// Do a best-effort broadcast of the given message.
    Broadcast(Message<Validated>),
    /// Do a byzantine reliable broadcast of the given message.
    RbcBroadcast(Message<Validated>, oneshot::Sender<Result<(), RbcError>>),
    /// End operation.
    Shutdown(oneshot::Sender<()>),
}

/// Rbc implement `Comm` and provides and reliable broadcast implementation.
#[derive(Debug)]
pub struct Rbc {
    // Inbound, RBC-delivered messages.
    rx: mpsc::Receiver<Message<Validated>>,
    // Directives to the RBC worker.
    tx: mpsc::Sender<Command>,
    // The worker task handle.
    jh: JoinHandle<()>,
    // Have we shutdown?
    closed: bool,
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
            closed: false,
        }
    }
}

#[async_trait]
impl Comm for Rbc {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        if self.closed {
            return Err(RbcError::Shutdown);
        }

        // Only vertex proposals require RBC properties. If this message is one
        // we hand it to the worker and wait for its acknowlegement before returning.
        if matches!(msg, Message::Vertex(_)) {
            let (tx, rx) = oneshot::channel();
            self.tx
                .send(Command::RbcBroadcast(msg, tx))
                .await
                .map_err(|_| RbcError::Shutdown)?;
            return rx.await.map_err(|_| RbcError::Shutdown)?;
        }

        // Anything else is on a best-effort basis.
        self.tx
            .send(Command::Broadcast(msg))
            .await
            .map_err(|_| RbcError::Shutdown)?;

        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        if self.closed {
            return Err(RbcError::Shutdown);
        }
        self.tx
            .send(Command::Send(to, msg))
            .await
            .map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err> {
        Ok(self.rx.recv().await.unwrap())
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        if self.closed {
            return Ok(());
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

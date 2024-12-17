use std::borrow::Cow;

use async_trait::async_trait;
use multisig::{Certificate, Committee, Envelope, Keypair, PublicKey, Validated};
use serde::{Deserialize, Serialize};
use timeboost_core::traits::comm::{Comm, RawComm};
use timeboost_core::types::message::Message;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{info, warn};

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
    ///
    /// The boolean flag indicates if the sender has received enough votes.
    Vote(Envelope<Digest, Status>, bool),
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

/// RBC configuration
#[derive(Debug, Clone)]
pub struct Config {
    keypair: Keypair,
    committee: Committee,
    early_delivery: bool,
}

impl Config {
    pub fn new(k: Keypair, c: Committee) -> Self {
        Self {
            keypair: k,
            committee: c,
            early_delivery: true,
        }
    }

    /// Should RBC deliver first messages as soon as 2f + 1 messages
    /// have been received in a round?
    pub fn with_early_delivery(mut self, val: bool) -> Self {
        self.early_delivery = val;
        self
    }
}

/// Rbc implements `Comm` and provides a reliable broadcast implementation.
///
/// We support message delivery with different properties: best-effort delivery
/// to all or one party, and byzantine reliable broadcast. The latter is used to
/// deliver vertex proposals. The algorithm is based on Abraham et al. [[1]]:
///
/// 1. Propose: When broadcasting a message we send a proposal to all parties.
/// 2. Vote: When receiving a first proposal from a broadcaster, we send
///    a vote for the proposal to all parties.
/// 3. Commit: When receiving 𝑛 − 𝑓 votes for a proposal, we send the
///    resulting certificate to all parties and deliver the message to the
///    application.
///
/// Voting uses the commit digest of the proposal, not the proposal message itself,
/// in order to minimise the amount of data to send.
///
/// [1]: Good-case Latency of Byzantine Broadcast: A Complete Categorization
///      (arXiv:2102.07240v3)
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
    pub fn new<C: RawComm + Send + 'static>(n: C, c: Config) -> Self {
        let (obound_tx, obound_rx) = mpsc::channel(2 * c.committee.size().get());
        let (ibound_tx, ibound_rx) = mpsc::channel(3 * c.committee.size().get());
        let worker = Worker::new(ibound_tx, obound_rx, c, n);
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
        // we hand it to the worker and wait for its acknowlegement by the worker
        // before returning. Once the message has been handed over to the worker it
        // will be eventually delivered.
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
        info!("shutting down operations");
        self.closed = true;
        let (tx, rx) = oneshot::channel();
        tracing::error!("rbc shutdown");
        if let Err(err) = self.tx.send(Command::Shutdown(tx)).await {
            warn!(%err, "error during shutdown");
        }
        tracing::error!("rbc await rx");
        let _ = rx.await;
        tracing::error!("close");
        self.rx.close();
        tracing::error!("complete");
        info!("shutdown complete");
        Ok(())
    }
}

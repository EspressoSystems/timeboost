use std::borrow::Cow;

use async_trait::async_trait;
use committable::Committable;
use multisig::{Certificate, Committee, Envelope, Keypair, PublicKey, Validated};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sailfish_types::{Comm, RawComm, Message};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

mod digest;
mod metrics;
mod worker;

use digest::Digest;
use worker::{RbcError, Worker};

pub use metrics::RbcMetrics;

/// The message type exchanged during RBC.
#[derive(Debug, Serialize, Deserialize)]
#[rustfmt::skip]
enum Protocol<'a, B: Clone, Status: Clone> {
    // Non-RBC section ////////////////////////////////////////////////////////

    /// A message that is sent without expectations ("fire and forget").
    Fire(Cow<'a, Message<B, Status>>),

    /// A message that is sent and received without quorum requirements.
    ///
    /// The sender expects an `Ack` for each message and will retry until
    /// it has been received (or the protocol moved on).
    Send(Cow<'a, Message<B, Status>>),

    /// An acknowledgement reply of a message.
    Ack(Envelope<Digest, Status>),

    // RBC section ////////////////////////////////////////////////////////////

    /// An RBC proposal.
    Propose(Cow<'a, Message<B, Status>>),

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
enum Command<B> {
    /// Send message to a party identified by the given public key.
    Send(PublicKey, Message<B, Validated>),
    /// Do a best-effort broadcast of the given message.
    Broadcast(Message<B, Validated>),
    /// Do a byzantine reliable broadcast of the given message.
    RbcBroadcast(Message<B, Validated>, oneshot::Sender<Result<(), RbcError>>),
}

/// RBC configuration
#[derive(Debug)]
pub struct RbcConfig {
    keypair: Keypair,
    committee: Committee,
    early_delivery: bool,
    metrics: RbcMetrics,
}

impl RbcConfig {
    pub fn new(k: Keypair, c: Committee) -> Self {
        Self {
            keypair: k,
            committee: c,
            early_delivery: true,
            metrics: RbcMetrics::default(),
        }
    }

    /// Should RBC deliver first messages as soon as 2f + 1 messages
    /// have been received in a round?
    pub fn with_early_delivery(mut self, val: bool) -> Self {
        self.early_delivery = val;
        self
    }

    /// Set the RBC metrics value to use.
    pub fn with_metrics(mut self, m: RbcMetrics) -> Self {
        self.metrics = m;
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
pub struct Rbc<B> {
    // Inbound, RBC-delivered messages.
    rx: mpsc::Receiver<Message<B, Validated>>,
    // Directives to the RBC worker.
    tx: mpsc::Sender<Command<B>>,
    // The worker task handle.
    jh: JoinHandle<()>,
}

impl<B> Drop for Rbc<B> {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl<B: Clone + Committable + Serialize + DeserializeOwned + Send + Sync + 'static> Rbc<B> {
    pub fn new<C: RawComm + Send + 'static>(n: C, c: RbcConfig) -> Self {
        let (obound_tx, obound_rx) = mpsc::channel(2 * c.committee.size().get());
        let (ibound_tx, ibound_rx) = mpsc::channel(3 * c.committee.size().get());
        let worker = Worker::new(ibound_tx, obound_rx, c, n);
        Self {
            rx: ibound_rx,
            tx: obound_tx,
            jh: tokio::spawn(worker.go()),
        }
    }
}

#[async_trait]
impl<B: Send + 'static> Comm<B> for Rbc<B> {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<B, Validated>) -> Result<(), Self::Err> {
        if self.rx.is_closed() {
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

    async fn send(&mut self, to: PublicKey, msg: Message<B, Validated>) -> Result<(), Self::Err> {
        if self.rx.is_closed() {
            return Err(RbcError::Shutdown);
        }
        self.tx
            .send(Command::Send(to, msg))
            .await
            .map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<B, Validated>, Self::Err> {
        Ok(self.rx.recv().await.unwrap())
    }
}

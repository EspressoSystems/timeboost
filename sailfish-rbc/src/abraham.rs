use std::borrow::Cow;

use async_trait::async_trait;
use committable::Committable;
use multisig::{Certificate, Committee, Envelope, Keypair, PublicKey, Validated};
use sailfish_types::{Comm, Message, RawComm};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::digest::Digest;
use crate::{RbcError, RbcMetrics};

mod worker;

use worker::Worker;

/// The message type exchanged during RBC.
#[derive(Debug, Serialize, Deserialize)]
#[rustfmt::skip]
enum Protocol<'a, T: Committable + Clone, Status: Clone> {
    // Non-RBC section ////////////////////////////////////////////////////////

    /// A message that is sent and received without quorum requirements.
    ///
    /// The sender expects an `Ack` for each message and will retry until
    /// it has been received (or the protocol moved on).
    Send(Cow<'a, Message<T, Status>>),

    /// An acknowledgement reply of a message.
    Ack(Envelope<Digest, Status>),

    // RBC section ////////////////////////////////////////////////////////////

    /// An RBC proposal.
    Propose(Cow<'a, Message<T, Status>>),

    /// A vote for an RBC proposal.
    ///
    /// The boolean flag indicates if the sender has received enough votes.
    Vote(Envelope<Digest, Status>, bool),

    /// A quorum certificate for an RBC proposal.
    Cert(Envelope<Certificate<Digest>, Status>),

    /// A direct request to retrieve a message, identified by the given digest.
    GetRequest(Envelope<Digest, Status>),

    /// The reply to a get request.
    GetResponse(Cow<'a, Message<T, Status>>),
}

/// Worker command
enum Command<T: Committable> {
    /// Send message to a party identified by the given public key.
    Send(PublicKey, Message<T, Validated>),
    /// Do a best-effort broadcast of the given message.
    Broadcast(Message<T, Validated>),
    /// Do a byzantine reliable broadcast of the given message.
    RbcBroadcast(Message<T, Validated>, oneshot::Sender<Result<(), RbcError>>),
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
/// deliver vertex proposals. The algorithm is based on Abraham et al. \[1\]:
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
/// \[1\]: Good-case Latency of Byzantine Broadcast: A Complete Categorization
///        (arXiv:2102.07240v3)
#[derive(Debug)]
pub struct Rbc<T: Committable> {
    // Inbound, RBC-delivered messages.
    rx: mpsc::Receiver<Message<T, Validated>>,
    // Directives to the RBC worker.
    tx: mpsc::Sender<Command<T>>,
    // The worker task handle.
    jh: JoinHandle<()>,
}

impl<T: Committable> Drop for Rbc<T> {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl<T: Clone + Committable + Serialize + DeserializeOwned + Send + Sync + 'static> Rbc<T> {
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
impl<T: Committable + Send + 'static> Comm<T> for Rbc<T> {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        if self.rx.is_closed() {
            return Err(RbcError::Shutdown);
        }

        // If this message requires RBC we hand it to the worker and wait for its
        // acknowlegement by the worker before returning. Once the message has been
        // handed over to the worker it will be eventually delivered.
        if requires_rbc(&msg) {
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

    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        if self.rx.is_closed() {
            return Err(RbcError::Shutdown);
        }
        self.tx
            .send(Command::Send(to, msg))
            .await
            .map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<T, Validated>, Self::Err> {
        Ok(self.rx.recv().await.unwrap())
    }
}

/// Check if the given message requires RBC properties.
fn requires_rbc<T: Committable, S>(m: &Message<T, S>) -> bool {
    match m {
        Message::Vertex(_) => true,
        Message::Timeout(_) => false,
        Message::NoVote(_) => false,
        Message::TimeoutCert(_) => false,
    }
}

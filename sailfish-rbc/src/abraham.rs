use std::borrow::Cow;
use std::fmt;

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use cliquenet::{Overlay, overlay::Data};
use committable::Committable;
use multisig::{Certificate, Committee, Envelope, Keypair, PublicKey, Validated};
use sailfish_types::{Comm, Evidence, Message, RoundNumber, Vertex};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::digest::Digest;
use crate::{RbcError, RbcMetrics};

#[rustfmt::skip]
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

    // RBC section ////////////////////////////////////////////////////////////

    /// An RBC proposal.
    Propose(Cow<'a, Envelope<Vertex<T>, Status>>),

    /// A vote for an RBC proposal.
    Vote(Envelope<Digest, Status>, Evidence),

    /// A quorum certificate for an RBC proposal.
    Cert(Certificate<Digest>),

    /// A direct request to retrieve a message, identified by the given digest.
    GetRequest(Digest),

    /// The reply to a get request.
    GetResponse(Cow<'a, Envelope<Vertex<T>, Status>>),

    /// A direct request to retries the current round number of a party.
    InfoRequest(Nonce),

    /// The reply to an info request with round number an evidence.
    InfoResponse(Nonce, RoundNumber, Cow<'a, Evidence>)
}

/// Worker command
enum Command<T: Committable> {
    /// Send message to a party identified by the given public key.
    Send(PublicKey, Message<T, Validated>, Data),
    /// Do a best-effort broadcast of the given message.
    Broadcast(Message<T, Validated>, Data),
    /// Do a byzantine reliable broadcast of the given message.
    RbcBroadcast(Envelope<Vertex<T>, Validated>, Data),
    /// Cleanup buffers up to the given round number.
    Gc(RoundNumber),
}

/// RBC configuration
#[derive(Debug)]
pub struct RbcConfig {
    keypair: Keypair,
    committee: Committee,
    recover: bool,
    early_delivery: bool,
    metrics: RbcMetrics,
}

impl RbcConfig {
    pub fn new(k: Keypair, c: Committee) -> Self {
        Self {
            keypair: k,
            committee: c,
            recover: true,
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

    /// Should we recover from a previous run?
    pub fn recover(mut self, val: bool) -> Self {
        self.recover = val;
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
    pub fn new(net: Overlay, c: RbcConfig) -> Self {
        let (obound_tx, obound_rx) = mpsc::channel(2 * c.committee.size().get());
        let (ibound_tx, ibound_rx) = mpsc::channel(3 * c.committee.size().get());
        let worker = Worker::new(ibound_tx, obound_rx, c, net);
        Self {
            rx: ibound_rx,
            tx: obound_tx,
            jh: tokio::spawn(worker.go()),
        }
    }
}

#[async_trait]
impl<T: Committable + Send + Serialize + Clone + 'static> Comm<T> for Rbc<T> {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        if self.rx.is_closed() {
            return Err(RbcError::Shutdown);
        }
        if let Message::Vertex(v) = msg {
            let data = serialize(&Protocol::Propose(Cow::Borrowed(&v)))?;
            self.tx
                .send(Command::RbcBroadcast(v, data))
                .await
                .map_err(|_| RbcError::Shutdown)?;
        } else {
            let data = serialize(&Protocol::Send(Cow::Borrowed(&msg)))?;
            self.tx
                .send(Command::Broadcast(msg, data))
                .await
                .map_err(|_| RbcError::Shutdown)?;
        }
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        if self.rx.is_closed() {
            return Err(RbcError::Shutdown);
        }
        let data = serialize(&Protocol::Send(Cow::Borrowed(&msg)))?;
        self.tx
            .send(Command::Send(to, msg, data))
            .await
            .map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<T, Validated>, Self::Err> {
        self.rx.recv().await.ok_or(RbcError::Shutdown)
    }

    async fn gc(&mut self, r: RoundNumber) -> Result<(), Self::Err> {
        self.tx
            .send(Command::Gc(r))
            .await
            .map_err(|_| RbcError::Shutdown)
    }
}

/// Serialize a given value into overlay `Data`.
fn serialize<T: Serialize>(d: &T) -> Result<Data, RbcError> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    Ok(b.into_inner().try_into()?)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
struct Nonce(u64);

impl Nonce {
    fn new() -> Self {
        Self(rand::random())
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

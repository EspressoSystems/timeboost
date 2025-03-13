use std::borrow::Cow;
use std::cmp::max;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use committable::{Commitment, Committable};
use multisig::{Certificate, Envelope, PublicKey, VoteAccumulator};
use multisig::{Unchecked, Validated};
use sailfish_types::{Message, RawComm, RoundNumber, Vertex};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::mpsc;
use tokio::time::{self, Instant, Interval};
use tracing::{debug, trace, warn};

use crate::RbcError;
use crate::digest::Digest;

use super::{Command, Protocol, RbcConfig};

type Result<T> = std::result::Result<T, RbcError>;
type Sender<T> = mpsc::Sender<Message<T, Validated>>;
type Receiver<T> = mpsc::Receiver<Command<T>>;

/// A worker is run by `Rbc` to perform the actual work of sending and
/// delivering messages.
pub struct Worker<C, T: Committable> {
    /// RBC configuration.
    config: RbcConfig,
    /// Label, used in debug logs.
    label: PublicKey,
    /// Underlying communication type.
    comm: C,
    /// Our channel to deliver messages to the application layer.
    tx: Sender<T>,
    /// Our channel to receive messages from the application layer.
    rx: Receiver<T>,
    /// The highest round number of the application (used for pruning).
    round: RoundNumber,
    /// The tracking information per message.
    buffer: BTreeMap<RoundNumber, Messages<T>>,
    /// A timer to retry messages.
    timer: Interval,
}

/// Messages of a single round.
struct Messages<T: Committable> {
    /// Did we deliver the messages early?
    ///
    /// Early delivery means that as soon as we receive 2f + 1 messages in a
    /// round, we deliver the messages. Afterwards this flag is set to true
    /// to avoid repeated calculations. The rationale behind this is that with
    /// 2f + 1 messages we know that at least f + 1 messages will eventually
    /// be delivered.
    early: bool,
    /// Tracking info per message.
    map: BTreeMap<Digest, Tracker<T>>,
    /// This tracks the remaining number of ACKs we still expect for the given
    /// message digest.
    acks: BTreeMap<Digest, Acks>,
}

impl<T: Committable> Messages<T> {
    /// Get a message digest of this source, if any.
    fn digest(&self, s: &PublicKey) -> Option<Digest> {
        for (d, t) in &self.map {
            if let Some(vertex) = &t.message.item {
                if vertex.data().source() == s {
                    return Some(*d);
                }
            }
        }
        None
    }
}

impl<T: Committable> Default for Messages<T> {
    fn default() -> Self {
        Self {
            early: false,
            map: Default::default(),
            acks: Default::default(),
        }
    }
}

/// Tracks remaining expected ACKs of a message.
struct Acks {
    /// The message we sent and await ACKs for.
    msg: Bytes,
    /// The time when the message was first sent.
    start: Instant,
    /// The time when the message was last sent.
    timestamp: Instant,
    /// The number of delivery retries.
    retries: usize,
    /// The number of parties that still have to send an ACK back.
    rem: Vec<PublicKey>,
}

/// Tracking information about a message and its status.
struct Tracker<T: Committable> {
    /// The producer of this message.
    source: Option<PublicKey>,
    /// Are we the original producer of this message?
    ours: bool,
    /// The time when this info was created.
    start: Instant,
    /// The time when this info was last updated.
    timestamp: Instant,
    /// The number of delivery retries.
    retries: usize,
    /// The message, if any.
    ///
    /// If we receive votes before the message, this item will be empty.
    message: Item<Envelope<Vertex<T>, Validated>>,
    /// The votes for a message.
    votes: VoteAccumulator<Digest>,
    /// The message status.
    status: Status,
}

impl<T: Committable> Tracker<T> {
    /// Randomly select a voter of the given commitment.
    fn choose_voter(&self, d: &Commitment<Digest>) -> Option<PublicKey> {
        use rand::seq::IteratorRandom;
        self.votes.voters(d).choose(&mut rand::rng()).copied()
    }
}

/// A message item.
struct Item<T> {
    /// This item's value, i.e. the message.
    item: Option<T>,
    /// If `true`, this item was delivered early.
    ///
    /// The flag is used for performance reasons to avoid duplicate delivery
    /// of a message to the application layer.
    early: bool,
}

impl<T> Item<T> {
    fn none() -> Self {
        Self {
            item: None,
            early: false,
        }
    }

    fn some(item: T) -> Self {
        Self {
            item: Some(item),
            early: false,
        }
    }
}

/// Message status.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Status {
    /// Nothing has happened yet
    Init,
    /// Message proposal has been submitted to the network.
    SentMsg,
    /// A message proposal has been received from the network.
    ReceivedMsg,
    /// Our vote for a message proposal has been submitted to the network.
    SentVote,
    /// We ask for the message corresponding to a quorum of votes.
    ///
    /// If we have collected a quorum of votes or received a quorum certificate
    /// before we received the message itself, we asked a random signer for it.
    RequestedMsg,
    /// We have received one or more votes.
    ReceivedVotes,
    /// A quorum of votes has been reached.
    ReachedQuorum,
    /// The message has been RBC delivered (terminal state).
    Delivered,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => f.write_str("init"),
            Self::SentMsg => f.write_str("sent-msg"),
            Self::ReceivedMsg => f.write_str("recv-msg"),
            Self::SentVote => f.write_str("sent-vote"),
            Self::ReceivedVotes => f.write_str("recv-votes"),
            Self::ReachedQuorum => f.write_str("quorum"),
            Self::RequestedMsg => f.write_str("req-msg"),
            Self::Delivered => f.write_str("delivered"),
        }
    }
}

impl<C: RawComm, T: Committable> Worker<C, T> {
    pub fn new(tx: Sender<T>, rx: Receiver<T>, cfg: RbcConfig, nt: C) -> Self {
        Self {
            label: cfg.keypair.public_key(),
            config: cfg,
            comm: nt,
            tx,
            rx,
            round: RoundNumber::genesis(),
            buffer: BTreeMap::new(),
            timer: {
                let mut i = time::interval(Duration::from_secs(1));
                i.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                i
            },
        }
    }
}

impl<C: RawComm, T: Clone + Committable + Serialize + DeserializeOwned> Worker<C, T> {
    /// The main event loop of this worker.
    ///
    /// We either receive messages from the application to send or from the network
    /// to deliver. Periodically we also revisit our message buffer and try to make
    /// progress.
    pub async fn go(mut self) {
        loop {
            tokio::select! {
                now = self.timer.tick() => {
                    match self.retry(now).await {
                        Ok(()) => {}
                        Err(RbcError::Shutdown) => {
                            debug!(node = %self.label, "rbc shutdown detected");
                            return;
                        }
                        Err(err) => {
                            warn!(node = %self.label, %err, "error retrying");
                        }
                    }
                },
                val = self.comm.receive() => {
                    match val {
                        Ok((key, bytes)) => {
                            match self.on_inbound(key, bytes).await {
                                Ok(()) => {}
                                Err(RbcError::Shutdown) => {
                                    debug!(node = %self.label, "rbc shutdown detected");
                                    return;
                                }
                                Err(err) => {
                                    warn!(node = %self.label, %err, "error on inbound message");
                                }
                            }
                        }
                        Err(err) => {
                            warn!(node = %self.label, %err, "error receiving message from network")
                        }
                    }
                },
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(Command::RbcBroadcast(v, tx)) => {
                            match self.on_outbound(v).await {
                                Ok(()) => {
                                    let _ = tx.send(Ok(()));
                                }
                                Err(err) => {
                                    warn!(node = %self.label, %err, "error rbc broadcasting message");
                                    let _ = tx.send(Err(err));
                                }
                            }
                        }
                        // Best-effort sending to a peer without RBC properties.
                        Some(Command::Send(to, msg)) => {
                            match self.on_send(to, msg).await {
                                Ok(()) => {}
                                Err(err) => warn!(node = %self.label, %err, "error sending message")
                            }
                        }
                        // Best-effort broadcast without RBC properties.
                        Some(Command::Broadcast(msg)) => {
                            match self.on_broadcast(msg).await {
                                Ok(()) => {}
                                Err(err) => {
                                    warn!(node = %self.label, %err, "error broadcasting message")
                                }
                            }
                        }
                        None => {
                            debug!(node = %self.label, "rbc shutdown detected");
                            return
                        }
                    }
                }
            }
        }
    }

    /// Best effort broadcast.
    async fn on_broadcast(&mut self, msg: Message<T, Validated>) -> Result<()> {
        trace!(node = %self.label, %msg, "broadcasting");
        let proto = Protocol::Send(Cow::Borrowed(&msg));
        let bytes = serialize(&proto)?;
        let digest = Digest::of_msg(&msg);
        // Expect an ACK from each party:
        self.buffer
            .entry(digest.round())
            .or_default()
            .acks
            .entry(digest)
            .or_insert_with(|| {
                let now = Instant::now();
                Acks {
                    msg: bytes.clone(),
                    start: now,
                    timestamp: now,
                    retries: 0,
                    rem: self.config.committee.parties().copied().collect(),
                }
            });
        self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
        Ok(())
    }

    /// 1:1 communication.
    async fn on_send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<()> {
        trace!(node = %self.label, %to, %msg, "sending");
        let proto = Protocol::Send(Cow::Borrowed(&msg));
        let bytes = serialize(&proto)?;
        let digest = Digest::of_msg(&msg);
        // Expect an ACK from `to`:
        self.buffer
            .entry(digest.round())
            .or_default()
            .acks
            .entry(digest)
            .or_insert_with(|| {
                let now = Instant::now();
                Acks {
                    msg: bytes.clone(),
                    start: now,
                    timestamp: now,
                    retries: 0,
                    rem: vec![to],
                }
            });
        self.comm.send(to, bytes).await.map_err(RbcError::net)
    }

    /// Start RBC broadcast.
    async fn on_outbound(&mut self, vertex: Envelope<Vertex<T>, Validated>) -> Result<()> {
        trace!(node = %self.label, vertex = %vertex.data(), "proposing");
        let proto = Protocol::Propose(Cow::Borrowed(&vertex));
        let bytes = serialize(&proto)?;
        let digest = Digest::of_vertex(&vertex);

        // We track the max. round number to know when it is safe to remove
        // old messages from our buffer.
        self.round = max(self.round, *vertex.data().round().data());

        // Remove buffer entries that are too old to be relevant.
        self.buffer.retain(|r, _| {
            let n = self.config.committee.size().get() as u64;
            let t = self.config.committee.threshold().get() as u64;
            *r + n + t >= self.round
        });

        let now = Instant::now();

        let tracker = Tracker {
            source: Some(self.config.keypair.public_key()),
            ours: true,
            start: now,
            timestamp: now,
            retries: 0,
            message: Item::some(vertex),
            votes: VoteAccumulator::new(self.config.committee.clone()),
            status: Status::Init,
        };

        let tracker = self
            .buffer
            .entry(digest.round())
            .or_default()
            .map
            .entry(digest)
            .or_insert(tracker);

        if let Err(e) = self.comm.broadcast(bytes).await {
            debug!(node = %self.label, %e, "network error");
        } else {
            debug!(node = %self.label, %digest, "message broadcast");
            tracker.status = Status::SentMsg;
        }

        Ok(())
    }

    /// We received a message from the network.
    async fn on_inbound(&mut self, src: PublicKey, bytes: Bytes) -> Result<()> {
        trace!(node = %self.label, %src, "inbound message");
        match bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?.0 {
            Protocol::Send(msg) => self.on_message(src, msg.into_owned()).await?,
            Protocol::Ack(dig) => self.on_ack(src, dig).await?,
            Protocol::Propose(msg) => self.on_propose(src, msg.into_owned()).await?,
            Protocol::Vote(env, done) => self.on_vote(env, done).await?,
            Protocol::GetRequest(dig) => self.on_get_request(src, dig).await?,
            Protocol::GetResponse(msg) => self.on_get_response(src, msg.into_owned()).await?,
            Protocol::Cert(crt) => self.on_cert(src, crt).await?,
        }

        Ok(())
    }

    /// A non-RBC message has been received which we deliver directly to the application.
    async fn on_message(&mut self, src: PublicKey, msg: Message<T, Unchecked>) -> Result<()> {
        trace!(node = %self.label, %src, %msg, "message received");
        if msg.is_vertex() {
            warn!(node = %self.label, %src, "received rbc message as non-rbc message");
            return Err(RbcError::InvalidMessage);
        }
        let Some(msg) = msg.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };
        let dig = Digest::of_msg(&msg);
        let ack = Protocol::<'_, T, Validated>::Ack(dig);
        let bytes = serialize(&ack)?;
        self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
        debug!(node = %self.label, digest = %dig, %src, "sending ack");
        self.comm.send(src, bytes).await.map_err(RbcError::net)
    }

    /// A message acknowledgement has been received.
    async fn on_ack(&mut self, src: PublicKey, digest: Digest) -> Result<()> {
        trace!(node = %self.label, %src, %digest, "ack received");
        let Some(msgs) = self.buffer.get_mut(&digest.round()) else {
            debug!(node = %self.label, %digest, "no ack expected for digest round");
            return Ok(());
        };

        let Some(acks) = msgs.acks.get_mut(&digest) else {
            debug!(node = %self.label, %digest, "no ack expected for digest");
            return Ok(());
        };

        acks.rem.retain(|k| *k != src);

        if acks.rem.is_empty() {
            self.config.metrics.add_ack_duration(acks.start.elapsed());
            msgs.acks.remove(&digest);
        }

        Ok(())
    }

    /// An RBC message proposal has been received.
    async fn on_propose(
        &mut self,
        src: PublicKey,
        vertex: Envelope<Vertex<T>, Unchecked>,
    ) -> Result<()> {
        trace!(node = %self.label, %src, vertex = %vertex.data(), "proposal received");
        let Some(vertex) = vertex.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        if *vertex.signing_key() != src {
            warn!(node = %self.label, %src, "message sender != message signer");
            return Err(RbcError::InvalidMessage);
        }

        let digest = Digest::of_vertex(&vertex);

        if let Some(messages) = self.buffer.get(&digest.round()) {
            if let Some(d) = messages.digest(&src) {
                if d != digest {
                    warn!(node = %self.label, %src, "multiple proposals received");
                    return Err(RbcError::InvalidMessage);
                }
            }
        }

        let messages = self.buffer.entry(digest.round()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| {
            let now = Instant::now();
            Tracker {
                source: None,
                ours: false,
                start: now,
                timestamp: now,
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(self.config.committee.clone()),
                status: Status::Init,
            }
        });

        match tracker.status {
            // First time we see this message.
            Status::Init => {
                tracker.source = Some(src);
                tracker.message = Item::some(vertex);
                tracker.status = Status::ReceivedMsg;
                let env = Envelope::signed(digest, &self.config.keypair, false);
                let vote = Protocol::<'_, T, Validated>::Vote(env, false);
                let bytes = serialize(&vote)?;
                self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                tracker.status = Status::SentVote
            }
            // We received a duplicate or a reflection of our own outbound message.
            // In any case we did not manage to cast our vote yet, so we try again.
            Status::ReceivedMsg | Status::SentMsg => {
                debug_assert!(tracker.message.item.is_some());
                let env = Envelope::signed(digest, &self.config.keypair, false);
                let vote = Protocol::<'_, T, Validated>::Vote(env, false);
                let bytes = serialize(&vote)?;
                self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                tracker.status = Status::SentVote
            }
            // We received votes, possibly prior to the message. If so we update the
            // tracking info with the actual message proposal and vote on the message.
            Status::ReceivedVotes => {
                if tracker.message.item.is_none() {
                    tracker.source = Some(src);
                    tracker.message = Item::some(vertex);
                    let env = Envelope::signed(digest, &self.config.keypair, false);
                    let vote = Protocol::<'_, T, Validated>::Vote(env, false);
                    let bytes = serialize(&vote)?;
                    self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                    tracker.status = Status::SentVote
                }
            }
            // We have received enough votes to form a quorum but we either did not manage
            // to request the message or to broadcast the certificate.
            Status::ReachedQuorum => {
                if tracker.message.item.is_none() {
                    tracker.source = Some(src);
                    tracker.message = Item::some(vertex.clone());
                    let cert = tracker.votes.certificate().expect("quorum => certificate");
                    if let Entry::Vacant(acks) = messages.acks.entry(Digest::of_cert(cert)) {
                        let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                        let b = serialize(&m)?;
                        let now = Instant::now();
                        acks.insert(Acks {
                            msg: b.clone(),
                            start: now,
                            timestamp: now,
                            retries: 0,
                            rem: self.config.committee.parties().copied().collect(),
                        });
                        self.comm.broadcast(b).await.map_err(RbcError::net)?;
                    }
                }
                self.tx
                    .send(Message::Vertex(vertex.clone()))
                    .await
                    .map_err(|_| RbcError::Shutdown)?;
                self.config
                    .metrics
                    .add_delivery_duration(tracker.start.elapsed());
                debug!(node = %self.label, vertex = %vertex.data(), %digest, "delivered");
                tracker.status = Status::Delivered
            }
            // We had previously reached a quorum of votes but were missing the message
            // which now arrived (after we requested it). We can finally deliver it to
            // the application.
            Status::RequestedMsg => {
                tracker.source = Some(src);
                tracker.message = Item::some(vertex.clone());
                debug!(node = %self.label, vertex = %vertex.data(), %digest, "delivered");
                self.tx
                    .send(Message::Vertex(vertex))
                    .await
                    .map_err(|_| RbcError::Shutdown)?;
                tracker.status = Status::Delivered;
                self.config
                    .metrics
                    .add_delivery_duration(tracker.start.elapsed())
            }
            // These states already have the message, so there is nothing to be done.
            Status::Delivered | Status::SentVote => {
                debug!(node = %self.label, %digest, status = %tracker.status, "ignoring message proposal");
                debug_assert!(tracker.message.item.is_some())
            }
        }

        if self.config.early_delivery && !messages.early {
            let available = messages
                .map
                .values()
                .filter(|t| t.message.item.is_some())
                .count();

            if available >= self.config.committee.quorum_size().get() {
                for tracker in messages.map.values_mut() {
                    if tracker.status == Status::Delivered {
                        continue;
                    }
                    if let Some(vertex) = &tracker.message.item {
                        self.tx
                            .send(Message::Vertex(vertex.clone()))
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        tracker.message.early = true;
                        self.config
                            .metrics
                            .add_delivery_duration(tracker.start.elapsed());
                        debug!(node = %self.label, vertex = %vertex.data(), %digest, "delivered");
                    }
                }
                messages.early = true
            }
        }

        Ok(())
    }

    /// A proposal vote has been received.
    async fn on_vote(&mut self, env: Envelope<Digest, Unchecked>, done: bool) -> Result<()> {
        trace!(node = %self.label, src = %env.signing_key(), %done, "vote received");
        let Some(env) = env.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let digest = *env.data();
        let commit = digest.commit();
        let source = *env.signing_key();

        let messages = self.buffer.entry(digest.round()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| {
            let now = Instant::now();
            Tracker {
                source: None,
                ours: false,
                start: now,
                timestamp: now,
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(self.config.committee.clone()),
                status: Status::Init,
            }
        });

        debug!(
            node   = %self.label,
            digest = %digest,
            status = %tracker.status,
            votes  = %tracker.votes.votes(&commit),
            "vote received"
        );

        match tracker.status {
            // Votes may precede the message proposal. We just try to add the votes
            // to our accumulator and see if we have reached a quorum. If this happens
            // we broadcast the certificate and deliver the message to the application
            // unless of course we are missing it, in which case we ask a single peer
            // to send it to us.
            Status::Init
            | Status::ReceivedMsg
            | Status::SentMsg
            | Status::ReceivedVotes
            | Status::SentVote => match tracker.votes.add(env.into_signed()) {
                Ok(None) => tracker.status = Status::ReceivedVotes,
                Ok(Some(cert)) => {
                    tracker.status = Status::ReachedQuorum;
                    if let Some(vertex) = &tracker.message.item {
                        let cert_digest = Digest::of_cert(cert);
                        if let Entry::Vacant(acks) = messages.acks.entry(cert_digest) {
                            let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                            let b = serialize(&m)?;
                            let now = Instant::now();
                            acks.insert(Acks {
                                msg: b.clone(),
                                start: now,
                                timestamp: now,
                                retries: 0,
                                rem: self.config.committee.parties().copied().collect(),
                            });
                            self.comm.broadcast(b).await.map_err(RbcError::net)?;
                        }
                        if !tracker.message.early {
                            self.tx
                                .send(Message::Vertex(vertex.clone()))
                                .await
                                .map_err(|_| RbcError::Shutdown)?;
                            self.config
                                .metrics
                                .add_delivery_duration(tracker.start.elapsed());
                            debug!(node = %self.label, vertex = %vertex.data(), %digest, "delivered");
                        }
                        tracker.status = Status::Delivered
                    } else {
                        let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                        let b = serialize(&m)?;
                        let s = tracker.choose_voter(&commit).expect("certificate => voter");
                        self.comm.send(s, b).await.map_err(RbcError::net)?;
                        tracker.status = Status::RequestedMsg;
                    }
                }
                Err(err) => {
                    warn!(node = %self.label, %err, %digest, "failed to add vote");
                    if tracker.votes.is_empty() && tracker.message.item.is_none() {
                        if let Some(messages) = self.buffer.get_mut(&digest.round()) {
                            messages.map.remove(&digest);
                        }
                    }
                }
            },
            // We have previously reached the quorum of votes but did not manage to request
            // the still missing message. We use this additional vote to try again.
            Status::ReachedQuorum if tracker.message.item.is_none() => {
                let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                let b = serialize(&m)?;
                let s = tracker.choose_voter(&commit).expect("quorum => voter");
                self.comm.send(s, b).await.map_err(RbcError::net)?;
                tracker.status = Status::RequestedMsg;
            }
            Status::ReachedQuorum | Status::RequestedMsg | Status::Delivered => {
                if done {
                    debug!(node = %self.label, status = %tracker.status, "ignoring vote")
                } else {
                    debug!(
                        node   = %self.label,
                        digest = %digest,
                        status = %tracker.status,
                        "replying with our vote to sender"
                    );
                    let env = Envelope::signed(digest, &self.config.keypair, false);
                    let vote = Protocol::<'_, T, Validated>::Vote(env, true);
                    let bytes = serialize(&vote)?;
                    self.comm.send(source, bytes).await.map_err(RbcError::net)?;
                }
            }
        }

        Ok(())
    }

    /// We received a vote certificate.
    async fn on_cert(&mut self, src: PublicKey, crt: Certificate<Digest>) -> Result<()> {
        trace!(node = %self.label, %src, digest = %crt.data(), "certificate received");
        let digest = *crt.data();
        let cert_digest = Digest::of_cert(&crt);

        if let Some(r) = self.buffer.keys().next() {
            if digest.round() < *r {
                // Certificate is too old.
                self.ack(src, cert_digest).await?;
                return Ok(());
            }
        }

        if !crt.is_valid_par(&self.config.committee) {
            return Err(RbcError::InvalidMessage);
        }

        let commit = digest.commit();

        let messages = self.buffer.entry(digest.round()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| {
            let now = Instant::now();
            Tracker {
                source: None,
                ours: false,
                start: now,
                timestamp: now,
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(self.config.committee.clone()),
                status: Status::Init,
            }
        });

        match tracker.status {
            // The certificate allows us to immediately reach the quorum and deliver the
            // message to the application layer. If we are missing the message, we have to
            // ask one of our peers for it.
            Status::Init
            | Status::ReceivedMsg
            | Status::SentMsg
            | Status::ReceivedVotes
            | Status::SentVote => {
                tracker.votes.set_certificate(crt.clone());
                tracker.status = Status::ReachedQuorum;

                if let Some(vertex) = &tracker.message.item {
                    if let Entry::Vacant(acks) = messages.acks.entry(cert_digest) {
                        let m = Protocol::<'_, T, Validated>::Cert(crt);
                        let b = serialize(&m)?;
                        let now = Instant::now();
                        acks.insert(Acks {
                            msg: b.clone(),
                            start: now,
                            timestamp: now,
                            retries: 0,
                            rem: self.config.committee.parties().copied().collect(),
                        });
                        self.comm.broadcast(b).await.map_err(RbcError::net)?;
                    }
                    if !tracker.message.early {
                        self.tx
                            .send(Message::Vertex(vertex.clone()))
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        self.config
                            .metrics
                            .add_delivery_duration(tracker.start.elapsed());
                        debug!(node = %self.label, vertex = %vertex.data(), %digest, "delivered");
                    }
                    tracker.status = Status::Delivered
                } else {
                    let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                    let b = serialize(&m)?;
                    let s = tracker.choose_voter(&commit).expect("certificate => voter");
                    self.comm.send(s, b).await.map_err(RbcError::net)?;
                    tracker.status = Status::RequestedMsg;
                }
            }
            // We have previously reached the quorum of votes but did not manage to request
            // the still missing message. Let's try again.
            Status::ReachedQuorum if tracker.message.item.is_none() => {
                let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                let b = serialize(&m)?;
                let s = tracker.choose_voter(&commit).expect("quorum => voter");
                self.comm.send(s, b).await.map_err(RbcError::net)?;
                tracker.status = Status::RequestedMsg;
            }
            Status::ReachedQuorum | Status::RequestedMsg | Status::Delivered => {
                debug!(node = %self.label, status = %tracker.status, "ignoring certificate")
            }
        }

        self.ack(src, cert_digest).await?;

        Ok(())
    }

    /// One of our peers is asking for a message proposal.
    async fn on_get_request(&mut self, src: PublicKey, digest: Digest) -> Result<()> {
        trace!(node = %self.label, %src, %digest, "get request received");
        let Some(tracker) = self
            .buffer
            .get_mut(&digest.round())
            .and_then(|m| m.map.get_mut(&digest))
        else {
            warn!(
                node = %self.label,
                src  = %src,
                "ignoring get request for data we do not have"
            );
            return Ok(());
        };

        match tracker.status {
            // We do not have the message ourselves when in these states.
            Status::Init | Status::RequestedMsg => {
                debug!(node = %self.label, %digest, status = %tracker.status, "ignoring get request");
                debug_assert!(tracker.message.item.is_none())
            }
            // Here, we may have the message and if so, we gladly share it.
            Status::SentVote | Status::ReceivedVotes | Status::ReachedQuorum => {
                if let Some(msg) = &tracker.message.item {
                    respond(&mut self.comm, src, msg).await?;
                }
            }
            // In these states we must have the message and send to the peer.
            Status::ReceivedMsg | Status::SentMsg | Status::Delivered => {
                let msg = tracker
                    .message
                    .item
                    .as_ref()
                    .expect("message item is present in these status");
                respond(&mut self.comm, src, msg).await?;
            }
        }

        Ok(())
    }

    /// We received a response to our get request.
    async fn on_get_response(
        &mut self,
        src: PublicKey,
        vertex: Envelope<Vertex<T>, Unchecked>,
    ) -> Result<()> {
        trace!(node = %self.label, %src, vertex = %vertex.data(), "get response received");
        let Some(vertex) = vertex.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let digest = Digest::of_vertex(&vertex);

        let Some(tracker) = self
            .buffer
            .get_mut(&digest.round())
            .and_then(|m| m.map.get_mut(&digest))
        else {
            debug!(node = %self.label, %src, "no tracker for get response");
            return Ok(());
        };

        if Status::RequestedMsg != tracker.status {
            debug!(node = %self.label, status = %tracker.status, %src, "ignoring get response");
            return Ok(());
        }

        self.tx
            .send(Message::Vertex(vertex.clone()))
            .await
            .map_err(|_| RbcError::Shutdown)?;

        tracker.message = Item::some(vertex);
        tracker.status = Status::Delivered;

        Ok(())
    }

    /// Periodically we go over message status and retry incomplete items.
    async fn retry(&mut self, now: Instant) -> Result<()> {
        trace!(node = %self.label, "retrying ...");
        // Go over RBC messages and check status:
        for (digest, tracker) in self.buffer.values_mut().flat_map(|m| m.map.iter_mut()) {
            trace!(
                node    = %self.label,
                digest  = %digest,
                status  = %tracker.status,
                retries = %tracker.retries,
                "revisiting"
            );
            match tracker.status {
                Status::Init | Status::Delivered => {}
                // We have sent a message but did not make further progress, so
                // we try to send the message again and hope for some response.
                Status::SentMsg => {
                    let timeout = [3, 6, 10, 15, 30]
                        .get(tracker.retries)
                        .copied()
                        .unwrap_or(30);
                    if tracker.timestamp.elapsed() < Duration::from_secs(timeout) {
                        continue;
                    }
                    let vertex = tracker
                        .message
                        .item
                        .as_ref()
                        .expect("message was sent => set in tracker");
                    debug!(node = %self.label, %digest, vertex = %vertex.data(), "re-broadcasting");
                    let proto = Protocol::Propose(Cow::Borrowed(vertex));
                    let bytes = serialize(&proto).expect("idempotent serialization");
                    tracker.timestamp = now;
                    tracker.retries = tracker.retries.saturating_add(1);
                    self.config.metrics.retries.add(1);
                    if let Err(err) = self.comm.broadcast(bytes).await {
                        debug!(node = %self.label, %err, "network error");
                    }
                }
                // If we have a message we might not have been able to send our vote
                // or it might not have reached enough parties, so we try again here.
                Status::ReceivedMsg | Status::ReceivedVotes | Status::SentVote => {
                    if let Some(msg) = &tracker.message.item {
                        let timeout = [3, 6, 10, 15, 30]
                            .get(tracker.retries)
                            .copied()
                            .unwrap_or(30);
                        if tracker.timestamp.elapsed() < Duration::from_millis(timeout) {
                            continue;
                        }
                        if tracker.ours {
                            debug!(node = %self.label, %digest, "sending our message (again)");
                            let proto = Protocol::Propose(Cow::Borrowed(msg));
                            let bytes = serialize(&proto)?;
                            self.comm.broadcast(bytes).await.map_err(RbcError::net)?
                        }
                        debug!(node = %self.label, %digest, "sending our vote (again)");
                        let env = Envelope::signed(*digest, &self.config.keypair, false);
                        let vote = Protocol::<'_, T, Validated>::Vote(env, false);
                        let bytes = serialize(&vote).expect("idempotent serialization");
                        tracker.timestamp = now;
                        tracker.retries = tracker.retries.saturating_add(1);
                        self.config.metrics.retries.add(1);
                        self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                        tracker.status = Status::SentVote
                    }
                }
                // We have reached a quorum of votes but are missing the message which we
                // had previously requested => try again, potentially from a different
                // source.
                Status::RequestedMsg => {
                    let timeout = [1, 3, 6, 10, 15, 30]
                        .get(tracker.retries)
                        .copied()
                        .unwrap_or(30);
                    if tracker.timestamp.elapsed() < Duration::from_millis(timeout) {
                        continue;
                    }
                    debug!(node = %self.label, %digest, "requesting message again");
                    let m = Protocol::<'_, T, Validated>::GetRequest(*digest);
                    let b = serialize(&m).expect("idempotent serialization");
                    let c = digest.commit();
                    let s = tracker.choose_voter(&c).expect("req-msg => voter");
                    tracker.timestamp = now;
                    tracker.retries = tracker.retries.saturating_add(1);
                    self.config.metrics.retries.add(1);
                    self.comm.send(s, b).await.map_err(RbcError::net)?;
                }
                // We have reached a quorum of votes. We may either already have the message,
                // in which case we previously failed to broadcast the certificate, or we did
                // not manage to request the message yet.
                Status::ReachedQuorum => {
                    let timeout = [3, 6, 10, 15, 30]
                        .get(tracker.retries)
                        .copied()
                        .unwrap_or(30);
                    if tracker.timestamp.elapsed() < Duration::from_millis(timeout) {
                        continue;
                    }
                    if let Some(vertex) = &tracker.message.item {
                        if !tracker.message.early {
                            self.tx
                                .send(Message::Vertex(vertex.clone()))
                                .await
                                .map_err(|_| RbcError::Shutdown)?;
                            self.config
                                .metrics
                                .add_delivery_duration(tracker.start.elapsed());
                            debug!(node = %self.label, vertex = %vertex.data(), %digest, "delivered");
                        }
                        tracker.status = Status::Delivered
                    } else {
                        debug!(node = %self.label, %digest, "requesting message");
                        let m = Protocol::<'_, T, Validated>::GetRequest(*digest);
                        let b = serialize(&m).expect("idempotent serialization");
                        let c = digest.commit();
                        let s = tracker.choose_voter(&c).expect("quorum => voter");
                        tracker.timestamp = now;
                        tracker.retries = tracker.retries.saturating_add(1);
                        self.config.metrics.retries.add(1);
                        self.comm.send(s, b).await.map_err(RbcError::net)?;
                        tracker.status = Status::RequestedMsg;
                    }
                }
            }
        }

        // Go over outstanding ACKs and re-transmit:
        for (digest, acks) in self.buffer.values_mut().flat_map(|m| m.acks.iter_mut()) {
            let timeout = [3, 6, 10, 15, 30].get(acks.retries).copied().unwrap_or(30);
            if acks.timestamp.elapsed() < Duration::from_millis(timeout) {
                continue;
            }
            for party in &acks.rem {
                debug!(node = %self.label, %digest, src = %party, "re-sending message");
                self.comm
                    .send(*party, acks.msg.clone())
                    .await
                    .map_err(RbcError::net)?
            }
            acks.retries = acks.retries.saturating_add(1);
            self.config.metrics.retries.add(1);
            acks.timestamp = now
        }

        Ok(())
    }

    async fn ack(&mut self, to: PublicKey, dig: Digest) -> Result<()> {
        let ack = Protocol::<'_, T, Validated>::Ack(dig);
        let bytes = serialize(&ack)?;
        debug!(node = %self.label, %to, digest = %dig, "sending ack");
        self.comm.send(to, bytes).await.map_err(RbcError::net)
    }
}

/// Factored out of `Worker` to help with borrowing.
async fn respond<T: Clone + Committable + Serialize, C: RawComm>(
    net: &mut C,
    to: PublicKey,
    vertex: &Envelope<Vertex<T>, Validated>,
) -> Result<()> {
    let proto = Protocol::GetResponse(Cow::Borrowed(vertex));
    let bytes = serialize(&proto)?;
    net.send(to, bytes).await.map_err(RbcError::net)?;
    Ok(())
}

/// Serialize a given data type into `Bytes`
fn serialize<T: Serialize>(d: &T) -> Result<Bytes> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    Ok(b.into_inner().freeze())
}

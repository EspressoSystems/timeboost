use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use bytes::Bytes;
use cliquenet::{
    Overlay,
    overlay::{Data, NetworkDown, SeqId},
};
use committable::{Commitment, Committable};
use multisig::{Certificate, Envelope, PublicKey, VoteAccumulator};
use multisig::{Unchecked, Validated};
use sailfish_types::{Evidence, Message, RoundNumber, Vertex};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, error, trace, warn};

use crate::RbcError;
use crate::digest::Digest;

use super::{Command, Nonce, Protocol, RbcConfig, serialize};

type RbcResult<T> = std::result::Result<T, RbcError>;
type SendResult<T> = std::result::Result<T, NetworkDown>;
type Sender<T> = mpsc::Sender<Message<T, Validated>>;
type Receiver<T> = mpsc::Receiver<Command<T>>;

/// A worker is run by `Rbc` to perform the actual work of sending and
/// delivering messages.
pub struct Worker<T: Committable> {
    /// RBC configuration.
    config: RbcConfig,
    /// Our own public key.
    key: PublicKey,
    /// Underlying communication network.
    comm: Overlay,
    /// Our channel to deliver messages to the application layer.
    tx: Sender<T>,
    /// Our channel to receive messages from the application layer.
    rx: Receiver<T>,
    /// The tracking information per message.
    buffer: BTreeMap<RoundNumber, Messages<T>>,
    /// The state the worker is in.
    state: WorkerState,
    /// The latest round number this worker is in.
    round: (RoundNumber, Evidence)
}

enum WorkerState {
    Start(Nonce, HashMap<PublicKey, RoundNumber>),
    Barrier(RoundNumber),
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
    /// The last sequence ID used when we proposed a message.
    ///
    /// This ties our own garbage collection to the one on the overlay network,
    /// i.e. when we garbage collect a round we also garbage collect the
    /// overlay network up to this sequence ID. It is set whenever we send out
    /// a proposal.
    last: Option<SeqId>,
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
            last: None,
        }
    }
}

/// Tracking information about a message and its status.
struct Tracker<T: Committable> {
    /// Are we the producer of this message?
    ours: bool,
    /// The time when this info was created.
    start: Instant,
    /// The message (if any).
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
    /// Message or votes have been sent or received.
    Initiated,
    /// We asked for the message corresponding to a quorum of votes.
    ///
    /// If we have collected a quorum of votes or received a quorum certificate
    /// before we received the message itself, we asked a random signer for it.
    Requested,
    /// The message has been RBC delivered (terminal state).
    Delivered,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Initiated => f.write_str("initiated"),
            Self::Requested => f.write_str("requested"),
            Self::Delivered => f.write_str("delivered"),
        }
    }
}

impl<T: Committable> Worker<T> {
    pub fn new(tx: Sender<T>, rx: Receiver<T>, cfg: RbcConfig, net: Overlay) -> Self {
        Self {
            key: cfg.keypair.public_key(),
            config: cfg,
            comm: net,
            tx,
            rx,
            buffer: BTreeMap::new(),
            round: (RoundNumber::genesis(), Evidence::Genesis),
            state: WorkerState::Start(Nonce::new(), HashMap::new())
        }
    }
}

impl<T: Clone + Committable + Serialize + DeserializeOwned> Worker<T> {
    /// The main event loop of this worker.
    ///
    /// We either receive messages from the application to send or from the network
    /// to deliver. Periodically we also revisit our message buffer and try to make
    /// progress.
    pub async fn go(mut self) {
        if let Err(err) = self.startup().await {
            error!(node = %self.key, %err, "startup failure");
            return
        }
        loop {
            tokio::select! {
                val = self.comm.receive(), if self.tx.capacity() > 0 => {
                    match val {
                        Ok((key, bytes)) => {
                            match self.on_inbound(key, bytes).await {
                                Ok(()) => {}
                                Err(RbcError::Shutdown) => {
                                    debug!(node = %self.key, "rbc shutdown detected");
                                    return;
                                }
                                Err(err) => {
                                    warn!(node = %self.key, %err, "error on inbound message");
                                }
                            }
                        }
                        Err(err) => {
                            let _: NetworkDown = err;
                            debug!(node = %self.key, "network went down");
                            return
                        }
                    }
                },
                cmd = self.rx.recv() => {
                    match cmd {
                        Some(Command::RbcBroadcast(v, data)) => {
                            if let Err(err) = self.propose(v, data).await {
                                let _: NetworkDown = err;
                                debug!(node = %self.key, "network went down");
                                return
                            }
                        }
                        // Best-effort sending to a peer without RBC properties.
                        Some(Command::Send(to, msg, data)) => {
                            if let Err(err) = self.send(to, msg, data).await {
                                let _: NetworkDown = err;
                                debug!(node = %self.key, "network went down");
                                return
                            }
                        }
                        // Best-effort broadcast without RBC properties.
                        Some(Command::Broadcast(msg, data)) => {
                            if let Err(err) = self.broadcast(msg, data).await {
                                let _: NetworkDown = err;
                                debug!(node = %self.key, "network went down");
                                return
                            }
                        }
                        Some(Command::Gc(round)) => {
                            debug!(node = %self.key, r = %round, "garbage collect");
                            if let Some(id) = self.buffer.get(&round).and_then(|m| m.last) {
                                self.comm.gc(id)
                            }
                            self.buffer.retain(|r, _| *r >= round);
                        }
                        None => {
                            debug!(node = %self.key, "rbc shutdown detected");
                            return
                        }
                    }
                }
            }
        }
    }

    /// Request round number information in startup.
    async fn startup(&mut self) -> RbcResult<()> {
        if let WorkerState::Start(nonce, _) = &self.state {
            let req = Protocol::<'_, T, Validated>::InfoRequest(*nonce);
            let bytes = serialize(&req)?;
            self.comm.broadcast(bytes).await?;
            debug!(node = %self.key, %nonce, "info request broadcasted");
        }
        Ok(())
    }

    /// Best effort broadcast.
    async fn broadcast(&mut self, msg: Message<T, Validated>, data: Data) -> SendResult<()> {
        if self.barrier().is_gt() {
            debug!(node = %self.key, "suppressing message broadcast");
            return Ok(())
        }
        let digest = Digest::of_msg(&msg);
        self.comm.broadcast(data).await?;
        debug!(node = %self.key, %digest, "message broadcasted");
        Ok(())
    }

    /// 1:1 communication.
    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>, data: Data) -> SendResult<()> {
        if self.barrier().is_gt() {
            debug!(node = %self.key, %msg, "suppressing direct send");
            return Ok(())
        }
        let digest = Digest::of_msg(&msg);
        self.comm.unicast(to, data).await?;
        debug!(node = %self.key, %to, %digest, "direct send");
        Ok(())
    }

    /// Start RBC broadcast.
    async fn propose(&mut self, vertex: Envelope<Vertex<T>, Validated>, data: Data) -> SendResult<()> {
        trace!(node = %self.key, vertex = %vertex.data(), "proposing");
        let digest = Digest::of_vertex(&vertex);

        self.round = (*vertex.data().round().data(), vertex.data().evidence().clone());

        let tracker = Tracker {
            ours: true,
            start: Instant::now(),
            message: Item::some(vertex),
            votes: VoteAccumulator::new(self.config.committee.clone()),
            status: Status::Initiated,
        };

        let can_send = self.barrier().is_le();
        let messages = self.buffer.entry(digest.round()).or_default();
        messages.map.insert(digest, tracker);

        if !can_send {
            debug!(node = %self.key, %digest, "suppressing proposal");
            return Ok(())
        }

        let id = self.comm.broadcast(data).await?;
        messages.last = Some(id);

        debug!(node = %self.key, %digest, "proposal broadcasted");

        Ok(())
    }

    /// We received a message from the network.
    async fn on_inbound(&mut self, src: PublicKey, bytes: Bytes) -> RbcResult<()> {
        trace!(node = %self.key, %src, buf = %self.buffer.len(), "inbound message");
        match bincode::serde::decode_from_slice(&bytes, bincode::config::standard())?.0 {
            Protocol::Send(msg) => self.on_message(src, msg.into_owned()).await?,
            Protocol::Propose(msg) => self.on_propose(src, msg.into_owned()).await?,
            Protocol::Vote(env, evi) => self.on_vote(src, env, evi).await?,
            Protocol::GetRequest(dig) => self.on_get_request(src, dig).await?,
            Protocol::GetResponse(msg) => self.on_get_response(src, msg.into_owned()).await?,
            Protocol::Cert(crt) => self.on_cert(src, crt).await?,
            Protocol::InfoRequest(nonce) => self.on_info_request(src, nonce).await?,
            Protocol::InfoResponse(n, r, e) => self.on_info_response(src, n, r, e.into_owned()).await?,
        }

        Ok(())
    }

    /// We receveived a round number information request.
    async fn on_info_request(&mut self, src: PublicKey, n: Nonce) -> RbcResult<()> {
        debug!(node = %self.key, %src, nonce = %n, "info request received");
        let (r, e) = &self.round;
        let proto = Protocol::<'_, T, Validated>::InfoResponse(n, *r, Cow::Borrowed(e));
        let bytes = serialize(&proto)?;
        self.comm.unicast(src, bytes).await?;
        Ok(())
    }

    /// We receveived a response to our round number information request.
    async fn on_info_response(&mut self, src: PublicKey, n: Nonce, r: RoundNumber, e: Evidence) -> RbcResult<()> {
        debug!(node = %self.key, %src, nonce = %n, %r, "info response received");

        let WorkerState::Start(nonce, rounds) = &mut self.state else {
            debug!(node = %self.key, %src, nonce = %n, %r, "startup phase already completed");
            return Ok(())
        };

        if rounds.contains_key(&src) {
            // We already received a response from this party.
            return Ok(())
        }

        if *nonce != n {
            warn!(node = %self.key, %src, ours = %nonce, theirs = %n, "nonce mismatch");
            return Ok(())
        }

        if !e.is_genesis() && (e.round() + 1 != r || !e.is_valid(&self.config.committee)) {
            warn!(node = %self.key, %src, "invalid round evidence");
            return Err(RbcError::InvalidMessage);
        }

        rounds.insert(src, r);

        if rounds.len() >= self.config.committee.quorum_size().get() {
            let round = rounds.values().max().copied().expect("|rounds| >= quorum > 0");

            let barrier = if round.is_genesis() {
                round
            } else {
                round.saturating_add(2).into()
            };

            self.state = WorkerState::Barrier(barrier);

            debug!(node = %self.key, %barrier, "round number info collected");

            if !barrier.is_genesis() {
                return Ok(())
            }

            if let Some(messages) = self.buffer.get_mut(&barrier) {
                for (digest, tracker) in &mut messages.map {
                    match tracker.status {
                        Status::Requested | Status::Delivered => continue,
                        Status::Initiated => {
                            if let Some(vertex) = &tracker.message.item {
                                if tracker.ours {
                                    let data = serialize(&Protocol::Propose(Cow::Borrowed(vertex)))?;
                                    let id = self.comm.broadcast(data).await?;
                                    messages.last = Some(id);
                                    debug!(node = %self.key, %digest, "proposal broadcasted");
                                }
                                if let Some(cert) = tracker.votes.certificate() {
                                    let cert_digest = Digest::of_cert(cert);
                                    let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                                    let b = serialize(&m)?;
                                    self.comm.broadcast(b).await?;
                                    debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                                } else {
                                    let evi = vertex.data().evidence().clone();
                                    let env = Envelope::signed(*digest, &self.config.keypair, false);
                                    let vote = Protocol::<'_, T, Validated>::Vote(env, evi);
                                    let bytes = serialize(&vote)?;
                                    self.comm.broadcast(bytes).await?;
                                    debug!(node = %self.key, %digest, "vote broadcasted");
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// A non-RBC message has been received which we deliver directly to the application.
    async fn on_message(&mut self, src: PublicKey, msg: Message<T, Unchecked>) -> RbcResult<()> {
        debug!(node = %self.key, %src, %msg, digest = %Digest::of_msg(&msg), "message received");
        if msg.is_vertex() {
            warn!(node = %self.key, %src, "received rbc message as non-rbc message");
            return Err(RbcError::InvalidMessage);
        }
        let Some(msg) = msg.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };
        self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    /// An RBC message proposal has been received.
    async fn on_propose(&mut self, src: PublicKey, vertex: Envelope<Vertex<T>, Unchecked>) -> RbcResult<()> {
        debug!(node = %self.key, %src, digest = %Digest::of_vertex(&vertex), "proposal received");
        let Some(vertex) = vertex.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        if *vertex.signing_key() != src {
            warn!(node = %self.key, %src, "message sender != message signer");
            return Err(RbcError::InvalidMessage);
        }

        let digest = Digest::of_vertex(&vertex);

        if let Some(messages) = self.buffer.get(&digest.round()) {
            if let Some(d) = messages.digest(&src) {
                if d != digest {
                    warn!(node = %self.key, %src, "multiple proposals received");
                    return Err(RbcError::InvalidMessage);
                }
            }
        }

        let can_send = self.barrier().is_le();
        let evidence = vertex.data().evidence().clone();
        let messages = self.buffer.entry(digest.round()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            message: Item::none(),
            votes: VoteAccumulator::new(self.config.committee.clone()),
            status: Status::Initiated,
        });

        match tracker.status {
            // If this is a new message or we received our own we vote for it.
            Status::Initiated => {
                if tracker.message.item.is_none() || src == self.key {
                    if can_send {
                        let env = Envelope::signed(digest, &self.config.keypair, false);
                        let vote = Protocol::<'_, T, Validated>::Vote(env, evidence);
                        let bytes = serialize(&vote)?;
                        self.comm.broadcast(bytes).await?;
                        debug!(node = %self.key, %digest, "vote broadcasted");
                    } else {
                        debug!(node = %self.key, %digest, "suppressing vote");
                    }
                }
                if tracker.message.item.is_none() {
                    tracker.ours = src == self.key;
                    tracker.message = Item::some(vertex);
                }
            }
            // We had previously reached a quorum of votes but were missing the
            // message which now arrived independently. We can finally deliver
            // it to the application.
            Status::Requested => {
                debug_assert!(tracker.message.item.is_none());
                tracker.ours = src == self.key;
                tracker.message = Item::some(vertex.clone());

                if can_send {
                    // Now that we have the message corresponding to the voter quorum we can
                    // broadcast the certificate as well:
                    let cert = tracker
                        .votes
                        .certificate()
                        .expect("requested message => certificate");
                    let cert_digest = Digest::of_cert(cert);
                    let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                    let b = serialize(&m)?;
                    self.comm.broadcast(b).await?;
                    debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                } else {
                    debug!(node = %self.key, %digest, "suppressing cert");
                }

                self.tx
                    .send(Message::Vertex(vertex.clone()))
                    .await
                    .map_err(|_| RbcError::Shutdown)?;
                tracker.status = Status::Delivered;
                self.config
                    .metrics
                    .add_delivery_duration(tracker.start.elapsed());
                debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
            }
            // Nothing to do here:
            Status::Delivered => {
                debug!(node = %self.key, %src, %digest, status = %tracker.status, "ignoring proposal");
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
                        debug!(node = %self.key, vertex = %vertex.data(), "delivered");
                    }
                }
                messages.early = true
            }
        }

        Ok(())
    }

    /// A proposal vote has been received.
    async fn on_vote(&mut self, src: PublicKey, env: Envelope<Digest, Unchecked>, evi: Evidence) -> RbcResult<()> {
        debug!(node = %self.key, %src, digest = %env.data(), "vote received");
        let Some(env) = env.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        if *env.signing_key() != src {
            warn!(node = %self.key, %src, "vote sender != vote signer");
            return Err(RbcError::InvalidMessage);
        }

        let digest = *env.data();
        let commit = digest.commit();

        // If a vote for a round greater than our current latest round + 1 arrives,
        // we demand evidence, that a quorum of parties is backing the round prior
        // to that vote.
        let latest_round = self
            .buffer
            .last_key_value()
            .map(|(r, _)| *r)
            .unwrap_or_else(RoundNumber::genesis);

        if digest.round() > latest_round + 1 {
            if evi.round() + 1 != digest.round() && !digest.round().is_genesis() {
                warn!(node = %self.key, %src, "invalid vote evidence round");
                return Err(RbcError::InvalidMessage);
            }
            if !evi.is_valid(&self.config.committee) {
                warn!(node = %self.key, %src, "invalid vote evidence");
                return Err(RbcError::InvalidMessage);
            }
        }

        let can_send = self.barrier().is_le();
        let messages = self.buffer.entry(digest.round()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            message: Item::none(),
            votes: VoteAccumulator::new(self.config.committee.clone()),
            status: Status::Initiated,
        });

        match tracker.status {
            // Votes may precede the message proposal. We just try to add the votes
            // to our accumulator and see if we have reached a quorum. If this happens
            // we broadcast the certificate and deliver the message to the application
            // unless of course we are missing it, in which case we ask a single peer
            // to send it to us.
            Status::Initiated => match tracker.votes.add(env.into_signed()) {
                Ok(Some(cert)) => {
                    if let Some(vertex) = &tracker.message.item {
                        if can_send {
                            let cert_digest = Digest::of_cert(cert);
                            let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                            let b = serialize(&m)?;
                            self.comm.broadcast(b).await?;
                            debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                        } else {
                            debug!(node = %self.key, %digest, "suppressing cert");
                        }
                        if !tracker.message.early {
                            self.tx
                                .send(Message::Vertex(vertex.clone()))
                                .await
                                .map_err(|_| RbcError::Shutdown)?;
                            self.config
                                .metrics
                                .add_delivery_duration(tracker.start.elapsed());
                            debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
                        }
                        tracker.status = Status::Delivered
                    } else {
                        let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                        let b = serialize(&m)?;
                        let s = tracker.choose_voter(&commit).expect("certificate => voter");
                        self.comm.unicast(s, b).await?;
                        tracker.status = Status::Requested;
                        debug!(node = %self.key, from = %s, %digest, "message requested")
                    }
                }
                Ok(None) => {
                    // quorum not reached yet => nothing else to do
                }
                Err(err) => {
                    warn!(node = %self.key, %err, %digest, "failed to add vote");
                    if tracker.votes.is_empty() && tracker.message.item.is_none() {
                        if let Some(messages) = self.buffer.get_mut(&digest.round()) {
                            messages.map.remove(&digest);
                        }
                    }
                }
            },
            Status::Requested | Status::Delivered => {
                debug!(node = %self.key, status = %tracker.status, "ignoring vote")
            }
        }

        Ok(())
    }

    /// We received a vote certificate.
    async fn on_cert(&mut self, src: PublicKey, crt: Certificate<Digest>) -> RbcResult<()> {
        let digest = *crt.data();
        let cert_digest = Digest::of_cert(&crt);

        debug!(node = %self.key, %src, %digest, cert = %cert_digest, "cert received");

        if let Some(r) = self.buffer.keys().next() {
            if digest.round() < *r {
                return Ok(());
            }
        }

        if !crt.is_valid_par(&self.config.committee) {
            return Err(RbcError::InvalidMessage);
        }

        let commit = digest.commit();
        let can_send = self.barrier().is_le();
        let messages = self.buffer.entry(digest.round()).or_default();
        let tracker = messages.map.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            message: Item::none(),
            votes: VoteAccumulator::new(self.config.committee.clone()),
            status: Status::Initiated,
        });

        match tracker.status {
            // The certificate allows us to immediately reach the quorum and deliver the
            // message to the application layer. If we are missing the message, we have to
            // ask one of our peers for it.
            Status::Initiated => {
                tracker.votes.set_certificate(crt.clone());
                if let Some(vertex) = &tracker.message.item {
                    if can_send {
                        let m = Protocol::<'_, T, Validated>::Cert(crt);
                        let b = serialize(&m)?;
                        self.comm.broadcast(b).await?;
                        debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                    } else {
                        debug!(node = %self.key, %digest, "suppressing cert");
                    }
                    if !tracker.message.early {
                        self.tx
                            .send(Message::Vertex(vertex.clone()))
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        self.config
                            .metrics
                            .add_delivery_duration(tracker.start.elapsed());
                        debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
                    }
                    tracker.status = Status::Delivered
                } else {
                    let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                    let b = serialize(&m)?;
                    let s = tracker.choose_voter(&commit).expect("certificate => voter");
                    self.comm.unicast(s, b).await?;
                    tracker.status = Status::Requested;
                    debug!(node = %self.key, from = %s, %digest, "message requested");
                }
            }
            Status::Requested | Status::Delivered => {
                debug!(node = %self.key, %digest, status = %tracker.status, "ignoring certificate")
            }
        }

        Ok(())
    }

    /// One of our peers is asking for a message proposal.
    async fn on_get_request(&mut self, src: PublicKey, digest: Digest) -> RbcResult<()> {
        debug!(node = %self.key, %src, %digest, "get request received");

        if self.barrier().is_gt() {
            debug!(node = %self.key, %src, %digest, "suppressing response to get request");
            return Ok(())
        }

        if let Some(msg) = self
            .buffer
            .get_mut(&digest.round())
            .and_then(|m| m.map.get_mut(&digest))
            .and_then(|t| t.message.item.as_ref())
        {
            let proto = Protocol::GetResponse(Cow::Borrowed(msg));
            let bytes = serialize(&proto)?;
            self.comm.unicast(src, bytes).await?;
            return Ok(());
        }

        warn!(node = %self.key, %src, "ignoring get request for data we do not have");

        Ok(())
    }

    /// We received a response to our get request.
    async fn on_get_response(&mut self, src: PublicKey, vertex: Envelope<Vertex<T>, Unchecked>) -> RbcResult<()> {
        debug!(node = %self.key, %src, digest = %Digest::of_vertex(&vertex), "get response received");
        let Some(vertex) = vertex.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let digest = Digest::of_vertex(&vertex);

        let Some(tracker) = self
            .buffer
            .get_mut(&digest.round())
            .and_then(|m| m.map.get_mut(&digest))
        else {
            debug!(node = %self.key, %src, "no tracker for get response");
            return Ok(());
        };

        if Status::Requested != tracker.status {
            debug!(node = %self.key, status = %tracker.status, %src, "ignoring get response");
            return Ok(());
        }

        self.tx
            .send(Message::Vertex(vertex.clone()))
            .await
            .map_err(|_| RbcError::Shutdown)?;

        debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
        tracker.message = Item::some(vertex);
        tracker.status = Status::Delivered;

        Ok(())
    }

    fn barrier(&self) -> Ordering {
        if let WorkerState::Barrier(r) = self.state {
            return r.cmp(&self.round.0)
        }
        Ordering::Greater
    }
}

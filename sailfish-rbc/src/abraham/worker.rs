use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fmt;

use bytes::Bytes;
use cliquenet::{
    AddressableCommittee, Overlay, Role,
    MAX_MESSAGE_SIZE,
    overlay::{self, Data, NetworkDown},
};
use committable::{Commitment, Committable};
use multisig::{Certificate, Envelope, PublicKey, VoteAccumulator};
use multisig::{Unchecked, Validated};
use sailfish_types::{Evidence, Message, Round, RoundNumber, Vertex};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::mpsc;
use tokio::time::{self, Duration, Instant, Interval};
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
    /// The latest round number this worker proposed.
    round: (RoundNumber, Evidence),
    /// Retry timer.
    timer: Interval,
}

enum WorkerState {
    /// The first run of this worker.
    ///
    /// No round number information is collected.
    Genesis,
    /// The worker did run previously and should collect round number information.
    ///
    /// While in this state, no messages will be sent to other parties,
    /// but inbound messages will be processed and delivered to the
    /// application as normal.
    ///
    /// Proposals, votes and certificates that would normally be sent are
    /// stored and once the round number barrier for participation has been
    /// reached, the deferred messages from that round number onwards will
    /// be sent out.
    Recover(Nonce, Option<cliquenet::Id>, HashMap<PublicKey, RoundNumber>),
    /// This is the normal running state after round numbers have been collected.
    /// The barrier is the maximum of at least 2t + 1 reported round numbers and
    /// restricts when messages are eligible for sending.
    Barrier(RoundNumber),
}

/// Messages of a single round.
struct Messages<T: Committable> {
    /// Did we receive > 2t messages pointing to the leader of the previous round?
    leader_threshold: bool,
    /// Tracking info per message proposal.
    map: BTreeMap<Digest, Tracker<Envelope<Vertex<T>, Validated>>>,
}

impl<T: Committable> Messages<T> {
    /// Get message digests of this source.
    fn digests(&self, s: &PublicKey) -> impl Iterator<Item = &Digest> {
        self.map.iter().filter_map(move |(d, t)| {
            let Some(vertex) = &t.message.item else {
                return None
            };
            (vertex.data().source() == s).then_some(d)
        })
    }
}

impl<T: Committable> Default for Messages<T> {
    fn default() -> Self {
        Self {
            leader_threshold: false,
            map: Default::default(),
        }
    }
}

/// Tracking information about a message and its status.
struct Tracker<T> {
    /// The time when this info was created.
    start: Instant,
    /// The time when this info was last updated.
    timestamp: Instant,
    /// The message (if any).
    ///
    /// If we receive votes before the message, this item will be empty.
    message: Item<T>,
    /// The votes for a message.
    votes: VoteAccumulator<Digest>,
    /// The message status.
    status: Status,
    /// The number of times we retried.
    retries: usize,
}

impl<T> Tracker<T> {
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
    /// The deferred proposals, votes or certificates (if any).
    defer: Deferred,
}

impl<T> Item<T> {
    fn none() -> Self {
        Self {
            item: None,
            defer: Deferred::default(),
        }
    }

    fn some(item: T) -> Self {
        Self {
            item: Some(item),
            defer: Deferred::default(),
        }
    }
}

#[derive(Default)]
struct Deferred {
    /// A deferred proposal.
    prop: Option<Data>,
    /// A deferred vote.
    vote: Option<Data>,
    /// A deferred certificate.
    cert: Option<Data>,
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
            comm: net,
            tx,
            rx,
            buffer: BTreeMap::new(),
            round: (RoundNumber::genesis(), Evidence::Genesis),
            state: if cfg.recover {
                WorkerState::Recover(Nonce::new(), None, HashMap::new())
            } else {
                WorkerState::Genesis
            },
            config: cfg,
            timer: {
                let mut i = time::interval(Duration::from_secs(1));
                i.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
                i
            },
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
                now = self.timer.tick() => {
                    match self.retry(now).await {
                        Ok(()) => {}
                        Err(RbcError::Shutdown) => {
                            debug!(node = %self.key, "rbc shutdown detected");
                            return;
                        }
                        Err(err) => {
                            warn!(node = %self.key, %err, "error retrying");
                        }
                    }
                },
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
                                if matches!(err, RbcError::Shutdown) {
                                    debug!(node = %self.key, "network went down");
                                    return
                                } else {
                                    warn!(node = %self.key, %err)
                                }
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
                                if matches!(err, RbcError::Shutdown) {
                                    debug!(node = %self.key, "network went down");
                                    return
                                } else {
                                    warn!(node = %self.key, %err)
                                }
                            }
                        }
                        Some(Command::Gc(round)) => {
                            debug!(node = %self.key, r = %round, "garbage collect");
                            self.comm.gc(*round);
                            self.buffer.retain(|r, _| *r >= round);
                        }
                        Some(Command::AddCommittee(c)) => {
                            if let Err(err) = self.add_committee(c).await {
                                if matches!(err, RbcError::Shutdown) {
                                    debug!(node = %self.key, "network went down");
                                    return
                                } else {
                                    warn!(node = %self.key, %err)
                                }
                            }
                        }
                        Some(Command::UseCommittee(r)) => {
                            if let Err(err) = self.use_committee(r).await {
                                if matches!(err, RbcError::Shutdown) {
                                    debug!(node = %self.key, "network went down");
                                    return
                                } else {
                                    warn!(node = %self.key, %err)
                                }
                            }
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

    /// Add a new committee.
    ///
    /// Peers that do not exist in the current committee are added to the network
    /// as passive nodes.
    async fn add_committee(&mut self, c: AddressableCommittee) -> RbcResult<()> {
        debug!(node = %self.key, committee = %c.committee().id(), "add committee");

        if self.config.committees.contains(c.committee().id()) {
            warn!(node = %self.key, committee = %c.committee().id(), "committee already added");
            return Ok(())
        }

        let Some(committee) = self.config.committees.get(self.config.committee_id) else {
            return Err(RbcError::NoCommittee(self.config.committee_id))
        };

        let mut additional = Vec::new();
        for (k, x, a) in c.entries().filter(|(k, ..)| !committee.contains_key(k)) {
            additional.push((k, x, a))
        }
        self.comm.add(additional).await?;

        self.config.committees.add(c.committee().clone());

        Ok(())
    }

    /// Switch over to use a committee that has previously been added.
    ///
    /// Peers that do not exist in the given committee are removed from the
    /// network and all committee peers are assigned an active role.
    async fn use_committee(&mut self, round: Round) -> RbcResult<()> {
        debug!(node = %self.key, %round, "use committee");
        let Some(committee) = self.config.committees.get(round.committee()) else {
            error!(node = %self.key, id = %round.committee(), "committee to use does not exist");
            return Err(RbcError::NoCommittee(round.committee()))
        };
        let old = self.comm
            .parties()
            .map(|(p, _)| p)
            .filter(|p| !committee.contains_key(p))
            .copied();
        self.comm.remove(old.collect()).await?;
        self.comm.assign(Role::Active, committee.parties().copied().collect()).await?;
        self.config.committee_id = round.committee();
        for (_, m) in self.buffer.range_mut(round.num() ..) {
            // Remove all messages from the old committee starting at round.
            m.map.retain(|d, _| d.round().committee() == round.committee())
        }
        Ok(())
    }

    /// Request round number information when recovering.
    async fn startup(&mut self) -> RbcResult<()> {
        if let WorkerState::Recover(nonce, id@None, _) = &mut self.state {
            let req = Protocol::<'_, T, Validated>::InfoRequest(*nonce);
            let bytes = serialize(&req)?;
            *id = Some(self.comm.broadcast(overlay::MAX_BUCKET, bytes).await?);
            debug!(node = %self.key, %nonce, "info request broadcasted");
        }
        Ok(())
    }

    /// Best effort broadcast.
    async fn broadcast(&mut self, msg: Message<T, Validated>, data: Data) -> RbcResult<()> {
        if self.barrier().is_gt() {
            debug!(node = %self.key, "suppressing message broadcast");
            return Ok(())
        }

        let digest = Digest::of_msg(&msg);
        let committee_id = msg.committee();

        // Messages not directed to the current committee will be multicasted.
        // This only affects handover messages and certificates which cross
        // committee boundaries.
        if committee_id != self.config.committee_id {
            let Some(committee) = self.config.committees.get(committee_id) else {
                return Err(RbcError::NoCommittee(committee_id))
            };
            let dest = committee.parties().copied().collect();
            self.comm.multicast(dest, *msg.round().num(), data).await?;
            debug!(node = %self.key, %digest, "message multicasted");
        } else {
            self.comm.broadcast(*msg.round().num(), data).await?;
            debug!(node = %self.key, %digest, "message broadcasted");
        }

        Ok(())
    }

    /// 1:1 communication.
    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>, data: Data) -> SendResult<()> {
        if self.barrier().is_gt() {
            debug!(node = %self.key, %msg, "suppressing direct send");
            return Ok(())
        }
        let digest = Digest::of_msg(&msg);
        self.comm.unicast(to, *msg.round().num(), data).await?;
        debug!(node = %self.key, %to, %digest, "direct send");

        Ok(())
    }

    /// Start RBC broadcast.
    async fn propose(&mut self, vertex: Envelope<Vertex<T>, Validated>, data: Data) -> RbcResult<()> {
        trace!(node = %self.key, vertex = %vertex.data(), "proposing");
        let digest = Digest::of_vertex(&vertex);

        debug_assert!(
            vertex.data().round().data().num() > self.round.0
                || vertex.data().evidence().is_handover()
                || self.round.0.is_genesis()
        );

        self.round = (vertex.data().round().data().num(), vertex.data().evidence().clone());

        let cid = vertex.data().round().data().committee();

        let Some(committee) = self.config.committees.get(cid) else {
            return Err(RbcError::NoCommittee(cid))
        };

        let now = Instant::now();
        let mut tracker = Tracker {
            start: now,
            timestamp: now,
            retries: 0,
            message: Item::some(vertex),
            votes: VoteAccumulator::new(committee.clone()),
            status: Status::Initiated,
        };

        let can_send = self.barrier().is_le();
        let messages = self.buffer.entry(digest.round().num()).or_default();

        if !can_send {
            tracker.message.defer.prop = Some(data);
            messages.map.insert(digest, tracker);
            debug!(node = %self.key, %digest, "suppressing proposal");
            return Ok(())
        }

        self.comm.broadcast(*digest.round().num(), data).await?;
        messages.map.insert(digest, tracker);

        debug!(node = %self.key, %digest, "proposal broadcasted");

        #[cfg(feature = "times")]
        times::record("rbc-proposed", *digest.round().num());

        Ok(())
    }

    /// We received a message from the network.
    async fn on_inbound(&mut self, src: PublicKey, bytes: Bytes) -> RbcResult<()> {
        trace!(node = %self.key, %src, buf = %self.buffer.len(), "inbound message");
        let conf = bincode::config::standard().with_limit::<MAX_MESSAGE_SIZE>();
        match bincode::serde::decode_from_slice(&bytes, conf)?.0 {
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

        if self.barrier().is_gt() {
            debug!(node = %self.key, %src, nonce = %n, "suppressed info response");
            return Ok(())
        }

        let (r, e) = &self.round;
        let proto = Protocol::<'_, T, Validated>::InfoResponse(n, *r, Cow::Borrowed(e));
        let bytes = serialize(&proto)?;
        self.comm.unicast(src, **r, bytes).await?;
        Ok(())
    }

    /// We receveived a response to our round number information request.
    async fn on_info_response(&mut self, src: PublicKey, n: Nonce, r: RoundNumber, e: Evidence) -> RbcResult<()> {
        debug!(node = %self.key, %src, nonce = %n, %r, "info response received");

        let WorkerState::Recover(nonce, id, rounds) = &mut self.state else {
            debug!(node = %self.key, %src, nonce = %n, %r, "round number info already complete");
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

        if !e.is_valid(r, &self.config.committees) {
            warn!(node = %self.key, %src, "invalid round evidence");
            return Err(RbcError::InvalidMessage);
        }

        rounds.insert(src, r);

        let Some(c) = self.config.committees.get(self.config.committee_id) else {
            return Err(RbcError::NoCommittee(self.config.committee_id))
        };

        if rounds.len() >= c.quorum_size().get() {
            let barrier = rounds
                .values()
                .max()
                .copied()
                .expect("|rounds| >= quorum > 0")
                .saturating_add(2)
                .into();

            if let Some(id) = id {
                self.comm.rm(overlay::MAX_BUCKET, *id);
            } else {
                error!(node = %self.key, "missing info request message id")
            }

            self.state = WorkerState::Barrier(barrier);

            debug!(node = %self.key, %barrier, "round number info collected");

            for (round, messages) in self.buffer.range_mut(barrier ..) {
                for (digest, tracker) in &mut messages.map {
                    match tracker.status {
                        // A quorum has been formed already => just send the certificate.
                        Status::Requested | Status::Delivered => {
                            if let Some(cert) = tracker.message.defer.cert.take() {
                                self.comm.broadcast(**round, cert).await?;
                                debug!(node = %self.key, %digest, "cert broadcasted");
                            }
                        }
                        // Send all deferred values.
                        Status::Initiated => {
                            if let Some(proposal) = tracker.message.defer.prop.take() {
                                self.comm.broadcast(**round, proposal).await?;
                                debug!(node = %self.key, %digest, "proposal broadcasted");
                            }
                            if let Some(vote) = tracker.message.defer.vote.take() {
                                self.comm.broadcast(**round, vote).await?;
                                debug!(node = %self.key, %digest, "vote broadcasted");
                            }
                            if let Some(cert) = tracker.message.defer.cert.take() {
                                self.comm.broadcast(**round, cert).await?;
                                debug!(node = %self.key, %digest, "cert broadcasted");
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
        let Some(msg) = msg.validated(&self.config.committees) else {
            return Err(RbcError::InvalidMessage);
        };
        self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    /// An RBC message proposal has been received.
    async fn on_propose(&mut self, src: PublicKey, vertex: Envelope<Vertex<T>, Unchecked>) -> RbcResult<()> {
        debug!(node = %self.key, %src, digest = %Digest::of_vertex(&vertex), "proposal received");

        let round = *vertex.data().round().data();

        #[cfg(feature = "times")]
        times::record("validate-msg-start", *round.num());

        let Some(Message::Vertex(vertex)) =
            Message::Vertex(vertex).validated(&self.config.committees) else {
                return Err(RbcError::InvalidMessage);
            };

        #[cfg(feature = "times")]
        times::record("validate-msg-end", *round.num());

        if *vertex.signing_key() != src {
            warn!(node = %self.key, %src, "message sender != message signer");
            return Err(RbcError::InvalidMessage);
        }

        let current_committee_pos =
            self.config.committees.position(self.config.committee_id)
                .expect("current committee is member of committee vec");

        let proposal_committee_pos =
            self.config.committees.position(round.committee())
                .expect("validated vertex committee is member of committee vec");

        if proposal_committee_pos > current_committee_pos {
            debug!(
                node   = %self.key,
                src    = %src,
                vertex = %vertex.data(),
                "rejecting proposal from older committee"
            );
            return Err(RbcError::InvalidMessage);
        }

        let digest = Digest::of_vertex(&vertex);

        if let Some(messages) = self.buffer.get(&digest.round().num()) {
            for d in messages.digests(&src).filter(|d| **d != digest) {
                let digest_committee_pos = self.config.committees.position(d.round().committee());
                if Some(proposal_committee_pos) >= digest_committee_pos {
                    warn!(node = %self.key, %src, old = %d, new = %digest, "multiple proposals received");
                    return Err(RbcError::InvalidMessage);
                }
                // The round number `r` to switch committees is based on the
                // *committed* rounds of parties. Therefore it may happen
                // that a node has already broadcasted their proposal for
                // `r` as a member of the old committee before broadcasting
                // again for `r` as a member of the new committee. Naturally,
                // the digests differ, so a receiving node who hasn't switched
                // to the next committee yet, would reject the second proposal,
                // but as a special case, we chose to accept it here if we have
                // proof that the proposal's committee is newer.
                warn!(
                    node = %self.key,
                    src  = %src,
                    old  = %d,
                    new  = %digest,
                    "accepting additional proposal from newer committee"
                );
            }
        }

        let can_send = self.barrier().is_le();
        let evidence = vertex.data().evidence().clone();
        let messages = self.buffer.entry(digest.round().num()).or_default();

        let Some(committee) = self.config.committees.get(round.committee()) else {
            return Err(RbcError::NoCommittee(round.committee()))
        };

        let tracker = messages.map.entry(digest).or_insert_with(|| {
            let now = Instant::now();
            Tracker {
                start: now,
                timestamp: now,
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(committee.clone()),
                status: Status::Initiated,
            }
        });

        match tracker.status {
            // If this is a new message or we received our own we vote for it.
            Status::Initiated => {
                if tracker.message.item.is_none() || src == self.key {
                    let env = Envelope::signed(digest, &self.config.keypair);
                    let vote = Protocol::<'_, T, Validated>::Vote(env, evidence);
                    let bytes = serialize(&vote)?;
                    if can_send {
                        self.comm.broadcast(*digest.round().num(), bytes).await?;
                        debug!(node = %self.key, %digest, "vote broadcasted");
                    } else {
                        tracker.message.defer.vote = Some(bytes);
                        debug!(node = %self.key, %digest, "suppressing vote");
                    }
                }
                if tracker.message.item.is_none() {
                    tracker.message = Item::some(vertex);
                }
            }
            // We had previously reached a quorum of votes but were missing the
            // message which now arrived independently. We can finally deliver
            // it to the application.
            Status::Requested => {
                debug_assert!(tracker.message.item.is_none());
                tracker.message = Item::some(vertex.clone());

                // Now that we have the message corresponding to the voter quorum we can
                // broadcast the certificate as well:
                let cert = tracker
                    .votes
                    .certificate()
                    .expect("requested message => certificate");
                let cert_digest = Digest::of_cert(cert);
                let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                let b = serialize(&m)?;

                if can_send {
                    self.comm.broadcast(*cert_digest.round().num(), b).await?;
                    debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                } else {
                    tracker.message.defer.cert = Some(b);
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
                #[cfg(feature = "times")]
                times::record_once("rbc-delivered", *vertex.data().round().data().num());
                debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
            }
            // Nothing to do here:
            Status::Delivered => {
                debug!(node = %self.key, %src, %digest, status = %tracker.status, "ignoring proposal");
                debug_assert!(tracker.message.item.is_some())
            }
        }

        if !messages.leader_threshold {
            let prev_round_leader = committee.leader(round.num().saturating_sub(1) as usize);
            if messages.map
                .values()
                .filter_map(|t| t.message.item.as_ref())
                .filter(|e| e.data().has_edge(&prev_round_leader))
                .count() > committee.quorum_size().get()
            {
                messages.leader_threshold = true
            }
        }

        Ok(())
    }

    /// A proposal vote has been received.
    async fn on_vote(&mut self, src: PublicKey, env: Envelope<Digest, Unchecked>, evi: Evidence) -> RbcResult<()> {
        debug!(node = %self.key, %src, digest = %env.data(), "vote received");

        let Some(committee) = self.config.committees.get(env.data().round().committee()) else {
            return Err(RbcError::NoCommittee(env.data().round().committee()))
        };

        let Some(env) = env.validated(committee) else {
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

        if digest.round().num() > latest_round + 1 && !evi.is_valid(digest.round().num(), &self.config.committees) {
            warn!(node = %self.key, %src, "invalid vote evidence");
            return Err(RbcError::InvalidMessage);
        }

        let can_send = self.barrier().is_le();
        let messages = self.buffer.entry(digest.round().num()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| {
            let now = Instant::now();
            Tracker {
                start: now,
                timestamp: now,
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(committee.clone()),
                status: Status::Initiated,
            }
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
                        let cert_digest = Digest::of_cert(cert);
                        let m = Protocol::<'_, T, Validated>::Cert(cert.clone());
                        let b = serialize(&m)?;
                        if can_send {
                            self.comm.broadcast(*cert_digest.round().num(), b).await?;
                            debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                        } else {
                            tracker.message.defer.cert = Some(b);
                            debug!(node = %self.key, %digest, "suppressing cert");
                        }
                        self.tx
                            .send(Message::Vertex(vertex.clone()))
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        self.config
                            .metrics
                            .add_delivery_duration(tracker.start.elapsed());
                        debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
                        #[cfg(feature = "times")]
                        times::record_once("rbc-delivered", *vertex.data().round().data().num());
                        tracker.status = Status::Delivered
                    } else {
                        let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                        let b = serialize(&m)?;
                        let s = tracker.choose_voter(&commit).expect("certificate => voter");
                        self.comm.unicast(s, *digest.round().num(), b).await?;
                        tracker.status = Status::Requested;
                        tracker.timestamp = Instant::now();
                        debug!(node = %self.key, from = %s, %digest, "message requested")
                    }
                }
                Ok(None) => {
                    // quorum not reached yet => nothing else to do
                }
                Err(err) => {
                    warn!(node = %self.key, %err, %digest, "failed to add vote");
                    if tracker.votes.is_empty() && tracker.message.item.is_none() {
                        if let Some(messages) = self.buffer.get_mut(&digest.round().num()) {
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
            if digest.round().num() < *r {
                return Ok(());
            }
        }

        let Some(committee) = self.config.committees.get(crt.data().round().committee()) else {
            return Err(RbcError::NoCommittee(crt.data().round().committee()))
        };

        if !crt.is_valid_par(committee) {
            return Err(RbcError::InvalidMessage);
        }

        let commit = digest.commit();
        let can_send = self.barrier().is_le();
        let messages = self.buffer.entry(digest.round().num()).or_default();
        let tracker = messages.map.entry(digest).or_insert_with(|| {
            let now = Instant::now();
            Tracker {
                start: now,
                timestamp: now,
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(committee.clone()),
                status: Status::Initiated,
            }
        });

        match tracker.status {
            // The certificate allows us to immediately reach the quorum and deliver the
            // message to the application layer. If we are missing the message, we have to
            // ask one of our peers for it.
            Status::Initiated => {
                tracker.votes.set_certificate(crt.clone());
                if let Some(vertex) = &tracker.message.item {
                    let m = Protocol::<'_, T, Validated>::Cert(crt);
                    let b = serialize(&m)?;
                    if can_send {
                        self.comm.broadcast(*digest.round().num(), b).await?;
                        debug!(node = %self.key, %digest, cert = %cert_digest, "cert broadcasted");
                    } else {
                        tracker.message.defer.cert = Some(b);
                        debug!(node = %self.key, %digest, "suppressing cert");
                    }
                    self.tx
                        .send(Message::Vertex(vertex.clone()))
                        .await
                        .map_err(|_| RbcError::Shutdown)?;
                    self.config
                        .metrics
                        .add_delivery_duration(tracker.start.elapsed());
                    debug!(node = %self.key, vertex = %vertex.data(), %digest, "delivered");
                    #[cfg(feature = "times")]
                    times::record_once("rbc-delivered", *vertex.data().round().data().num());
                    tracker.status = Status::Delivered
                } else {
                    let m = Protocol::<'_, T, Validated>::GetRequest(digest);
                    let b = serialize(&m)?;
                    let s = tracker.choose_voter(&commit).expect("certificate => voter");
                    self.comm.unicast(s, *digest.round().num(), b).await?;
                    tracker.status = Status::Requested;
                    tracker.timestamp = Instant::now();
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
            .get_mut(&digest.round().num())
            .and_then(|m| m.map.get_mut(&digest))
            .and_then(|t| t.message.item.as_ref())
        {
            let proto = Protocol::GetResponse(Cow::Borrowed(msg));
            let bytes = serialize(&proto)?;
            self.comm.unicast(src, *digest.round().num(), bytes).await?;
            return Ok(());
        }

        warn!(node = %self.key, %src, %digest, "ignoring get request for data we do not have");

        Ok(())
    }

    /// We received a response to our get request.
    async fn on_get_response(&mut self, src: PublicKey, vertex: Envelope<Vertex<T>, Unchecked>) -> RbcResult<()> {
        debug!(node = %self.key, %src, digest = %Digest::of_vertex(&vertex), "get response received");

        let round = vertex.data().round().data();

        let Some(committee) = self.config.committees.get(round.committee()) else {
            return Err(RbcError::NoCommittee(round.committee()))
        };

        let Some(vertex) = vertex.validated(committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let digest = Digest::of_vertex(&vertex);

        let Some(tracker) = self
            .buffer
            .get_mut(&digest.round().num())
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

        #[cfg(feature = "times")]
        times::record_once("rbc-delivered", *vertex.data().round().data().num());

        tracker.message = Item::some(vertex);
        tracker.status = Status::Delivered;

        Ok(())
    }

    /// Periodically we go over message status and retry incomplete items.
    async fn retry(&mut self, now: Instant) -> RbcResult<()> {
        trace!(node = %self.key, "retrying ...");
        for (digest, tracker) in self.buffer.values_mut().flat_map(|m| m.map.iter_mut()) {
            if tracker.status == Status::Requested {
                debug!(
                    node     = %self.key,
                    digest   = %digest,
                    elapsed  = ?tracker.start.elapsed(),
                    retries  = %tracker.retries,
                    "revisiting ..."
                );
                let timeout = [1, 3, 6, 10, 15].get(tracker.retries).copied().unwrap_or(30);
                if tracker.timestamp.elapsed() < Duration::from_secs(timeout) {
                    continue;
                }
                debug!(node = %self.key, %digest, "requesting message again");
                let m = Protocol::<'_, T, Validated>::GetRequest(*digest);
                let b = serialize(&m)?;
                let c = digest.commit();
                let s = tracker.choose_voter(&c).expect("status = requested => voter");
                self.comm.unicast(s, *digest.round().num(), b).await?;
                tracker.timestamp = now;
                tracker.retries = tracker.retries.saturating_add(1);
                debug!(node = %self.key, from = %s, %digest, "message requested");
            }
        }
        Ok(())
    }

    fn barrier(&self) -> Ordering {
        match self.state {
            WorkerState::Genesis => Ordering::Less,
            WorkerState::Recover(..) => Ordering::Greater,
            WorkerState::Barrier(rn) => rn.cmp(&self.round.0)
        }
    }
}

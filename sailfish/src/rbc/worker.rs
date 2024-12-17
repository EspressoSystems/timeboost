use std::borrow::Cow;
use std::cmp::max;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use committable::{Commitment, Committable};
use multisig::{Certificate, Envelope, PublicKey, VoteAccumulator};
use multisig::{Unchecked, Validated};
use timeboost_core::traits::comm::RawComm;
use timeboost_core::types::message::Message;
use timeboost_utils::types::round_number::RoundNumber;
use tokio::sync::mpsc;
use tokio::time::{self, Instant, Interval};
use tracing::{debug, error, instrument, warn};

use super::{Command, Config, Digest, Protocol};

type Result<T> = std::result::Result<T, RbcError>;
type Sender = mpsc::Sender<Message<Validated>>;
type Receiver = mpsc::Receiver<Command>;

/// A worker is run by `Rbc` to perform the actual work of sending and
/// delivering messages.
pub struct Worker<C> {
    /// RBC configuration.
    config: Config,
    /// Label, used in debug logs.
    label: PublicKey,
    /// Underlying communication type.
    comm: C,
    /// Our channel to deliver messages to the application layer.
    tx: Sender,
    /// Our channel to receive messages from the application layer.
    rx: Receiver,
    /// The highest round number of the application (used for pruning).
    round: RoundNumber,
    /// The tracking information per message.
    buffer: BTreeMap<RoundNumber, Messages>,
    /// A timer to retry messages.
    timer: Interval,
}

/// Tracking information about a message and its status.
struct Tracker {
    /// Are we the original producer of this message?
    ours: bool,
    /// The time when this info was created or last updated.
    start: Instant,
    /// The number of delivery retries.
    retries: usize,
    /// The message, if any.
    ///
    /// If we receive votes before the message, this will be `None`.
    message: Item<Message<Validated>>,
    /// The votes for a message.
    votes: VoteAccumulator<Digest>,
    /// The message status.
    status: Status,
}

impl Tracker {
    /// Randomly select a voter of the given commitment.
    fn choose_voter(&self, d: &Commitment<Digest>) -> Option<PublicKey> {
        use rand::seq::IteratorRandom;
        self.votes
            .voters(d)
            .choose(&mut rand::thread_rng())
            .copied()
    }
}

/// Messages of a single round.
#[derive(Default)]
struct Messages {
    /// Did we deliver the messages early?
    ///
    /// Early delivery means that as soon as we receive 2f + 1 messages in a
    /// round, we deliver the messages. Afterwards this flag is set to true
    /// to avoid repeated calculations. The rationale behind this is that with
    /// 2f + 1 messages we know that at least f + 1 messages will eventually
    /// be delivered.
    early: bool,
    /// Tracking info per message.
    map: BTreeMap<Digest, Tracker>,
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

impl<C: RawComm> Worker<C> {
    pub fn new(tx: Sender, rx: Receiver, cfg: Config, nt: C) -> Self {
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

    /// The main event loop of this worker.
    ///
    /// We either receive messages from the application to send or from the network
    /// to deliver. Periodically we also revisit our message buffer and try to make
    /// progress.
    pub async fn go(mut self) {
        loop {
            tokio::select! {
                now = self.timer.tick() => {
                    if let Err(e) = self.retry(now).await {
                        warn!(n = %self.label, %e, "error retrying");
                    }
                },
                val = self.comm.receive() => {
                    match val {
                        Ok(bytes) => {
                            if let Err(e) = self.on_inbound(bytes).await {
                                warn!(n = %self.label, %e, "error on inbound message");
                            }
                        }
                        Err(e) => warn!(n = %self.label, %e, "error receiving message from network")
                    }
                },
                cmd = self.rx.recv() => match cmd {
                    Some(Command::RbcBroadcast(msg, tx)) => {
                        match self.on_outbound(msg).await {
                            Ok(()) => {
                                let _ = tx.send(Ok(()));
                            }
                            Err(RbcError::Shutdown) => {
                                warn!(n = %self.label, "unexpected shutdown detected");
                                let _ = self.comm.shutdown().await;
                                return
                            }
                            Err(e) => {
                                warn!(n = %self.label, %e, "error rbc broadcasting message");
                                let _ = tx.send(Err(e));
                            }
                        }
                    }
                    // Best-effort sending to a peer without RBC properties.
                    Some(Command::Send(to, msg)) => {
                        match self.on_send(to, &msg).await {
                            Ok(()) => {}
                            Err(e) => warn!(n = %self.label, %e, "error sending message")
                        }
                    }
                    // Best-effort broadcast without RBC properties.
                    Some(Command::Broadcast(msg)) => {
                        match self.on_broadcast(&msg).await {
                            Ok(()) => {}
                            Err(e) => warn!(n = %self.label, %e, "error broadcasting message")
                        }
                    }
                    // Terminate operation.
                    Some(Command::Shutdown(reply)) => {
                        tracing::error!("shutdown comm");
                        let _ = self.comm.shutdown().await;
                        tracing::error!("send reply");
                        let _ = reply.send(());
                        tracing::error!("sent reply");
                        return
                    }
                    None => {
                        return
                    }
                }
            }
        }
    }

    /// Best effort broadcast.
    #[instrument(level = "trace", skip_all, fields(n = %self.label, m = %msg))]
    async fn on_broadcast(&mut self, msg: &Message<Validated>) -> Result<()> {
        let proto = Protocol::Bypass(Cow::Borrowed(msg));
        let bytes = bincode::serialize(&proto)?;
        self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
        Ok(())
    }

    /// 1:1 communication.
    #[instrument(level = "trace", skip_all, fields(n = %self.label, m = %msg))]
    async fn on_send(&mut self, to: PublicKey, msg: &Message<Validated>) -> Result<()> {
        send(&mut self.comm, to, msg).await
    }

    /// Start RBC broadcast.
    #[instrument(level = "trace", skip_all, fields(n = %self.label, m = %msg))]
    async fn on_outbound(&mut self, msg: Message<Validated>) -> Result<()> {
        let proto = Protocol::Propose(Cow::Borrowed(&msg));
        let bytes = bincode::serialize(&proto)?;
        let digest = Digest::new(&msg);

        // We track the max. round number to know when it is safe to remove
        // old messages from our buffer.
        self.round = max(self.round, msg.round());

        // Remove buffer entries that are too old to be relevant.
        self.buffer.retain(|r, _| {
            let n = self.config.committee.size().get() as u64;
            let t = self.config.committee.threshold().get() as u64;
            *r + n + t >= self.round
        });

        let tracker = Tracker {
            ours: true,
            start: Instant::now(),
            retries: 0,
            message: Item::some(msg),
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
            debug!(n = %self.label, %e, "network error");
        } else {
            debug!(n = %self.label, d = %digest, "message broadcast");
            tracker.status = Status::SentMsg;
        }

        Ok(())
    }

    /// We received a message from the network.
    #[instrument(level = "trace", skip_all, fields(n = %self.label))]
    async fn on_inbound(&mut self, bytes: Vec<u8>) -> Result<()> {
        match bincode::deserialize(&bytes)? {
            Protocol::Bypass(msg) => self.on_bypass(msg.into_owned()).await?,
            Protocol::Propose(msg) => self.on_propose(msg.into_owned()).await?,
            Protocol::Vote(env, done) => self.on_vote(env, done).await?,
            Protocol::Get(env) => self.on_get(env).await?,
            Protocol::Cert(crt) => self.on_cert(crt).await?,
        }
        Ok(())
    }

    /// A non-RBC message has been received which we deliver directly to the application.
    #[instrument(level = "trace", skip_all, fields(n = %self.label, m = %msg))]
    async fn on_bypass(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };
        self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    /// An RBC message proposal has been received.
    #[instrument(level = "trace", skip_all, fields(n = %self.label, m = %msg))]
    async fn on_propose(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let digest = Digest::new(&msg);

        let messages = self.buffer.entry(digest.round()).or_default();

        let tracker = messages.map.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            retries: 0,
            message: Item::none(),
            votes: VoteAccumulator::new(self.config.committee.clone()),
            status: Status::Init,
        });

        debug!(n = %self.label, d = %digest, s = %tracker.status, "proposal received");

        match tracker.status {
            // First time we see this message.
            Status::Init => {
                tracker.message = Item::some(msg);
                tracker.status = Status::ReceivedMsg;
                let env = Envelope::signed(digest, &self.config.keypair, false);
                let vote = Protocol::Vote(env, false);
                let bytes = bincode::serialize(&vote)?;
                self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                tracker.status = Status::SentVote
            }
            // We received a duplicate or a reflection of our own outbound message.
            // In any case we did not manage to cast our vote yet, so we try again.
            Status::ReceivedMsg | Status::SentMsg => {
                debug_assert!(tracker.message.item.is_some());
                let env = Envelope::signed(digest, &self.config.keypair, false);
                let vote = Protocol::Vote(env, false);
                let bytes = bincode::serialize(&vote)?;
                self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                tracker.status = Status::SentVote
            }
            // We received votes, possibly prior to the message. If so we update the
            // tracking info with the actual message proposal and vote on the message.
            Status::ReceivedVotes => {
                if tracker.message.item.is_none() {
                    tracker.message = Item::some(msg);
                    let env = Envelope::signed(digest, &self.config.keypair, false);
                    let vote = Protocol::Vote(env, false);
                    let bytes = bincode::serialize(&vote)?;
                    self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                    tracker.status = Status::SentVote
                }
            }
            // We had previously reached a quorum of votes but were missing the message
            // which now arrived (after we requested it). We can finally deliver it to
            // the application.
            Status::RequestedMsg => {
                tracker.message = Item::some(msg.clone());
                debug!(n = %self.label, m = %msg, d = %digest, "delivered");
                self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
                tracker.status = Status::Delivered
            }
            // These states already have the message, so there is nothing to be done.
            Status::Delivered | Status::SentVote | Status::ReachedQuorum => {
                debug!(n = %self.label, d = %digest, s = %tracker.status, "ignoring message proposal");
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
                    if let Some(msg) = &tracker.message.item {
                        self.tx
                            .send(msg.clone())
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        tracker.message.early = true;
                        debug!(n = %self.label, m = %msg, d = %digest, "delivered");
                    }
                }
                messages.early = true
            }
        }

        Ok(())
    }

    /// A proposal vote has been received.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.label,
        s = %env.signing_key(),
        r = %env.data().round())
    )]
    async fn on_vote(&mut self, env: Envelope<Digest, Unchecked>, done: bool) -> Result<()> {
        let Some(env) = env.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let digest = *env.data();
        let commit = digest.commit();
        let source = *env.signing_key();

        let tracker = self
            .buffer
            .entry(digest.round())
            .or_default()
            .map
            .entry(digest)
            .or_insert_with(|| Tracker {
                ours: false,
                start: Instant::now(),
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(self.config.committee.clone()),
                status: Status::Init,
            });

        debug!(
            n = %self.label,
            d = %digest,
            s = %tracker.status,
            v = %tracker.votes.votes(&commit),
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
                    if let Some(msg) = &tracker.message.item {
                        let e = Envelope::signed(cert.clone(), &self.config.keypair, false);
                        let m = Protocol::Cert(e);
                        let b = bincode::serialize(&m)?;
                        self.comm.broadcast(b).await.map_err(RbcError::net)?;
                        if !tracker.message.early {
                            self.tx
                                .send(msg.clone())
                                .await
                                .map_err(|_| RbcError::Shutdown)?;
                            debug!(n = %self.label, m = %msg, d = %digest, "delivered");
                        }
                        tracker.status = Status::Delivered
                    } else {
                        let e = Envelope::signed(digest, &self.config.keypair, false);
                        let m = Protocol::Get(e);
                        let b = bincode::serialize(&m)?;
                        let s = tracker.choose_voter(&commit).expect("certificate => voter");
                        self.comm.send(s, b).await.map_err(RbcError::net)?;
                        tracker.status = Status::RequestedMsg;
                    }
                }
                Err(e) => {
                    warn!(n = %self.label, %e, d = %digest, "failed to add vote");
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
                let m = Protocol::Get(Envelope::signed(digest, &self.config.keypair, false));
                let b = bincode::serialize(&m)?;
                let s = tracker.choose_voter(&commit).expect("quorum => voter");
                self.comm.send(s, b).await.map_err(RbcError::net)?;
                tracker.status = Status::RequestedMsg;
            }
            Status::ReachedQuorum | Status::RequestedMsg | Status::Delivered => {
                if done {
                    debug!(n = %self.label, s = %tracker.status, "ignoring vote")
                } else {
                    debug!(
                        n = %self.label,
                        d = %digest,
                        s = %tracker.status,
                        "replying with our vote to sender"
                    );
                    let env = Envelope::signed(digest, &self.config.keypair, false);
                    let vote = Protocol::Vote(env, true);
                    let bytes = bincode::serialize(&vote)?;
                    self.comm.send(source, bytes).await.map_err(RbcError::net)?;
                }
            }
        }

        Ok(())
    }

    /// We received a vote certificate.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.label,
        s = %env.signing_key(),
        r = %env.data().data().round())
    )]
    async fn on_cert(&mut self, env: Envelope<Certificate<Digest>, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        if !env.data().is_valid_par(&self.config.committee) {
            return Err(RbcError::InvalidMessage);
        }

        let digest = *env.data().data();
        let commit = digest.commit();

        let tracker = self
            .buffer
            .entry(digest.round())
            .or_default()
            .map
            .entry(digest)
            .or_insert_with(|| Tracker {
                ours: false,
                start: Instant::now(),
                retries: 0,
                message: Item::none(),
                votes: VoteAccumulator::new(self.config.committee.clone()),
                status: Status::Init,
            });

        debug!(n = %self.label, d = %digest, s = %tracker.status, "certificate received");

        match tracker.status {
            // The certificate allows us to immediately reach the quorum and deliver the
            // message to the application layer. If we are missing the message, we have to
            // ask one of our peers for it.
            Status::Init
            | Status::ReceivedMsg
            | Status::SentMsg
            | Status::ReceivedVotes
            | Status::SentVote => {
                tracker.votes.set_certificate(env.data().clone());
                tracker.status = Status::ReachedQuorum;

                if let Some(msg) = &tracker.message.item {
                    let e = Envelope::signed(env.into_data(), &self.config.keypair, false);
                    let m = Protocol::Cert(e);
                    let b = bincode::serialize(&m)?;
                    self.comm.broadcast(b).await.map_err(RbcError::net)?;
                    if !tracker.message.early {
                        self.tx
                            .send(msg.clone())
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        debug!(n = %self.label, m = %msg, d = %digest, "delivered");
                    }
                    tracker.status = Status::Delivered
                } else {
                    let m = Protocol::Get(Envelope::signed(digest, &self.config.keypair, false));
                    let b = bincode::serialize(&m)?;
                    let s = tracker.choose_voter(&commit).expect("certificate => voter");
                    self.comm.send(s, b).await.map_err(RbcError::net)?;
                    tracker.status = Status::RequestedMsg;
                }
            }
            // We have previously reached the quorum of votes but did not manage to request
            // the still missing message. Let's try again.
            Status::ReachedQuorum if tracker.message.item.is_none() => {
                let e = Envelope::signed(digest, &self.config.keypair, false);
                let m = Protocol::Get(e);
                let b = bincode::serialize(&m)?;
                let s = tracker.choose_voter(&commit).expect("quorum => voter");
                self.comm.send(s, b).await.map_err(RbcError::net)?;
                tracker.status = Status::RequestedMsg;
            }
            Status::ReachedQuorum | Status::RequestedMsg | Status::Delivered => {
                debug!(n = %self.label, s = %tracker.status, "ignoring certificate")
            }
        }

        Ok(())
    }

    /// One of our peers is asking for a message proposal.
    #[instrument(level = "trace", skip_all, fields(
        n = %self.label,
        s = %env.signing_key(),
        r = %env.data().round())
    )]
    async fn on_get(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.config.committee) else {
            return Err(RbcError::InvalidMessage);
        };

        let Some(tracker) = self
            .buffer
            .get_mut(&env.data().round())
            .and_then(|m| m.map.get_mut(env.data()))
        else {
            warn!(
                n = %self.label,
                f = %env.signing_key(),
                "ignoring get request for data we do not have"
            );
            return Ok(());
        };

        debug!(n = %self.label, d = %env.data(), s = %tracker.status, "get request received");

        match tracker.status {
            // We do not have the message ourselves when in these states.
            Status::Init | Status::RequestedMsg => {
                debug!(n = %self.label, d = %env.data(), s = %tracker.status, "ignoring get request");
                debug_assert!(tracker.message.item.is_none())
            }
            // Here, we may have the message and if so, we gladly share it.
            Status::SentVote | Status::ReceivedVotes | Status::ReachedQuorum => {
                if let Some(msg) = &tracker.message.item {
                    send(&mut self.comm, *env.signing_key(), msg).await?;
                }
            }
            // In these states we must have the message and send to the peer.
            Status::ReceivedMsg | Status::SentMsg | Status::Delivered => {
                let msg = tracker
                    .message
                    .item
                    .as_ref()
                    .expect("message item is present in these status");
                send(&mut self.comm, *env.signing_key(), msg).await?;
            }
        }

        Ok(())
    }

    /// Periodically we go over message status and retry incomplete items.
    #[instrument(level = "trace", skip_all, fields(n = %self.label))]
    async fn retry(&mut self, now: Instant) -> Result<()> {
        for (digest, tracker) in self.buffer.values_mut().flat_map(|m| m.map.iter_mut()) {
            debug!(n = %self.label, d = %digest, s = %tracker.status, r = %tracker.retries, "revisiting");
            match tracker.status {
                Status::Init | Status::Delivered => {}
                // We have sent a message but did not make further progress, so
                // we try to send the message again and hope for some response.
                Status::SentMsg => {
                    let timeout = [3, 6, 10, 15, 30]
                        .get(tracker.retries)
                        .copied()
                        .unwrap_or(30);
                    if tracker.start.elapsed() < Duration::from_secs(timeout) {
                        continue;
                    }
                    let messg = tracker
                        .message
                        .item
                        .as_ref()
                        .expect("message was sent => set in tracker");
                    debug!(n = %self.label, d = %digest, m = %messg, "re-broadcasting message");
                    let proto = Protocol::Propose(Cow::Borrowed(messg));
                    let bytes = bincode::serialize(&proto).expect("idempotent serialization");
                    tracker.start = now;
                    tracker.retries = tracker.retries.saturating_add(1);
                    if let Err(e) = self.comm.broadcast(bytes).await {
                        debug!(n = %self.label, %e, "network error");
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
                        if tracker.start.elapsed() < Duration::from_millis(timeout) {
                            continue;
                        }
                        if tracker.ours {
                            debug!(n = %self.label, d = %digest, "sending our message (again)");
                            let proto = Protocol::Propose(Cow::Borrowed(msg));
                            let bytes = bincode::serialize(&proto)?;
                            self.comm.broadcast(bytes).await.map_err(RbcError::net)?
                        }
                        debug!(n = %self.label, d = %digest, "sending our vote (again)");
                        let env = Envelope::signed(*digest, &self.config.keypair, false);
                        let vote = Protocol::Vote(env, false);
                        let bytes = bincode::serialize(&vote).expect("idempotent serialization");
                        tracker.start = now;
                        tracker.retries = tracker.retries.saturating_add(1);
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
                    if tracker.start.elapsed() < Duration::from_millis(timeout) {
                        continue;
                    }
                    debug!(n = %self.label, d = %digest, "requesting message again");
                    let m = Protocol::Get(Envelope::signed(*digest, &self.config.keypair, false));
                    let b = bincode::serialize(&m).expect("idempotent serialization");
                    let c = digest.commit();
                    let s = tracker.choose_voter(&c).expect("req-msg => voter");
                    tracker.start = now;
                    tracker.retries = tracker.retries.saturating_add(1);
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
                    if tracker.start.elapsed() < Duration::from_millis(timeout) {
                        continue;
                    }
                    if let Some(msg) = &tracker.message.item {
                        let c = tracker
                            .votes
                            .certificate()
                            .expect("reached quorum => certificate");
                        debug!(n = %self.label, d = %digest, m = %msg, "sending certificate");
                        let e = Envelope::signed(c.clone(), &self.config.keypair, false);
                        let m = Protocol::Cert(e);
                        let b = bincode::serialize(&m).expect("idempotent serialization");
                        tracker.start = now;
                        tracker.retries = tracker.retries.saturating_add(1);
                        self.comm.broadcast(b).await.map_err(RbcError::net)?;
                        if !tracker.message.early {
                            self.tx
                                .send(msg.clone())
                                .await
                                .map_err(|_| RbcError::Shutdown)?;
                            debug!(n = %self.label, m = %msg, d = %digest, "delivered");
                        }
                        tracker.status = Status::Delivered
                    } else {
                        debug!(n = %self.label, d = %digest, "requesting message");
                        let e = Envelope::signed(*digest, &self.config.keypair, false);
                        let m = Protocol::Get(e);
                        let b = bincode::serialize(&m).expect("idempotent serialization");
                        let c = digest.commit();
                        let s = tracker.choose_voter(&c).expect("quorum => voter");
                        tracker.start = now;
                        tracker.retries = tracker.retries.saturating_add(1);
                        self.comm.send(s, b).await.map_err(RbcError::net)?;
                        tracker.status = Status::RequestedMsg;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Factored out of `Worker` to help with borrowing.
async fn send<C: RawComm>(net: &mut C, to: PublicKey, msg: &Message<Validated>) -> Result<()> {
    let proto = Protocol::Bypass(Cow::Borrowed(msg));
    let bytes = bincode::serialize(&proto)?;
    net.send(to, bytes).await.map_err(RbcError::net)?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RbcError {
    #[error("network error: {0}")]
    Net(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("bincode error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("invalid message")]
    InvalidMessage,

    #[error("rbc has shut down")]
    Shutdown,
}

impl RbcError {
    fn net<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Net(Box::new(e))
    }
}

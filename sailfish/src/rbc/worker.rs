use std::borrow::Cow;
use std::cmp::max;
use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use rand::seq::IteratorRandom;
use timeboost_core::traits::comm::RawComm;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::{Envelope, Unchecked, Validated};
use timeboost_core::types::message::Message;
use timeboost_core::types::{Keypair, Label, PublicKey};
use timeboost_utils::types::round_number::RoundNumber;
use tokio::sync::mpsc;
use tokio::time::{self, Instant, Interval};
use tracing::{debug, error, instrument, warn};

use super::{Command, Digest, Protocol};
use crate::consensus::VoteAccumulator;

type Result<T> = std::result::Result<T, RbcError>;
type Sender = mpsc::Sender<Message<Validated>>;
type Receiver = mpsc::Receiver<Command>;

/// The number of old rounds for which to keep data in our buffer.
const BUFFER_HISTORY_LEN: u64 = 8;

/// A worker is run by `Rbc` to perform the actual work of sending and
/// delivering messages.
pub struct Worker<C> {
    /// The keypair we use for signing some of our protocol messages.
    keypair: Keypair,
    /// Label, used in debug logs.
    label: Label,
    /// Underlying communication type.
    comm: C,
    /// Our channel to deliver messages to the application layer.
    tx: Sender,
    /// Our channel to receive messages from the application layer.
    rx: Receiver,
    /// The highest round number of the application (used for pruning).
    round: RoundNumber,
    /// The set of voters.
    committee: StaticCommittee,
    /// The tracking information per message.
    buffer: HashMap<Digest, Tracker>,
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
    /// If we receive votes before the message, this will be `None`.
    message: Option<Message<Validated>>,
    /// The votes for a message.
    votes: VoteAccumulator<Digest>,
    /// The message status.
    status: Status,
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
    /// before we received the message itself, we asked a peer (denoted by the
    /// public key) for it.
    RequestedMsg(PublicKey),
    /// We have received one or more votes.
    ReceivedVotes,
    /// A quorum of votes has been reached.
    ///
    /// The public key denotes the sender of the last vote that made us
    /// reach the quorum. This is potentially used when retrying.
    ReachedQuorum(PublicKey),
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
            Self::ReachedQuorum(_) => f.write_str("quorum"),
            Self::RequestedMsg(_) => f.write_str("req-msg"),
            Self::Delivered => f.write_str("delivered"),
        }
    }
}

impl<C: RawComm> Worker<C> {
    pub fn new(tx: Sender, rx: Receiver, kp: Keypair, nt: C, sc: StaticCommittee) -> Self {
        Self {
            label: Label::new(kp.public_key()),
            keypair: kp,
            comm: nt,
            tx,
            rx,
            round: RoundNumber::genesis(),
            committee: sc,
            buffer: HashMap::new(),
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
            tokio::select! { biased;
                now = self.timer.tick() => {
                    if let Err(err) = self.retry(now).await {
                        warn!(%err, "error retrying");
                    }
                },
                val = self.comm.receive() => {
                    match val {
                        Ok(bytes) => {
                            if let Err(err) = self.on_inbound(bytes).await {
                                warn!(%err, "error on inbound message");
                            }
                        }
                        Err(err) => warn!(%err, "error receiving message from network")
                    }
                },
                cmd = self.rx.recv() => match cmd {
                    Some(Command::RbcBroadcast(msg, tx)) => {
                        match self.on_outbound(msg).await {
                            Ok(()) => {
                                let _ = tx.send(Ok(()));
                            }
                            Err(RbcError::Shutdown) => {
                                warn!("unexpected shutdown detected");
                                let _ = self.comm.shutdown().await;
                                return
                            }
                            Err(err) => {
                                warn!(%err, "error rbc broadcasting message");
                                let _ = tx.send(Err(err));
                            }
                        }
                    }
                    // Best-effort sending to a peer without RBC properties.
                    Some(Command::Send(to, msg)) => {
                        match self.on_send(to, &msg).await {
                            Ok(()) => {}
                            Err(err) => warn!(%err, "error sending message")
                        }
                    }
                    // Best-effort broadcast without RBC properties.
                    Some(Command::Broadcast(msg)) => {
                        match self.on_broadcast(&msg).await {
                            Ok(()) => {}
                            Err(err) => warn!(%err, "error broadcasting message")
                        }
                    }
                    // Terminate operation.
                    Some(Command::Shutdown(reply)) => {
                        let _ = self.comm.shutdown().await;
                        let _ = reply.send(());
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
    #[instrument(level = "trace", skip_all, fields(node = %self.label, %msg))]
    async fn on_broadcast(&mut self, msg: &Message<Validated>) -> Result<()> {
        let proto = Protocol::Bypass(Cow::Borrowed(msg));
        let bytes = bincode::serialize(&proto)?;
        self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
        Ok(())
    }

    /// 1:1 communication.
    #[instrument(level = "trace", skip_all, fields(node = %self.label, %msg))]
    async fn on_send(&mut self, to: PublicKey, msg: &Message<Validated>) -> Result<()> {
        send(&mut self.comm, to, msg).await
    }

    /// Start RBC broadcast.
    #[instrument(level = "trace", skip_all, fields(node = %self.label, %msg))]
    async fn on_outbound(&mut self, msg: Message<Validated>) -> Result<()> {
        let proto = Protocol::Propose(Cow::Borrowed(&msg));
        let bytes = bincode::serialize(&proto)?;
        let digest = Digest::new(&msg);

        // We track the max. round number to know when it is safe to remove
        // old messages from our buffer.
        self.round = max(self.round, msg.round());

        // Remove buffer entries that are too old to be relevant.
        self.buffer
            .retain(|k, _| *k.round() + BUFFER_HISTORY_LEN >= *self.round);

        let tracker = Tracker {
            ours: true,
            start: Instant::now(),
            retries: 0,
            message: Some(msg),
            votes: VoteAccumulator::new(self.committee.clone()),
            status: Status::Init,
        };

        self.buffer.insert(digest, tracker);

        if let Err(err) = self.comm.broadcast(bytes).await {
            debug!(%err, "network error");
        } else {
            debug!(%digest, "message broadcast");
            self.buffer
                .get_mut(&digest)
                .expect("tracker was just created")
                .status = Status::SentMsg;
        }

        Ok(())
    }

    /// We received a message from the network.
    #[instrument(level = "trace", skip_all, fields(node = %self.label))]
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
    #[instrument(level = "trace", skip_all, fields(node = %self.label, %msg))]
    async fn on_bypass(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };
        self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
        Ok(())
    }

    /// An RBC message proposal has been received.
    #[instrument(level = "trace", skip_all, fields(node = %self.label, %msg))]
    async fn on_propose(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = Digest::new(&msg);

        let tracker = self.buffer.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            retries: 0,
            message: None,
            votes: VoteAccumulator::new(self.committee.clone()),
            status: Status::Init,
        });

        debug!(%digest, status = %tracker.status, "proposal received");

        match tracker.status {
            // First time we see this message.
            Status::Init => {
                tracker.message = Some(msg);
                tracker.status = Status::ReceivedMsg;
                let vote = Protocol::Vote(Envelope::signed(digest, &self.keypair), false);
                let bytes = bincode::serialize(&vote)?;
                self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                tracker.status = Status::SentVote
            }
            // We received a duplicate or a reflection of our own outbound message.
            // In any case we did not manage to cast our vote yet, so we try again.
            Status::ReceivedMsg | Status::SentMsg => {
                debug_assert!(tracker.message.is_some());
                let vote = Protocol::Vote(Envelope::signed(digest, &self.keypair), false);
                let bytes = bincode::serialize(&vote)?;
                self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                tracker.status = Status::SentVote
            }
            // We received votes, possibly prior to the message. If so we update the
            // tracking info with the actual message proposal and vote on the message.
            Status::ReceivedVotes => {
                if tracker.message.is_none() {
                    tracker.message = Some(msg);
                    let vote = Protocol::Vote(Envelope::signed(digest, &self.keypair), false);
                    let bytes = bincode::serialize(&vote)?;
                    self.comm.broadcast(bytes).await.map_err(RbcError::net)?;
                    tracker.status = Status::SentVote
                }
            }
            // We had previously reached a quorum of votes but were missing the message
            // which now arrived (after we requested it). We can finally deliver it to
            // the application.
            Status::RequestedMsg(_) => {
                tracker.message = Some(msg.clone());
                debug!(%msg, %digest, "delivered");
                self.tx.send(msg).await.map_err(|_| RbcError::Shutdown)?;
                tracker.status = Status::Delivered
            }
            // These states already have the message, so there is nothing to be done.
            Status::Delivered | Status::SentVote | Status::ReachedQuorum(_) => {
                debug!(node = %self.label, %digest, status = %tracker.status, "ignoring message proposal");
                debug_assert!(tracker.message.is_some())
            }
        }

        Ok(())
    }

    /// A proposal vote has been received.
    #[instrument(level = "trace", skip_all, fields(
        node  = %self.label,
        from  = %env.signer_label(),
        round = %env.data().round())
    )]
    async fn on_vote(&mut self, env: Envelope<Digest, Unchecked>, done: bool) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = *env.data();
        let source = *env.signing_key();

        let tracker = self.buffer.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            retries: 0,
            message: None,
            votes: VoteAccumulator::new(self.committee.clone()),
            status: Status::Init,
        });

        debug!(%digest, status = %tracker.status, votes = %tracker.votes.votes(), "vote received");

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
            | Status::SentVote => match tracker.votes.add(env) {
                Ok(None) => tracker.status = Status::ReceivedVotes,
                Ok(Some(cert)) => {
                    tracker.status = Status::ReachedQuorum(source);
                    if let Some(msg) = &tracker.message {
                        let m = Protocol::Cert(Envelope::signed(cert.clone(), &self.keypair));
                        let b = bincode::serialize(&m)?;
                        self.comm.broadcast(b).await.map_err(RbcError::net)?;
                        self.tx
                            .send(msg.clone())
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        debug!(%msg, %digest, "delivered");
                        tracker.status = Status::Delivered
                    } else {
                        let m = Protocol::Get(Envelope::signed(digest, &self.keypair));
                        let b = bincode::serialize(&m)?;
                        self.comm.send(source, b).await.map_err(RbcError::net)?;
                        tracker.status = Status::RequestedMsg(source);
                    }
                }
                Err(err) => {
                    warn!(%err, %digest, "failed to add vote");
                    if tracker.votes.is_empty() && tracker.message.is_none() {
                        self.buffer.remove(&digest);
                    }
                }
            },
            // We have previously reached the quorum of votes but did not manage to request
            // the still missing message. We use this additional vote to try again.
            Status::ReachedQuorum(source) if tracker.message.is_none() => {
                let m = Protocol::Get(Envelope::signed(digest, &self.keypair));
                let b = bincode::serialize(&m)?;
                self.comm.send(source, b).await.map_err(RbcError::net)?;
                tracker.status = Status::RequestedMsg(source);
            }
            Status::ReachedQuorum(_) | Status::RequestedMsg(_) | Status::Delivered => {
                if done {
                    debug!(node = %self.label, status = %tracker.status, "ignoring vote")
                } else {
                    debug!(%digest, status = %tracker.status, "replying with our vote to sender");
                    let vote = Protocol::Vote(Envelope::signed(digest, &self.keypair), true);
                    let bytes = bincode::serialize(&vote)?;
                    self.comm.send(source, bytes).await.map_err(RbcError::net)?;
                }
            }
        }

        Ok(())
    }

    /// We received a vote certificate.
    #[instrument(level = "trace", skip_all, fields(
        node  = %self.label,
        from  = %env.signer_label(),
        round = %env.data().data().round())
    )]
    async fn on_cert(&mut self, env: Envelope<Certificate<Digest>, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        if !env.data().is_valid_quorum(&self.committee) {
            return Err(RbcError::InvalidSignature);
        }

        let digest = *env.data().data();
        let source = *env.signing_key();

        let tracker = self.buffer.entry(digest).or_insert_with(|| Tracker {
            ours: false,
            start: Instant::now(),
            retries: 0,
            message: None,
            votes: VoteAccumulator::new(self.committee.clone()),
            status: Status::Init,
        });

        debug!(%digest, status = %tracker.status, "certificate received");

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
                tracker.status = Status::ReachedQuorum(source);

                if let Some(msg) = &tracker.message {
                    let m = Protocol::Cert(Envelope::signed(env.into_data(), &self.keypair));
                    let b = bincode::serialize(&m)?;
                    self.comm.broadcast(b).await.map_err(RbcError::net)?;
                    self.tx
                        .send(msg.clone())
                        .await
                        .map_err(|_| RbcError::Shutdown)?;
                    debug!(%msg, "delivered");
                    tracker.status = Status::Delivered
                } else {
                    let m = Protocol::Get(Envelope::signed(digest, &self.keypair));
                    let b = bincode::serialize(&m)?;
                    self.comm.send(source, b).await.map_err(RbcError::net)?;
                    tracker.status = Status::RequestedMsg(source);
                }
            }
            // We have previously reached the quorum of votes but did not manage to request
            // the still missing message. Let's try again.
            Status::ReachedQuorum(source) if tracker.message.is_none() => {
                let m = Protocol::Get(Envelope::signed(digest, &self.keypair));
                let b = bincode::serialize(&m)?;
                self.comm.send(source, b).await.map_err(RbcError::net)?;
                tracker.status = Status::RequestedMsg(source);
            }
            Status::ReachedQuorum(_) | Status::RequestedMsg(_) | Status::Delivered => {
                debug!(node = %self.label, status = %tracker.status, "ignoring certificate")
            }
        }

        Ok(())
    }

    /// One of our peers is asking for a message proposal.
    #[instrument(level = "trace", skip_all, fields(
        node  = %self.label,
        from  = %env.signer_label(),
        round = %env.data().round())
    )]
    async fn on_get(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let Some(tracker) = self.buffer.get_mut(env.data()) else {
            warn!(
                node = %self.label,
                from = %env.signer_label(),
                "ignoring get request for data we do not have"
            );
            return Ok(());
        };

        debug!(digest = %env.data(), status = %tracker.status, "get request received");

        match tracker.status {
            // We do not have the message ourselves when in these states.
            Status::Init | Status::RequestedMsg(_) => {
                debug!(node = %self.label, status = %tracker.status, "ignoring get request");
                debug_assert!(tracker.message.is_none())
            }
            // Here, we may have the message and if so, we gladly share it.
            Status::SentVote | Status::ReceivedVotes | Status::ReachedQuorum(_) => {
                if let Some(msg) = &tracker.message {
                    send(&mut self.comm, *env.signing_key(), msg).await?;
                }
            }
            // In these states we must have the message and send to to the peer.
            Status::ReceivedMsg | Status::SentMsg | Status::Delivered => {
                let msg = tracker
                    .message
                    .as_ref()
                    .expect("message is present in these status");
                send(&mut self.comm, *env.signing_key(), msg).await?;
            }
        }

        Ok(())
    }

    /// Periodically we go over message status and retry incomplete items.
    #[instrument(level = "trace", skip_all, fields(node = %self.label))]
    async fn retry(&mut self, now: Instant) -> Result<()> {
        for (digest, tracker) in &mut self.buffer {
            debug!(%digest, status = %tracker.status, retries = %tracker.retries, "revisiting");
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
                        .as_ref()
                        .expect("message was sent => set in tracker");
                    debug!(%digest, msg = %messg, "re-broadcasting message");
                    let proto = Protocol::Propose(Cow::Borrowed(messg));
                    let bytes = bincode::serialize(&proto).expect("idempotent serialization");
                    tracker.start = now;
                    tracker.retries = tracker.retries.saturating_add(1);
                    if let Err(e) = self.comm.broadcast(bytes).await {
                        debug!(err = %e, "network error");
                    }
                }
                // If we have a message we might not have been able to send our vote
                // or it might not have reached enough parties, so we try again here.
                Status::ReceivedMsg | Status::ReceivedVotes | Status::SentVote => {
                    if let Some(msg) = &tracker.message {
                        let timeout = [3, 6, 10, 15, 30]
                            .get(tracker.retries)
                            .copied()
                            .unwrap_or(30);
                        if tracker.start.elapsed() < Duration::from_millis(timeout) {
                            continue;
                        }
                        if tracker.ours {
                            debug!(%digest, "sending our message (again)");
                            let proto = Protocol::Propose(Cow::Borrowed(msg));
                            let bytes = bincode::serialize(&proto)?;
                            self.comm.broadcast(bytes).await.map_err(RbcError::net)?
                        }
                        debug!(%digest, "sending our vote (again)");
                        let vote = Protocol::Vote(Envelope::signed(*digest, &self.keypair), false);
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
                Status::RequestedMsg(source) => {
                    let timeout = [1, 3, 6, 10, 15, 30]
                        .get(tracker.retries)
                        .copied()
                        .unwrap_or(30);
                    if tracker.start.elapsed() < Duration::from_millis(timeout) {
                        continue;
                    }
                    debug!(%digest, "requesting message again");
                    let m = Protocol::Get(Envelope::signed(*digest, &self.keypair));
                    let b = bincode::serialize(&m).expect("idempotent serialization");
                    let s = tracker
                        .votes
                        .voters()
                        .choose(&mut rand::thread_rng())
                        .unwrap_or(&source);
                    tracker.start = now;
                    tracker.retries = tracker.retries.saturating_add(1);
                    self.comm.send(*s, b).await.map_err(RbcError::net)?;
                }
                // We have reached a quorum of votes. We may either already have the message,
                // in which case we previously failed to broadcast the certificate, or we did
                // not manage to request the message yet.
                Status::ReachedQuorum(source) => {
                    let timeout = [3, 6, 10, 15, 30]
                        .get(tracker.retries)
                        .copied()
                        .unwrap_or(30);
                    if tracker.start.elapsed() < Duration::from_millis(timeout) {
                        continue;
                    }
                    if let Some(msg) = &tracker.message {
                        let c = tracker
                            .votes
                            .certificate()
                            .expect("reached quorum => certificate");
                        debug!(%digest, %msg, "sending certificate");
                        let m = Protocol::Cert(Envelope::signed(c.clone(), &self.keypair));
                        let b = bincode::serialize(&m).expect("idempotent serialization");
                        tracker.start = now;
                        tracker.retries = tracker.retries.saturating_add(1);
                        self.comm.broadcast(b).await.map_err(RbcError::net)?;
                        self.tx
                            .send(msg.clone())
                            .await
                            .map_err(|_| RbcError::Shutdown)?;
                        debug!(%msg, "delivered");
                        tracker.status = Status::Delivered
                    } else {
                        debug!(%digest, "requesting message");
                        let m = Protocol::Get(Envelope::signed(*digest, &self.keypair));
                        let b = bincode::serialize(&m).expect("idempotent serialization");
                        let s = tracker
                            .votes
                            .voters()
                            .choose(&mut rand::thread_rng())
                            .unwrap_or(&source);
                        tracker.start = now;
                        tracker.retries = tracker.retries.saturating_add(1);
                        self.comm.send(*s, b).await.map_err(RbcError::net)?;
                        tracker.status = Status::RequestedMsg(source);
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

    #[error("invalid signature")]
    InvalidSignature,

    #[error("rbc has shut down")]
    Shutdown,
}

impl RbcError {
    fn net<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Net(Box::new(e))
    }
}

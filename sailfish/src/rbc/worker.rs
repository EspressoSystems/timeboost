use std::borrow::Cow;
use std::cmp::max;
use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use hotshot::traits::NetworkError;
use hotshot_types::traits::network::Topic;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::{Envelope, Unchecked, Validated};
use timeboost_core::types::message::Message;
use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::{Keypair, Label, PublicKey};
use timeboost_networking::network::client::Libp2pNetwork;
use tokio::sync::mpsc;
use tracing::{debug, error, instrument, trace, warn};

use super::{Command, Digest, RbcMsg};
use crate::consensus::VoteAccumulator;

type Result<T> = std::result::Result<T, RbcError>;
type Sender = mpsc::Sender<Message<Validated>>;
type Receiver = mpsc::Receiver<Command>;

pub struct Worker {
    keypair: Keypair,
    label: Label,
    libp2p: Libp2pNetwork<PublicKey>,
    tx: Sender,
    rx: Receiver,
    round: RoundNumber,
    committee: StaticCommittee,
    buffer: HashMap<Digest, Tracker>,
}

struct Tracker {
    start: Instant,
    message: Option<Message<Validated>>,
    votes: VoteAccumulator<Digest>,
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
    RequestedMsg,
    /// We have received one or more votes.
    ReceivedVotes,
    /// A quorum of votes has been reached.
    ReachedQuorum,
    /// The message has been RBC delivered.
    Delivered
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

impl Worker {
    pub fn new(
        tx: Sender,
        rx: Receiver,
        kp: Keypair,
        nt: Libp2pNetwork<PublicKey>,
        sc: StaticCommittee,
    ) -> Self {
        Self {
            label: Label::new(kp.public_key()),
            keypair: kp,
            libp2p: nt,
            tx,
            rx,
            round: RoundNumber::genesis(),
            committee: sc,
            buffer: HashMap::new(),
        }
    }

    pub async fn go(mut self) {
        // TODO: Go repeatedly over status and retry old messages.
        loop {
            tokio::select! {
                val = self.libp2p.recv_message() => {
                    match val {
                        Ok(bytes) => {
                            if let Err(err) = self.on_inbound(bytes).await {
                                warn!(%err, "error on inbound message");
                            }
                        }
                        Err(err) => warn!(%err, "error receiving message from libp2p")
                    }
                },
                cmd = self.rx.recv() => match cmd {
                    Some(Command::RbcBroadcast(msg, tx)) => {
                        match self.on_outbound(msg).await {
                            Ok(()) => {
                                let _ = tx.send(Ok(()));
                            }
                            Err(err) => {
                                warn!(%err, "error rbc broadcasting message");
                                let _ = tx.send(Err(err));
                            }
                        }
                    }
                    Some(Command::Send(to, msg)) => {
                        match self.on_send(to, msg).await {
                            Ok(()) => {}
                            Err(err) => warn!(%err, "error sending message")
                        }
                    }
                    Some(Command::Broadcast(msg)) => {
                        match self.on_broadcast(msg).await {
                            Ok(()) => {}
                            Err(err) => warn!(%err, "error broadcasting message")
                        }
                    }
                    Some(Command::Shutdown(reply)) => {
                        self.libp2p.shut_down().await;
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
    #[instrument(level = "trace", skip(self), fields(node = %self.label))]
    async fn on_broadcast(&mut self, msg: Message<Validated>) -> Result<()> {
        let bytes = bincode::serialize(&msg)?;
        self.libp2p.broadcast_message(bytes, Topic::Global).await?;
        Ok(())
    }

    /// 1:1 communication.
    #[instrument(level = "trace", skip(self), fields(node = %self.label))]
    async fn on_send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<()> {
        let bytes = bincode::serialize(&msg)?;
        self.libp2p.direct_message(bytes, to).await?;
        Ok(())
    }

    /// Start RBC broadcast.
    #[instrument(level = "trace", skip(self), fields(node = %self.label))]
    async fn on_outbound(&mut self, msg: Message<Validated>) -> Result<()> {
        let proto = RbcMsg::Propose(Cow::Borrowed(&msg));
        let bytes = bincode::serialize(&proto)?;
        let digest = Digest::new(&msg);

        self.round = max(self.round, msg.round());

        let tracker = Tracker {
            start: Instant::now(),
            message: Some(msg),
            votes: VoteAccumulator::new(self.committee.clone()),
            status: Status::Init
        };

        self.buffer.insert(digest, tracker);

        if let Err(err) = self.libp2p.broadcast_message(bytes, Topic::Global).await {
            debug!(%err, "network error");
        } else {
            self.buffer
                .get_mut(&digest)
                .expect("tracker was just created")
                .status = Status::SentMsg;
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.label))]
    async fn on_inbound(&mut self, bytes: Vec<u8>) -> Result<()> {
        match bincode::deserialize(&bytes)? {
            RbcMsg::Propose(msg) => self.on_propose(msg.into_owned()).await?,
            RbcMsg::Vote(env) => self.on_vote(env).await?,
            RbcMsg::Get(env) => self.on_get(env).await?,
            RbcMsg::Cert(crt) => self.on_cert(crt).await?,
        }
        Ok(())
    }

    #[instrument(level = "trace", skip(self), fields(node = %self.label))]
    async fn on_propose(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = Digest::new(&msg);

        let tracker = self.buffer.entry(digest).or_insert_with(|| Tracker {
            start: Instant::now(),
            message: None,
            votes: VoteAccumulator::new(self.committee.clone()),
            status: Status::Init,
        });

        match tracker.status {
            Status::Init => {
                tracker.message = Some(msg);
                tracker.status = Status::ReceivedMsg;
                let vote = RbcMsg::Vote(Envelope::signed(digest, &self.keypair));
                let bytes = bincode::serialize(&vote)?;
                self.libp2p.broadcast_message(bytes, Topic::Global).await?;
                tracker.status = Status::SentVote
            }
            Status::ReceivedMsg | Status::SentMsg => {
                debug_assert!(tracker.message.is_some());
                let vote = RbcMsg::Vote(Envelope::signed(digest, &self.keypair));
                let bytes = bincode::serialize(&vote)?;
                self.libp2p.broadcast_message(bytes, Topic::Global).await?;
                tracker.status = Status::SentVote
            }
            Status::ReceivedVotes => {
                if tracker.message.is_none() {
                    tracker.message = Some(msg);
                    let vote = RbcMsg::Vote(Envelope::signed(digest, &self.keypair));
                    let bytes = bincode::serialize(&vote)?;
                    self.libp2p.broadcast_message(bytes, Topic::Global).await?;
                }
            }
            Status::RequestedMsg => {
                tracker.message = Some(msg.clone());
                self.tx.send(msg).await.unwrap();
                tracker.status = Status::Delivered
            }
            Status::Delivered | Status::SentVote | Status::ReachedQuorum => {
                debug!(node = %self.label, status = %tracker.status, "ignoring message proposal")
            }
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.label, from = %env.signer_label()))]
    async fn on_vote(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = *env.data();
        let source = *env.signing_key();

        let tracker = self.buffer.entry(digest).or_insert_with(|| {
            Tracker {
                start: Instant::now(),
                message: None,
                votes: VoteAccumulator::new(self.committee.clone()),
                status: Status::ReceivedVotes
            }
        });

        match tracker.status {
            Status::Init | Status::ReceivedMsg | Status::SentMsg | Status::ReceivedVotes | Status::SentVote => {
                match tracker.votes.add(env) {
                    Ok(None) => {
                        tracker.status = Status::ReceivedVotes
                    }
                    Ok(Some(cert)) => {
                        tracker.status = Status::ReachedQuorum;
                        if let Some(msg) = &tracker.message {
                            let m = RbcMsg::Cert(Envelope::signed(cert.clone(), &self.keypair));
                            let b = bincode::serialize(&m)?;
                            self.libp2p.broadcast_message(b, Topic::Global).await?;
                            self.tx.send(msg.clone()).await.unwrap();
                            tracker.status = Status::Delivered
                        } else {
                            let m = RbcMsg::Get(Envelope::signed(digest, &self.keypair));
                            let b = bincode::serialize(&m)?;
                            self.libp2p.direct_message(b, source).await?;
                            tracker.status = Status::RequestedMsg;
                        }
                    }
                    Err(err) => {
                        warn!(%err, "failed to add vote");
                        if tracker.votes.is_empty() && tracker.message.is_none() {
                            self.buffer.remove(&digest);
                        }
                    }
                }
            }
            Status::RequestedMsg | Status::Delivered | Status::ReachedQuorum => {
                debug!(node = %self.label, status = %tracker.status, "ignoring vote")
            }
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.label, from = %env.signer_label()))]
    async fn on_cert(&mut self, env: Envelope<Certificate<Digest>, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        if !env.data().is_valid_quorum(&self.committee) {
            return Err(RbcError::InvalidSignature);
        }

        let digest = *env.data().data();
        let source = *env.signing_key();

        let tracker = self.buffer.entry(digest).or_insert_with(|| {
            Tracker {
                start: Instant::now(),
                message: None,
                votes: VoteAccumulator::new(self.committee.clone()),
                status: Status::Init
            }
        });

        match tracker.status {
            Status::Init | Status::ReceivedMsg | Status::SentMsg | Status::ReceivedVotes | Status::SentVote => {
                tracker.votes.set_certificate(env.data().clone());
                tracker.status = Status::ReachedQuorum;

                if let Some(msg) = &tracker.message {
                    let m = RbcMsg::Cert(Envelope::signed(env.into_data(), &self.keypair));
                    let b = bincode::serialize(&m)?;
                    self.libp2p.broadcast_message(b, Topic::Global).await?;
                    self.tx.send(msg.clone()).await.unwrap();
                    tracker.status = Status::Delivered
                } else {
                    let m = RbcMsg::Get(Envelope::signed(digest, &self.keypair));
                    let b = bincode::serialize(&m)?;
                    self.libp2p.direct_message(b, source).await?;
                    tracker.status = Status::RequestedMsg;
                }
            }
            Status::Delivered | Status::ReachedQuorum | Status::RequestedMsg => {
                debug!(node = %self.label, status = %tracker.status, "ignoring certificate")
            }
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(node = %self.label, from = %env.signer_label()))]
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
            return Ok(())
        };

        match tracker.status {
            Status::Init | Status::RequestedMsg => {
                debug!(node = %self.label, status = %tracker.status, "ignoring get request")
            }
            Status::ReceivedMsg
                | Status::SentMsg
                | Status::ReceivedVotes
                | Status::SentVote
                | Status::Delivered
                | Status::ReachedQuorum =>
            {
                let msg = tracker.message.clone().unwrap();
                self.on_send(*env.signing_key(), msg).await.unwrap()
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RbcError {
    #[error("network error: {0}")]
    Net(#[from] NetworkError),

    #[error("bincode error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("rbc has shut down")]
    Shutdown
}

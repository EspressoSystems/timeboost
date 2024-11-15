use std::borrow::Cow;
use std::cmp::max;
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Instant;

use hotshot::traits::{implementations::Libp2pNetwork, NetworkError};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::{Envelope, Unchecked, Validated};
use timeboost_core::types::message::Message;
use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::{Keypair, PublicKey};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use super::{Digest, RbcMsg};
use crate::consensus::VoteAccumulator;

type Result<T> = std::result::Result<T, RbcError>;
type Sender = mpsc::Sender<Message<Validated>>;
type Receiver = mpsc::Receiver<(Option<PublicKey>, Message<Validated>)>;

pub struct Worker {
    keypair: Keypair,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Status {
    Init,
    SentMsg,
    ReceivedMsg,
    SentVote,
    RequestedMsg,
    ReceivedVotes,
    ReachedQuorum,
    Delivered
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
            keypair: kp,
            libp2p: nt,
            tx,
            rx,
            round: RoundNumber::genesis(),
            committee: sc,
            buffer: HashMap::new(),
        }
    }

    pub async fn go(mut self) -> Infallible {
        // TODO: Go repeatedly over status and retry old messages.
        loop {
            tokio::select! {
                val = self.libp2p.recv_message() => {
                    match val {
                        Ok(bytes) => self.on_inbound(bytes).await.unwrap(),
                        Err(err) => warn!(%err, "error receiving message from libp2p")
                    }
                },
                Some((to, msg)) = self.rx.recv() => {
                    match self.on_outbound(to, msg).await {
                        Ok(()) => {}
                        Err(err) => warn!(%err, "error sending messages")
                    }
                },
                else => {
                    // `Rbc` never closes the sending half of `Worker::rx` and its
                    // `Drop` impl stops the worker task, so `tokio::select!` will
                    // never fail to match a branch.
                    unreachable!("A `Worker` does not outlive the `Rbc` it belongs to.")
                }
            }
        }
    }

    async fn on_outbound(&mut self, to: Option<PublicKey>, msg: Message<Validated>) -> Result<()> {
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

        if let Some(to) = to {
            self.libp2p.direct_message(bytes, to).await?;
        } else {
            self.libp2p.broadcast_message(bytes, Topic::Global, BroadcastDelay::None).await?;
        }

        self.buffer
            .get_mut(&digest)
            .expect("tracker was just created")
            .status = Status::SentMsg;

        Ok(())
    }

    async fn on_inbound(&mut self, bytes: Vec<u8>) -> Result<()> {
        let proto = bincode::deserialize(&bytes)?;
        match proto {
            RbcMsg::Propose(msg) => self.on_propose(msg.into_owned()).await?,
            RbcMsg::Vote(env) => self.on_vote(env).await?,
            RbcMsg::Get(env) => self.on_get(env)?,
            RbcMsg::Cert(crt) => self.on_cert(crt).await?,
        }
        Ok(())
    }

    async fn on_propose(&mut self, msg: Message<Unchecked>) -> Result<()> {
        if msg.round() < self.round.saturating_sub(1).into() {
            debug!(round = %self.round, r = %msg.round(), "ignoring old proposal");
            return Ok(());
        }

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
                self.libp2p
                    .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
                    .await?;
                tracker.status = Status::SentVote
            }
            Status::ReceivedMsg => {
                debug_assert!(tracker.message.is_some());
                let vote = RbcMsg::Vote(Envelope::signed(digest, &self.keypair));
                let bytes = bincode::serialize(&vote)?;
                self.libp2p
                    .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
                    .await?;
                tracker.status = Status::SentVote
            }
            Status::SentVote => {}
            Status::ReceivedVotes => {
                if tracker.message.is_none() {
                    tracker.message = Some(msg);
                    let vote = RbcMsg::Vote(Envelope::signed(digest, &self.keypair));
                    let bytes = bincode::serialize(&vote)?;
                    self.libp2p
                        .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
                        .await?;
                }
            }
            Status::Delivered => return Ok(()),
            Status::RequestedMsg => {
                tracker.message = Some(msg.clone());
                self.tx.send(msg).await.unwrap();
                tracker.status = Status::Delivered
            }
            Status::ReachedQuorum => {}
            Status::SentMsg => unreachable!()
        }

        Ok(())
    }

    async fn on_vote(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = *env.data();
        let source = *env.signing_key();

        if digest.round() < self.round.saturating_sub(1).into() {
            debug!(round = %self.round, r = %digest.round(), "ignoring old vote");
            return Ok(());
        }

        let tracker = self.buffer.entry(digest).or_insert_with(|| {
            Tracker {
                start: Instant::now(),
                message: None,
                votes: VoteAccumulator::new(self.committee.clone()),
                status: Status::ReceivedVotes
            }
        });

        match tracker.votes.add(env) {
            Ok(None) => {
                tracker.status = Status::ReceivedVotes
            }
            Ok(Some(cert)) => {
                tracker.status = Status::ReachedQuorum;
                if let Some(msg) = &tracker.message {
                    let m = RbcMsg::Cert(Envelope::signed(cert.clone(), &self.keypair));
                    let b = bincode::serialize(&m)?;
                    self.libp2p
                        .broadcast_message(b, Topic::Global, BroadcastDelay::None)
                        .await?;
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
                if tracker.votes.is_empty() && tracker.message.is_none() {
                    self.buffer.remove(&digest);
                }
            }
        }

        Ok(())
    }

    async fn on_cert(&mut self, env: Envelope<Certificate<Digest>, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        if !env.data().is_valid_quorum(&self.committee) {
            return Err(RbcError::InvalidSignature);
        }

        let digest = *env.data().data();
        let source = *env.signing_key();

        if digest.round() < self.round.saturating_sub(1).into() {
            debug!(round = %self.round, r = %digest.round(), "ignoring old certificate");
            return Ok(());
        }

        let tracker = self.buffer.entry(digest).or_insert_with(|| {
            Tracker {
                start: Instant::now(),
                message: None,
                votes: VoteAccumulator::new(self.committee.clone()),
                status: Status::ReceivedVotes
            }
        });

        if tracker.status == Status::Delivered {
            return Ok(())
        }

        tracker.votes.set_certificate(env.data().clone());
        tracker.status = Status::ReachedQuorum;

        if let Some(msg) = &tracker.message {
            let m = RbcMsg::Cert(Envelope::signed(env.into_data(), &self.keypair));
            let b = bincode::serialize(&m)?;
            self.libp2p
                .broadcast_message(b, Topic::Global, BroadcastDelay::None)
                .await?;
            self.tx.send(msg.clone()).await.unwrap();
            tracker.status = Status::Delivered
        } else {
            let m = RbcMsg::Get(Envelope::signed(digest, &self.keypair));
            let b = bincode::serialize(&m)?;
            self.libp2p.direct_message(b, source).await?;
            tracker.status = Status::RequestedMsg;
        }

        Ok(())
    }

    fn on_get(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };
        todo!()
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
}

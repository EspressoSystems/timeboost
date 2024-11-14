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
    net: Libp2pNetwork<PublicKey>,
    tx: Sender,
    rx: Receiver,
    round: RoundNumber,
    committee: StaticCommittee,
    all: HashMap<Digest, MultiStatus>,
    one: HashMap<Digest, UniStatus>,
}

/// Track the status of a multicast message.
struct MultiStatus {
    /// When did we send the message or received one (or their votes).
    start: Instant,
    /// The message we sent or received.
    message: Option<Message<Validated>>,
    /// The votes we received for this message.
    votes: VoteAccumulator<Digest>,
    /// Did we vote ourselves for the message?
    voted: bool,
    /// Have we already delivered the message?
    delivered: bool,
}

struct UniStatus {
    start: Instant,
    message: Message<Validated>,
    success: bool,
    delivered: bool,
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
            net: nt,
            tx,
            rx,
            round: RoundNumber::genesis(),
            committee: sc,
            all: HashMap::new(),
            one: HashMap::new(),
        }
    }

    pub async fn go(mut self) -> Infallible {
        // TODO: Go repeatedly over status and retry old messages.
        loop {
            tokio::select! {
                val = self.net.recv_message() => match val {
                    Ok(bytes) => self.on_inbound(bytes).await.unwrap(),
                    Err(err) => {
                        warn!(%err, "error receiving message from libp2p")
                    }
                },
                Some((to, msg)) = self.rx.recv() => {
                    self.on_outbound(to, msg).await.unwrap()
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

        self.round = max(self.round, msg.round());

        if let Some(to) = to {
            let status = UniStatus {
                start: Instant::now(),
                message: msg,
                success: false,
                delivered: false,
            };
            self.one.insert(Digest::new(&status.message), status);
            self.net.direct_message(bytes, to).await?
        } else {
            let digest = Digest::new(&msg);
            let status = MultiStatus {
                start: Instant::now(),
                message: Some(msg),
                votes: VoteAccumulator::new(self.committee.clone()),
                voted: true,
                delivered: false,
            };
            self.all.insert(digest, status);
            self.net
                .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
                .await?
        }

        Ok(())
    }

    async fn on_inbound(&mut self, bytes: Vec<u8>) -> Result<()> {
        let proto = bincode::deserialize(&bytes)?;
        match proto {
            RbcMsg::Propose(msg) => self.on_propose(msg.into_owned()).await?,
            RbcMsg::Vote(env) => self.on_vote(env)?,
            RbcMsg::Get(env) => self.on_get(env)?,
            RbcMsg::Cert(crt) => self.on_cert(crt).await?,
        }
        Ok(())
    }

    async fn on_propose(&mut self, msg: Message<Unchecked>) -> Result<()> {
        if msg.round() + 2 < self.round {
            debug!(round = %self.round, r = %msg.round(), "ignoring old proposal");
            return Ok(());
        }

        let Some(msg) = msg.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = Digest::new(&msg);

        // Let's first see if we asked for this data:

        if let Some(status) = self.one.get_mut(&digest) {
            if status.delivered {
                return Ok(());
            }
            status.delivered = true;
            self.tx.send(status.message.clone()).await.unwrap();
            return Ok(());
        }

        // Otherwise it is a broadcast message:

        let status = self.all.entry(digest).or_insert_with(|| MultiStatus {
            start: Instant::now(),
            message: Some(msg),
            votes: VoteAccumulator::new(self.committee.clone()),
            voted: false,
            delivered: false,
        });

        if !status.voted {
            let vote = RbcMsg::Vote(Envelope::signed(digest, &self.keypair));
            let bytes = bincode::serialize(&vote)?;
            self.net
                .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
                .await?;
            status.voted = true
        }

        Ok(())
    }

    fn on_vote(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        let digest = *env.data();

        if digest.round() + 2 < self.round {
            debug!(round = %self.round, r = %digest.round(), "ignoring old vote");
            return Ok(());
        }

        todo!()
    }

    async fn on_cert(&mut self, env: Envelope<Certificate<Digest>, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };

        if !env.data().is_valid_quorum(&self.committee) {
            return Err(RbcError::InvalidSignature);
        }

        let digest = *env.data().data();

        if digest.round() + 2 < self.round {
            debug!(round = %self.round, r = %digest.round(), "ignoring old certificate");
            return Ok(());
        }

        //let status = self.all.entry(digest).or_insert_with(|| {
        //});
        //
        //if status.delivered {
        //    return Ok(())
        //}
        //
        //status.success.set_certificate(cert);
        //
        //if let Some(msg) = &status.message {
        //    self.tx.send(msg.clone()).await.unwrap();
        //    status.delivered = true;
        //} else {
        //    let msg = RbcMsg::Get(Envelope::signed(digest, &self.keypair));
        //    let bytes = bincode::serialize(&msg)?;
        //}
        //
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

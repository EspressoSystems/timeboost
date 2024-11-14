use std::borrow::Cow;
use std::cmp::max;
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Instant;

use async_trait::async_trait;
use committable::{Commitment, Committable};
use hotshot::traits::{implementations::Libp2pNetwork, NetworkError};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};
use serde::{Deserialize, Serialize};
use timeboost_core::traits::comm::Comm;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::{Envelope, Unchecked, Validated};
use timeboost_core::types::message::Message;
use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::PublicKey;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::consensus::VoteAccumulator;

type Result<T> = std::result::Result<T, RbcError>;

#[derive(Debug, Serialize, Deserialize)]
enum RbcMsg<'a, Status: Clone> {
    Propose(Cow<'a, Message<Status>>),
    Vote(Envelope<Digest, Status>),
    Cert(Certificate<Digest>),
    Get(Envelope<Digest, Status>),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct Digest([u8; 32]);

impl<S> From<Commitment<Message<S>>> for Digest {
    fn from(value: Commitment<Message<S>>) -> Self {
        Self(value.into())
    }
}

impl Committable for Digest {
    fn commit(&self) -> Commitment<Self> {
        Commitment::from_raw(self.0)
    }
}

#[derive(Debug)]
pub struct Rbc {
    rx: mpsc::Receiver<Message<Validated>>,
    tx: mpsc::Sender<(Option<PublicKey>, Message<Validated>)>,
    jh: JoinHandle<Infallible>,
}

impl Drop for Rbc {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl Rbc {
    pub fn new(net: Libp2pNetwork<PublicKey>, committee: StaticCommittee) -> Self {
        let (obound_tx, obound_rx) = mpsc::channel(2 * committee.size().get());
        let (ibound_tx, ibound_rx) = mpsc::channel(3 * committee.size().get());
        let worker = Worker {
            net,
            tx: ibound_tx,
            rx: obound_rx,
            committee,
            round: RoundNumber::genesis(),
            all: Default::default(),
            one: Default::default(),
        };
        Self {
            rx: ibound_rx,
            tx: obound_tx,
            jh: tokio::spawn(worker.go()),
        }
    }
}

#[async_trait]
impl Comm for Rbc {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<()> {
        self.tx.send((None, msg)).await.unwrap();
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<()> {
        self.tx.send((Some(to), msg)).await.unwrap();
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<Validated>> {
        Ok(self.rx.recv().await.unwrap())
    }
}

#[derive(Debug)]
struct Worker {
    net: Libp2pNetwork<PublicKey>,
    tx: mpsc::Sender<Message<Validated>>,
    rx: mpsc::Receiver<(Option<PublicKey>, Message<Validated>)>,
    round: RoundNumber,
    committee: StaticCommittee,
    all: HashMap<Digest, Status<VoteAccumulator<Digest>>>,
    one: HashMap<Digest, Status<bool>>,
}

#[derive(Debug)]
struct Status<T> {
    start: Instant,
    message: Message<Validated>,
    success: T,
    delivered: bool
}

impl Worker {
    async fn go(mut self) -> Infallible {
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
            let status = Status {
                start: Instant::now(),
                message: msg,
                success: false,
                delivered: false
            };
            self.one.insert(status.message.commit().into(), status);
            self.net.direct_message(bytes, to).await?
        } else {
            let status = Status {
                start: Instant::now(),
                message: msg,
                success: VoteAccumulator::new(self.committee.clone()),
                delivered: false
            };
            self.all.insert(status.message.commit().into(), status);
            self.net
                .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
                .await?
        }

        Ok(())
    }

    async fn on_inbound(&mut self, bytes: Vec<u8>) -> Result<()> {
        let proto = bincode::deserialize(&bytes)?;
        match proto {
            RbcMsg::Propose(msg) => self.on_propose(msg.into_owned())?,
            RbcMsg::Vote(env) => self.on_vote(env)?,
            RbcMsg::Get(env) => self.on_get(env)?,
            RbcMsg::Cert(crt) => {
                if let Some(msg) = self.on_cert(crt) {
                    self.tx.send(msg).await.unwrap()
                }
            }
        }
        Ok(())
    }

    fn on_propose(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };
        todo!()
    }

    fn on_vote(&mut self, env: Envelope<Digest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature);
        };
        todo!()
    }

    fn on_cert(&mut self, cert: Certificate<Digest>) -> Option<Message<Validated>> {
        let Some(status) = self.all.get_mut(cert.data()) else {
            return None
        };

        if status.delivered {
            return None
        }

        if !cert.is_valid_quorum(&self.committee) {
            warn!("message digest certificate has invalid quorum");
            return None
        }

        status.delivered = true;
        Some(status.message.clone())
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

use std::borrow::Cow;
use std::collections::BTreeMap;

use async_trait::async_trait;
use committable::{Committable, Commitment};
use hotshot::traits::{implementations::Libp2pNetwork, NetworkError};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};
use serde::{Serialize, Deserialize};
use timeboost_core::traits::comm::Comm;
use timeboost_core::types::PublicKey;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::envelope::{Envelope, Validated, Unchecked};
use timeboost_core::types::message::Message;

use crate::consensus::VoteAccumulator;

type Result<T> = std::result::Result<T, RbcError>;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
struct MessageDigest([u8; 32]);

impl<S> From<Commitment<Message<S>>> for MessageDigest {
    fn from(value: Commitment<Message<S>>) -> Self {
        Self(value.into())
    }
}

impl Committable for MessageDigest {
    fn commit(&self) -> Commitment<Self> {
        Commitment::from_raw(self.0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum Protocol<'a, Status: Clone> {
    Proposal(Cow<'a, Message<Status>>),
    Vote(Envelope<MessageDigest, Status>),
    Done(Certificate<MessageDigest>),
    Get(Envelope<MessageDigest, Status>),
}

#[derive(Debug)]
pub struct Rbc {
    committee: StaticCommittee,
    net: Libp2pNetwork<PublicKey>,
    cache: BTreeMap<MessageDigest, Message<Validated>>,
    votes: BTreeMap<MessageDigest, VoteAccumulator<MessageDigest>>,
}

impl Rbc {
    pub fn new(net: Libp2pNetwork<PublicKey>, committee: StaticCommittee) -> Self {
        Self {
            committee,
            net,
            cache: BTreeMap::new(),
            votes: BTreeMap::new()
        }
    }

    async fn on_proposal(&mut self, msg: Message<Unchecked>) -> Result<()> {
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature)
        };
        todo!()
    }

    async fn on_vote(&mut self, env: Envelope<MessageDigest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature)
        };
        todo!()
    }

    async fn on_get(&mut self, env: Envelope<MessageDigest, Unchecked>) -> Result<()> {
        let Some(env) = env.validated(&self.committee) else {
            return Err(RbcError::InvalidSignature)
        };
        todo!()
    }

    fn on_cert(&mut self, cert: Certificate<MessageDigest>) -> Option<Message<Validated>> {
        self.cache.get(cert.data()).cloned()
    }
}

#[async_trait]
impl Comm for Rbc {
    type Err = RbcError;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<()> {
        let proto = Protocol::Proposal(Cow::Borrowed(&msg));
        let bytes = bincode::serialize(&proto)?;
        let commit = msg.commit().into();
        self.cache.insert(commit, msg);
        self.votes.insert(commit, VoteAccumulator::new(self.committee.clone()));
        self.net.broadcast_message(bytes, Topic::Global, BroadcastDelay::None).await?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<()> {
        let proto = Protocol::Proposal(Cow::Borrowed(&msg));
        let bytes = bincode::serialize(&proto)?;
        self.net.direct_message(bytes, to).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<Validated>> {
        loop {
            let bytes = self.net.recv_message().await?;
            let proto = bincode::deserialize(&bytes)?;
            match proto {
                Protocol::Proposal(msg) => self.on_proposal(msg.into_owned()).await?,
                Protocol::Vote(env) => self.on_vote(env).await?,
                Protocol::Get(env) => self.on_get(env).await?,
                Protocol::Done(crt) => if let Some(msg) = self.on_cert(crt) {
                    return Ok(msg)
                }
            }
        }
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
    InvalidSignature
}

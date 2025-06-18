use std::error::Error;

use async_trait::async_trait;
use committable::Committable;
use multisig::{PublicKey, Validated};

use crate::{Message, Round, RoundNumber};

/// Types that provide broadcast and 1:1 message communication.
#[async_trait]
pub trait Comm<T: Committable> {
    type Err: Error + Send + Sync + 'static;
    type CommitteeInfo: Send + Sync + 'static;

    /// Send a message to all nodes.
    async fn broadcast(&mut self, msg: Message<T, Validated>) -> Result<(), Self::Err>;

    /// Send a message to one node.
    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<(), Self::Err>;

    /// Await the next message.
    async fn receive(&mut self) -> Result<Message<T, Validated>, Self::Err>;

    /// Garbage collect up to the given round number.
    async fn gc(&mut self, _: RoundNumber) -> Result<(), Self::Err> {
        Ok(())
    }

    /// Add a set of peers.
    async fn add_committee(&mut self, _: Self::CommitteeInfo) -> Result<(), Self::Err> {
        Ok(())
    }

    /// Switch over to a set of peers.
    async fn use_committee(&mut self, _: Round) -> Result<(), Self::Err> {
        Ok(())
    }
}

#[async_trait]
impl<A: Committable + Send + 'static, T: Comm<A> + Send> Comm<A> for Box<T> {
    type Err = T::Err;
    type CommitteeInfo = T::CommitteeInfo;

    async fn broadcast(&mut self, msg: Message<A, Validated>) -> Result<(), Self::Err> {
        (**self).broadcast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Message<A, Validated>) -> Result<(), Self::Err> {
        (**self).send(to, msg).await
    }

    async fn receive(&mut self) -> Result<Message<A, Validated>, Self::Err> {
        (**self).receive().await
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommError<E> {
    #[error("network error: {0}")]
    Net(#[source] E),

    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("invalid message signature")]
    Invalid,
}

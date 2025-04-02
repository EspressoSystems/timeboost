use std::error::Error;

use async_trait::async_trait;
use bytes::Bytes;
use committable::Committable;
use multisig::{PublicKey, Validated};

use crate::{Message, RoundNumber};

/// Types that provide broadcast and 1:1 message communication.
#[async_trait]
pub trait Comm<T: Committable> {
    type Err: Error + Send + Sync + 'static;

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
}

/// Types that provide broadcast and 1:1 message communication.
///
/// In contrast to `Comm` this trait operates on raw byte vectors instead
/// of `Message`s.
#[async_trait]
pub trait RawComm {
    type Err: Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Bytes) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Bytes) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<(PublicKey, Bytes), Self::Err>;
}

#[async_trait]
impl<A: Committable + Send + 'static, T: Comm<A> + Send> Comm<A> for Box<T> {
    type Err = T::Err;

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

#[async_trait]
impl<T: RawComm + Send> RawComm for Box<T> {
    type Err = T::Err;

    async fn broadcast(&mut self, msg: Bytes) -> Result<(), Self::Err> {
        (**self).broadcast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Bytes) -> Result<(), Self::Err> {
        (**self).send(to, msg).await
    }

    async fn receive(&mut self) -> Result<(PublicKey, Bytes), Self::Err> {
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

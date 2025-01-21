use std::error::Error;

use crate::types::message::Message;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use multisig::{Committee, PublicKey, Unchecked, Validated};
use timeboost_networking::{Network, NetworkError};

/// Types that provide broadcast and 1:1 message communication.
#[async_trait]
pub trait Comm {
    type Err: Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err>;

    async fn shutdown(&mut self) -> Result<(), Self::Err>;
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

    async fn receive(&mut self) -> Result<Bytes, Self::Err>;

    async fn shutdown(&mut self) -> Result<(), Self::Err>;
}

#[async_trait]
impl<T: Comm + Send> Comm for Box<T> {
    type Err = T::Err;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        (**self).broadcast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        (**self).send(to, msg).await
    }

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err> {
        (**self).receive().await
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        (**self).shutdown().await
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

    async fn receive(&mut self) -> Result<Bytes, Self::Err> {
        (**self).receive().await
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        (**self).shutdown().await
    }
}

#[async_trait]
impl RawComm for Network {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Bytes) -> Result<(), Self::Err> {
        self.multicast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Bytes) -> Result<(), Self::Err> {
        self.unicast(to, msg).await
    }

    async fn receive(&mut self) -> Result<Bytes, Self::Err> {
        let (_, m) = self.receive().await?;
        Ok(m)
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        Ok(())
    }
}

/// An implementation of `Comm` that performs message validation.
#[derive(Debug)]
pub struct CheckedComm<R> {
    net: R,
    committee: Committee,
}

impl<R> CheckedComm<R> {
    pub fn new(net: R, c: Committee) -> Self {
        Self { net, committee: c }
    }
}

#[async_trait]
impl<R: RawComm + Send> Comm for CheckedComm<R> {
    type Err = CommError<R::Err>;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        let mut bytes = BytesMut::new().writer();
        bincode::serialize_into(&mut bytes, &msg)?;
        self.net
            .broadcast(bytes.into_inner().freeze())
            .await
            .map_err(CommError::Net)?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        let mut bytes = BytesMut::new().writer();
        bincode::serialize_into(&mut bytes, &msg)?;
        self.net
            .send(to, bytes.into_inner().freeze())
            .await
            .map_err(CommError::Net)?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err> {
        let bytes = self.net.receive().await.map_err(CommError::Net)?;
        let msg: Message<Unchecked> = bincode::deserialize(&bytes)?;
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(CommError::Invalid);
        };
        Ok(msg)
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        self.net.shutdown().await.map_err(CommError::Net)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommError<E> {
    #[error("network error: {0}")]
    Net(#[source] E),

    #[error("bincode error: {0}")]
    Bincode(#[from] bincode::Error),

    #[error("invalid message signature")]
    Invalid,
}

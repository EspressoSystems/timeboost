use std::error::Error;

use crate::types::committee::StaticCommittee;
use crate::types::envelope::{Unchecked, Validated};
use crate::types::message::Message;
use crate::types::PublicKey;
use async_trait::async_trait;
use hotshot::traits::NetworkError;
use hotshot_types::traits::network::Topic;
use timeboost_networking::network::client::Libp2pNetwork;

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

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err>;

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

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        (**self).broadcast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
        (**self).send(to, msg).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        (**self).receive().await
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        (**self).shutdown().await
    }
}

#[async_trait]
impl RawComm for Libp2pNetwork<PublicKey> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.broadcast_message(msg, Topic::Global).await
    }

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.direct_message(msg, to).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        self.recv_message().await
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        self.shut_down().await;
        Ok(())
    }
}

/// An implementation of `Comm` that performs message validation.
#[derive(Debug)]
pub struct CheckedComm<R> {
    net: R,
    committee: StaticCommittee,
}

impl<R> CheckedComm<R> {
    pub fn new(net: R, c: StaticCommittee) -> Self {
        Self { net, committee: c }
    }
}

#[async_trait]
impl<R: RawComm + Send> Comm for CheckedComm<R> {
    type Err = CommError<R::Err>;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        let bytes = bincode::serialize(&msg)?;
        self.net.broadcast(bytes).await.map_err(CommError::Net)?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        let bytes = bincode::serialize(&msg)?;
        self.net.send(to, bytes).await.map_err(CommError::Net)?;
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

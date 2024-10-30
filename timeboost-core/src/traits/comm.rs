use std::error::Error;

use async_trait::async_trait;
use hotshot::traits::{implementations::Libp2pNetwork, NetworkError};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};

use crate::types::PublicKey;

#[async_trait]
pub trait Comm {
    type Err: Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err>;
}

#[async_trait]
impl<T: Comm + Send> Comm for Box<T> {
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
}

#[async_trait]
impl Comm for Libp2pNetwork<PublicKey> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.broadcast_message(msg, Topic::Global, BroadcastDelay::None)
            .await
    }

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.direct_message(msg, to).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        self.recv_message().await
    }
}

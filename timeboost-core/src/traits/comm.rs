use std::error::Error;

use async_trait::async_trait;
use hotshot::traits::{implementations::Libp2pNetwork, NetworkError};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};

use crate::types::message::Message;
use crate::types::PublicKey;

#[async_trait]
pub trait Comm {
    type Err: Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Message) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Message) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Message, Self::Err>;
}

#[async_trait]
impl<T: Comm + Send> Comm for Box<T> {
    type Err = T::Err;

    async fn broadcast(&mut self, msg: Message) -> Result<(), Self::Err> {
        (**self).broadcast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Message) -> Result<(), Self::Err> {
        (**self).send(to, msg).await
    }

    async fn receive(&mut self) -> Result<Message, Self::Err> {
        (**self).receive().await
    }
}

#[async_trait]
impl Comm for Libp2pNetwork<PublicKey> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Message) -> Result<(), Self::Err> {
        let bytes =
            bincode::serialize(&msg).map_err(|e| NetworkError::FailedToSerialize(e.to_string()))?;

        self.broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
            .await
    }

    async fn send(&mut self, to: PublicKey, msg: Message) -> Result<(), Self::Err> {
        let bytes =
            bincode::serialize(&msg).map_err(|e| NetworkError::FailedToSerialize(e.to_string()))?;

        self.direct_message(bytes, to).await
    }

    async fn receive(&mut self) -> Result<Message, Self::Err> {
        let bytes = self.recv_message().await?;

        bincode::deserialize(&bytes).map_err(|e| NetworkError::FailedToDeserialize(e.to_string()))
    }
}

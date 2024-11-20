use std::error::Error;

use crate::types::message::Message;
use crate::types::PublicKey;
use async_trait::async_trait;
use hotshot::traits::NetworkError;
use hotshot_types::traits::network::Topic;
use timeboost_networking::network::client::Libp2pNetwork;
#[async_trait]
pub trait Comm {
    type Err: Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Message) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Message) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Message, Self::Err>;

    async fn start(&mut self) -> Result<(), Self::Err>;

    async fn shutdown(&mut self) -> Result<(), Self::Err>;
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

    async fn start(&mut self) -> Result<(), Self::Err> {
        (**self).start().await
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        (**self).shutdown().await
    }
}

#[async_trait]
impl Comm for Libp2pNetwork<PublicKey> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Message) -> Result<(), Self::Err> {
        let bytes =
            bincode::serialize(&msg).map_err(|e| NetworkError::FailedToSerialize(e.to_string()))?;

        self.broadcast_message(bytes, Topic::Global).await
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

    async fn start(&mut self) -> Result<(), Self::Err> {
        self.wait_for_ready().await;
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        self.shut_down().await;
        Ok(())
    }
}

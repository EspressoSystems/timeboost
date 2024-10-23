use async_trait::async_trait;
use hotshot::{
    traits::{implementations::Libp2pNetwork, NetworkError},
    types::SignatureKey,
};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};

#[async_trait]
pub trait Network {
    type Err: std::error::Error + Send + Sync + 'static;

    /// Broadcast a message to all peers.
    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err>;

    /// Receive a message from a peer.
    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err>;
}

#[async_trait]
impl<N: Network + Send + Sync + 'static> Network for Box<N> {
    type Err = N::Err;

    /// Broadcast a message to all peers.
    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        (**self).broadcast(msg).await
    }

    /// Receive a message from a peer.
    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        (**self).receive().await
    }
}

#[async_trait]
impl<K: SignatureKey> Network for Libp2pNetwork<K> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.broadcast_message(msg, Topic::Global, BroadcastDelay::None)
            .await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        self.recv_message().await
    }
}

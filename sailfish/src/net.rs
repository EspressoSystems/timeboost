use async_trait::async_trait;
use hotshot::{
    traits::{implementations::Libp2pNetwork, NetworkError},
    types::SignatureKey,
};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};
use tracing::warn;

#[async_trait]
pub trait Network {
    type Err: std::error::Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err>;

    async fn wait_for_ready(&mut self);
}

#[async_trait]
impl<T: Network + Send> Network for Box<T> {
    type Err = T::Err;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        (*self).broadcast(msg).await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        (*self).receive().await
    }

    async fn wait_for_ready(&mut self) {
        (*self).wait_for_ready().await
    }
}

#[async_trait]
impl<T: SignatureKey> Network for Libp2pNetwork<T> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.broadcast_message(msg, Topic::Global, BroadcastDelay::None)
            .await
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        self.recv_message().await
    }

    async fn wait_for_ready(&mut self) {
        self.wait_for_ready().await
    }
}

pub struct Endpoint<A, B = A> {
    tx: async_broadcast::Sender<A>,
    rx: async_broadcast::Receiver<B>,
}

pub fn channel<A, B>(cap: usize) -> (Endpoint<A, B>, Endpoint<B, A>) {
    let (tx_a, rx_a) = async_broadcast::broadcast(cap);
    let (tx_b, rx_b) = async_broadcast::broadcast(cap);
    (
        Endpoint { tx: tx_a, rx: rx_b },
        Endpoint { tx: tx_b, rx: rx_a },
    )
}

#[async_trait]
impl Network for Endpoint<Vec<u8>> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.tx
            .broadcast_direct(msg)
            .await
            .map(|_| warn!("broadcast channel overflow"))
            .map_err(|e| NetworkError::ChannelSendError(e.to_string()))
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        self.rx
            .recv()
            .await
            .map_err(|e| NetworkError::ChannelReceiveError(e.to_string()))
    }

    async fn wait_for_ready(&mut self) {}
}

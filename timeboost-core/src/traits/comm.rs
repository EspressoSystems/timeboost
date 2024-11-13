use std::error::Error;

use async_trait::async_trait;
use hotshot::traits::{implementations::Libp2pNetwork, NetworkError};
use hotshot_types::traits::network::{BroadcastDelay, ConnectedNetwork, Topic};

use crate::types::committee::StaticCommittee;
use crate::types::envelope::{Unchecked, Validated};
use crate::types::message::Message;
use crate::types::PublicKey;

#[async_trait]
pub trait Comm {
    type Err: Error + Send + Sync + 'static;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err>;

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err>;

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err>;
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
}

#[derive(Debug)]
pub struct Libp2p {
    net: Libp2pNetwork<PublicKey>,
    committee: StaticCommittee,
}

impl Libp2p {
    pub fn new(net: Libp2pNetwork<PublicKey>, c: StaticCommittee) -> Self {
        Self { net, committee: c }
    }
}

#[async_trait]
impl Comm for Libp2p {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        let bytes =
            bincode::serialize(&msg).map_err(|e| NetworkError::FailedToSerialize(e.to_string()))?;

        self.net
            .broadcast_message(bytes, Topic::Global, BroadcastDelay::None)
            .await
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        let bytes =
            bincode::serialize(&msg).map_err(|e| NetworkError::FailedToSerialize(e.to_string()))?;

        self.net.direct_message(bytes, to).await
    }

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err> {
        let bytes = self.net.recv_message().await?;
        let msg: Message<Unchecked> = bincode::deserialize(&bytes)
            .map_err(|e| NetworkError::FailedToDeserialize(e.to_string()))?;
        let Some(msg) = msg.validated(&self.committee) else {
            return Err(NetworkError::FailedToDeserialize(
                "invalid message signature".to_string(),
            ));
        };
        Ok(msg)
    }
}

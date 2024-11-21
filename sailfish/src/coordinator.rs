use std::{future::pending, time::Duration};

use crate::consensus::{Consensus, Dag};

use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        block::Block,
        message::{Action, Message},
        round_number::RoundNumber,
        NodeId, PublicKey,
    },
};
use tokio::time::sleep;
use tracing::warn;

pub struct Coordinator<C> {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    timer: BoxFuture<'static, RoundNumber>,

    init: bool,
}

impl<C: Comm> Coordinator<C> {
    pub fn new(id: NodeId, comm: C, cons: Consensus) -> Self {
        Self {
            id,
            comm,
            consensus: cons,
            timer: pending().boxed(),
            init: false,
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        if !self.init {
            self.init = true;
            return Ok(self.consensus.go(Dag::new(self.consensus.committee_size())));
        }

        tokio::select! { biased;
            vnr = &mut self.timer => Ok(self.consensus.timeout(vnr)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    pub async fn execute(&mut self, action: Action) -> Result<Option<Block>, C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
            }
            Action::Deliver(b, _, _) => return Ok(Some(b)),
            Action::SendProposal(e) => {
                self.broadcast(Message::Vertex(e.cast())).await;
            }
            Action::SendTimeout(e) => {
                self.broadcast(Message::Timeout(e.cast())).await;
            }
            Action::SendTimeoutCert(c) => {
                self.broadcast(Message::TimeoutCert(c)).await;
            }
            Action::SendNoVote(to, v) => {
                self.unicast(to, Message::NoVote(v.cast())).await;
            }
        }
        Ok(None)
    }

    pub async fn shutdown(&mut self) -> Result<(), C::Err> {
        self.comm.shutdown().await
    }

    async fn broadcast(&mut self, msg: Message) {
        if let Err(err) = self.comm.broadcast(msg).await {
            warn!(%err, "failed to broadcast message to network")
        }
    }

    async fn unicast(&mut self, to: PublicKey, msg: Message) {
        if let Err(err) = self.comm.send(to, msg).await {
            warn!(%err, %to, "failed to send message")
        }
    }
}

use std::{future::pending, time::Duration};

use crate::{
    consensus::{Consensus, Dag},
    sailfish::ShutdownToken,
};

use anyhow::Result;
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::{
    traits::comm::Comm,
    types::{
        block::Block,
        event::{SailfishStatusEvent, TimeboostStatusEvent},
        message::{Action, Message},
        round_number::RoundNumber,
        NodeId,
    },
};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::{
    sync::oneshot::{self},
    time::sleep,
};

pub struct Coordinator<C> {
    /// The node ID of this coordinator.
    id: NodeId,

    /// The communication channel for this coordinator.
    comm: C,

    /// The instance of Sailfish consensus for this coordinator.
    consensus: Consensus,

    timer: BoxFuture<'static, RoundNumber>,

    init: bool
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg(feature = "test")]
pub enum CoordinatorAuditEvent {
    ActionTaken(Action),
    MessageReceived(Message),
}

#[cfg(feature = "test")]
impl std::fmt::Display for CoordinatorAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionTaken(a) => write!(f, "Action taken: {a}"),
            Self::MessageReceived(m) => write!(f, "Message received: {m}"),
        }
    }
}

impl<C: Comm> Coordinator<C> {
    pub fn new(
        id: NodeId,
        comm: C,
        cons: Consensus,
        _shutdown_rx: oneshot::Receiver<ShutdownToken>,
        _sf_app_tx: Sender<SailfishStatusEvent>,
        _tb_app_rx: Receiver<TimeboostStatusEvent>,
    ) -> Self {
        Self {
            id,
            comm,
            consensus: cons,
            timer: pending().boxed(),
            init: false
        }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    #[cfg(feature = "test")]
    pub fn consensus(&self) -> &Consensus {
        &self.consensus
    }

    #[cfg(feature = "test")]
    pub async fn append_test_event(&mut self, _event: CoordinatorAuditEvent) {
    }

    //async fn test_example(c: C) {
    //    use timeboost_core::types::test::testnet::TestNet;
    //
    //    let mut net = TestNet::new(c);
    //    let messages = net.messages();
    //
    //    let mut coord: Coordinator<C>; // TODO: Coordinator::new(..., net, ...);
    //
    //    loop {
    //        match coord.next().await {
    //            Ok(actions) => {
    //                let _inbox = messages.drain_inbox();
    //
    //                // test(inbox, actions) ok?
    //
    //                for a in &actions {
    //                    let _ = coord.exec(a.clone()).await; // optional: handle delivered blocks
    //                }
    //
    //                let _outbox = messages.drain_outbox();
    //
    //                // test(actions, outbox) ok?
    //            }
    //            Err(_err) => {
    //                todo!()
    //            }
    //        }
    //    }
    //}

    //async fn prod_example<T: Comm + Send + 'static>(_: T) {
    //    let mut coord: Coordinator<T>; // TODO: Coordinator::new(..., net, ...);
    //
    //    let handle = tokio::spawn(async move {
    //        loop {
    //            match coord.next().await {
    //                Ok(actions) => {
    //                    for a in actions {
    //                        match coord.exec(a).await {
    //                            Ok(Some(_block)) => todo!(),
    //                            Ok(None) => {}
    //                            Err(_err) => {
    //                                todo!()
    //                            }
    //                        }
    //                    }
    //                }
    //                Err(_err) => {
    //                    todo!()
    //                }
    //            }
    //        }
    //    });
    //}

    pub async fn next(&mut self) -> Result<Vec<Action>, C::Err> {
        if !self.init {
            self.init = true;
            return Ok(self.consensus.go(Dag::new(self.consensus.committee_size())))
        }

        tokio::select! { biased;
            vnr = &mut self.timer => Ok(self.consensus.timeout(vnr)),
            msg = self.comm.receive() => Ok(self.consensus.handle_message(msg?)),
        }
    }

    pub async fn exec(&mut self, action: Action) -> Result<Option<Block>, C::Err> {
        match action {
            Action::ResetTimer(r) => {
                self.timer = sleep(Duration::from_secs(4)).map(move |_| r).fuse().boxed();
            }
            Action::Deliver(b, _, _) => {
                return Ok(Some(b))
            }
            Action::SendProposal(e) => {
                self.comm.broadcast(Message::Vertex(e.cast())).await?;
            }
            Action::SendTimeout(e) => {
                self.comm.broadcast(Message::Timeout(e.cast())).await?;
            }
            Action::SendTimeoutCert(c) => {
                self.comm.broadcast(Message::TimeoutCert(c)).await?;
            }
            Action::SendNoVote(to, v) => {
                self.comm.send(to, Message::NoVote(v.cast())).await?;
            }
        }
        Ok(None)
    }

    pub async fn go(self) -> ShutdownToken {
        todo!("remove this method")
    }
}

use std::sync::Arc;

use crate::{consensus::Consensus, sailfish::ShutdownToken};

use async_lock::RwLock;
use timeboost_core::{
    traits::comm::Comm,
    types::{
        event::{SailfishStatusEvent, TimeboostStatusEvent},
        message::{Action, Message},
        NodeId,
    },
};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot::{self};

use super::{coordinator::Coordinator, interceptor::NetworkMessageInterceptor};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CoordinatorAuditEvent {
    ActionTaken(Action),
    MessageReceived(Message),
}

impl std::fmt::Display for CoordinatorAuditEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActionTaken(a) => write!(f, "Action taken: {a}"),
            Self::MessageReceived(m) => write!(f, "Message received: {m}"),
        }
    }
}

pub struct TestCoordinator<C> {
    coordinator: Coordinator<C>,
    event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
    interceptor: Arc<NetworkMessageInterceptor>,
}

#[allow(clippy::too_many_arguments)]
impl<C: Comm + 'static> TestCoordinator<C> {
    pub fn new(
        id: NodeId,
        comm: C,
        cons: Consensus,
        shutdown_rx: oneshot::Receiver<ShutdownToken>,
        sf_app_tx: Sender<SailfishStatusEvent>,
        tb_app_rx: Receiver<TimeboostStatusEvent>,
        event_log: Option<Arc<RwLock<Vec<CoordinatorAuditEvent>>>>,
        interceptor: Arc<NetworkMessageInterceptor>,
    ) -> Self {
        let coordinator = Coordinator::new(id, comm, cons, shutdown_rx, sf_app_tx, tb_app_rx);
        Self {
            coordinator,
            event_log,
            interceptor: Arc::clone(&interceptor.clone()),
        }
    }

    pub async fn go(self) -> ShutdownToken {
        self.coordinator
            .go_test(&mut self.event_log.unwrap(), self.interceptor)
            .await
    }
}

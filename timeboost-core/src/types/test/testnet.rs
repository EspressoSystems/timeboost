use std::sync::Arc;

use async_trait::async_trait;
use crossbeam_queue::SegQueue;
use multisig::{PublicKey, Validated};

use crate::traits::comm::Comm;
use crate::types::message::Message;

use super::message_interceptor::NetworkMessageInterceptor;

#[derive(Debug, Clone)]
pub struct MsgQueues {
    ibox: Arc<SegQueue<Message>>,
    obox: Arc<SegQueue<(Option<PublicKey>, Message)>>,
}

/// Go through the messages inbound and outbound that we received / sent
impl MsgQueues {
    pub fn drain_inbox(&self) -> Vec<Message> {
        let mut v = Vec::new();
        while let Some(m) = self.ibox.pop() {
            v.push(m)
        }
        v
    }

    pub fn drain_outbox(&self) -> Vec<(Option<PublicKey>, Message)> {
        let mut v = Vec::new();
        while let Some(m) = self.obox.pop() {
            v.push(m)
        }
        v
    }
}

/// Create a test net over `Comm` trait so we are able to save messages as they come in
/// This helps us with networking tests and we can then interact and write tests in a way
/// Where we do not have to modify anything inside of `Coordinator` itself
#[derive(Debug)]
pub struct TestNet<C> {
    comm: C,
    msgs: MsgQueues,
    id: u64,
    interceptor: NetworkMessageInterceptor,
}

impl<C: Comm> TestNet<C> {
    pub fn new(comm: C, id: u64, interceptor: NetworkMessageInterceptor) -> Self {
        Self {
            comm,
            msgs: MsgQueues {
                ibox: Arc::new(SegQueue::new()),
                obox: Arc::new(SegQueue::new()),
            },
            id,
            interceptor,
        }
    }

    pub fn messages(&self) -> MsgQueues {
        self.msgs.clone()
    }
}

/// Wrap Comm Err into `TestNetError`
#[derive(Debug)]
pub enum TestNetError<C: Comm> {
    RecvError(C::Err),
    SendError(C::Err),
    BroadcastError(C::Err),
    InterceptError(String),
}

impl<C: Comm + Send> std::fmt::Display for TestNetError<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestNetError::RecvError(err) => write!(f, "receive Error: {}", err),
            TestNetError::SendError(err) => write!(f, "send Error: {}", err),
            TestNetError::BroadcastError(err) => write!(f, "broadcast Error: {}", err),
            TestNetError::InterceptError(err) => write!(f, "intercept Error: {}", err),
        }
    }
}

impl<C: Comm + std::fmt::Debug + Send> std::error::Error for TestNetError<C> {}

#[async_trait]
impl<C> Comm for TestNet<C>
where
    C: Comm + Send + std::fmt::Debug + 'static,
{
    type Err = TestNetError<C>;

    async fn broadcast(&mut self, msg: Message<Validated>) -> Result<(), Self::Err> {
        self.msgs.obox.push((None, msg.clone()));
        if let Err(e) = self.comm.broadcast(msg).await {
            return Err(TestNetError::BroadcastError(e));
        }
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<Validated>) -> Result<(), Self::Err> {
        self.msgs.obox.push((Some(to), msg.clone()));
        if let Err(e) = self.comm.send(to, msg).await {
            return Err(TestNetError::SendError(e));
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<Validated>, Self::Err> {
        match self.comm.receive().await {
            Ok(msg) => match self.interceptor.intercept_message(msg, self.id) {
                Ok(m) => {
                    self.msgs.ibox.push(m.clone());
                    return Ok(m);
                }
                Err(e) => {
                    return Err(TestNetError::InterceptError(e));
                }
            },
            Err(e) => {
                return Err(TestNetError::RecvError(e));
            }
        }
    }
}

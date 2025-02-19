use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use crossbeam_queue::SegQueue;
use multisig::{PublicKey, Validated};

use sailfish_types::{Comm, Message};

use super::message_interceptor::NetworkMessageInterceptor;

#[derive(Debug)]
pub struct MsgQueues<B> {
    ibox: Arc<SegQueue<Message<B>>>,
    obox: Arc<SegQueue<(Option<PublicKey>, Message<B>)>>,
}

impl<B> Clone for MsgQueues<B> {
    fn clone(&self) -> Self {
        Self { ibox: self.ibox.clone(), obox: self.obox.clone() }
    }
}

/// Go through the messages inbound and outbound that we received / sent
impl<B> MsgQueues<B> {
    pub fn drain_inbox(&self) -> Vec<Message<B>> {
        let mut v = Vec::new();
        while let Some(m) = self.ibox.pop() {
            v.push(m)
        }
        v
    }

    pub fn drain_outbox(&self) -> Vec<(Option<PublicKey>, Message<B>)> {
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
pub struct TestNet<B, C> {
    comm: C,
    msgs: MsgQueues<B>,
    id: u64,
    interceptor: NetworkMessageInterceptor<B>,
}

impl<B, C: Comm<B>> TestNet<B, C> {
    pub fn new(comm: C, id: u64, interceptor: NetworkMessageInterceptor<B>) -> Self {
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

    pub fn messages(&self) -> MsgQueues<B> {
        self.msgs.clone()
    }
}

/// Wrap Comm Err into `TestNetError`
#[derive(Debug)]
pub enum TestNetError<B, C: Comm<B>> {
    RecvError(C::Err),
    SendError(C::Err),
    BroadcastError(C::Err),
    InterceptError(String),
}

impl<B: Send, C: Comm<B> + Send> std::fmt::Display for TestNetError<B, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestNetError::RecvError(err) => write!(f, "receive Error: {}", err),
            TestNetError::SendError(err) => write!(f, "send Error: {}", err),
            TestNetError::BroadcastError(err) => write!(f, "broadcast Error: {}", err),
            TestNetError::InterceptError(err) => write!(f, "intercept Error: {}", err),
        }
    }
}

impl<B: Debug + Send, C: Comm<B> + Debug + Send> std::error::Error for TestNetError<B, C> {}

#[async_trait]
impl<B, C> Comm<B> for TestNet<B, C>
where
    B: Clone + std::fmt::Debug + Send + 'static,
    C: Comm<B> + Send + std::fmt::Debug + 'static,
{
    type Err = TestNetError<B, C>;

    async fn broadcast(&mut self, msg: Message<B, Validated>) -> Result<(), Self::Err> {
        self.msgs.obox.push((None, msg.clone()));
        if let Err(e) = self.comm.broadcast(msg).await {
            return Err(TestNetError::BroadcastError(e));
        }
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<B, Validated>) -> Result<(), Self::Err> {
        self.msgs.obox.push((Some(to), msg.clone()));
        if let Err(e) = self.comm.send(to, msg).await {
            return Err(TestNetError::SendError(e));
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<B, Validated>, Self::Err> {
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

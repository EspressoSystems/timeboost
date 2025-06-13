use std::fmt::Debug;
use std::future::{Ready, ready};
use std::sync::Arc;

use async_trait::async_trait;
use committable::Committable;
use crossbeam_queue::SegQueue;
use multisig::{PublicKey, Validated};

use sailfish_types::{Comm, Empty, Message};

use super::message_interceptor::NetworkMessageInterceptor;

#[derive(Debug)]
pub struct MsgQueues<T: Committable> {
    ibox: Arc<SegQueue<Message<T>>>,
    obox: Arc<SegQueue<(Option<PublicKey>, Message<T>)>>,
}

impl<T: Committable> Clone for MsgQueues<T> {
    fn clone(&self) -> Self {
        Self {
            ibox: self.ibox.clone(),
            obox: self.obox.clone(),
        }
    }
}

/// Go through the messages inbound and outbound that we received / sent
impl<T: Committable> MsgQueues<T> {
    pub fn drain_inbox(&self) -> Vec<Message<T>> {
        let mut v = Vec::new();
        while let Some(m) = self.ibox.pop() {
            v.push(m)
        }
        v
    }

    #[allow(dead_code)]
    pub fn drain_outbox(&self) -> Vec<(Option<PublicKey>, Message<T>)> {
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
pub struct TestNet<T: Committable, C> {
    comm: C,
    msgs: MsgQueues<T>,
    id: u64,
    interceptor: NetworkMessageInterceptor<T>,
}

impl<T: Committable, C: Comm<T>> TestNet<T, C> {
    pub fn new(comm: C, id: u64, interceptor: NetworkMessageInterceptor<T>) -> Self {
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

    pub fn messages(&self) -> MsgQueues<T> {
        self.msgs.clone()
    }
}

/// Wrap Comm Err into `TestNetError`
#[derive(Debug)]
pub enum TestNetError<T: Committable, C: Comm<T>> {
    Recv(C::Err),
    Send(C::Err),
    Broadcast(C::Err),
    Intercept(String),
}

impl<T: Committable + Send, C: Comm<T> + Send> std::fmt::Display for TestNetError<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestNetError::Recv(err) => write!(f, "receive Error: {}", err),
            TestNetError::Send(err) => write!(f, "send Error: {}", err),
            TestNetError::Broadcast(err) => write!(f, "broadcast Error: {}", err),
            TestNetError::Intercept(err) => write!(f, "intercept Error: {}", err),
        }
    }
}

impl<T: Committable + Debug + Send, C: Comm<T> + Debug + Send> std::error::Error
    for TestNetError<T, C>
{
}

#[async_trait]
impl<T, C> Comm<T> for TestNet<T, C>
where
    T: Committable + Clone + std::fmt::Debug + Send + 'static,
    C: Comm<T> + Send + std::fmt::Debug + 'static,
{
    type Err = TestNetError<T, C>;
    type CommitteeInfo = Empty;
    type Sync = Ready<bool>;

    async fn broadcast(&mut self, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        self.msgs.obox.push((None, msg.clone()));
        if let Err(e) = self.comm.broadcast(msg).await {
            return Err(TestNetError::Broadcast(e));
        }
        Ok(())
    }

    async fn broadcast_sync(
        &mut self,
        msg: Message<T, Validated>,
    ) -> Result<Self::Sync, Self::Err> {
        self.broadcast(msg).await?;
        Ok(ready(true))
    }

    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        self.msgs.obox.push((Some(to), msg.clone()));
        if let Err(e) = self.comm.send(to, msg).await {
            return Err(TestNetError::Send(e));
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Message<T, Validated>, Self::Err> {
        match self.comm.receive().await {
            Ok(msg) => match self.interceptor.intercept_message(msg, self.id) {
                Ok(m) => {
                    self.msgs.ibox.push(m.clone());
                    return Ok(m);
                }
                Err(e) => {
                    return Err(TestNetError::Intercept(e));
                }
            },
            Err(e) => {
                return Err(TestNetError::Recv(e));
            }
        }
    }
}

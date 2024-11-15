use std::sync::Arc;

use async_trait::async_trait;
use crossbeam_queue::SegQueue;

use crate::traits::comm::Comm;
use crate::types::message::Message;
use crate::types::PublicKey;

#[derive(Debug, Clone)]
pub struct MsgQueues {
    ibox: Arc<SegQueue<Message>>,
    obox: Arc<SegQueue<(Option<PublicKey>, Message)>>,
}

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

#[derive(Debug)]
pub struct TestNet<C> {
    comm: C,
    msgs: MsgQueues,
}

impl<C: Comm> TestNet<C> {
    pub fn new(comm: C) -> Self {
        Self {
            comm,
            msgs: MsgQueues {
                ibox: Arc::new(SegQueue::new()),
                obox: Arc::new(SegQueue::new()),
            },
        }
    }

    pub fn messages(&self) -> MsgQueues {
        self.msgs.clone()
    }
}

#[async_trait]
impl<C: Comm + Send> Comm for TestNet<C> {
    type Err = C::Err;

    async fn broadcast(&mut self, msg: Message) -> Result<(), Self::Err> {
        self.msgs.obox.push((None, msg.clone()));
        self.comm.broadcast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Message) -> Result<(), Self::Err> {
        self.msgs.obox.push((Some(to), msg.clone()));
        self.comm.send(to, msg).await
    }

    async fn receive(&mut self) -> Result<Message, Self::Err> {
        let msg = self.comm.receive().await?;
        self.msgs.ibox.push(msg.clone());
        Ok(msg)
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        self.comm.shutdown().await
    }
}

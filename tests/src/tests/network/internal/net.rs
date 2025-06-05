use std::collections::HashMap;
use std::{io, iter};

use async_trait::async_trait;
use committable::Committable;
use multisig::{PublicKey, Validated};
use sailfish_types::{Comm, Empty, Message};
use tokio::sync::mpsc;
use tracing::warn;

/// Network with star topology.
///
/// Every `Conn` is connected to `Star` and messages are send to `Star` which
/// dispatches them to all connected `Conn` endpoints, or to specific ones.
#[derive(Debug)]
pub struct Star<T: Clone> {
    inbound: mpsc::UnboundedReceiver<Event<T>>,
    outbound: mpsc::UnboundedSender<Event<T>>,
    members: HashMap<PublicKey, mpsc::UnboundedSender<T>>,
}

/// A single network connection.
#[derive(Debug)]
pub struct Conn<T> {
    id: PublicKey,
    tx: mpsc::UnboundedSender<Event<T>>,
    rx: mpsc::UnboundedReceiver<T>,
}

/// A network event.
#[derive(Clone, Debug)]
pub enum Event<T> {
    Unicast {
        src: PublicKey,
        dest: PublicKey,
        data: T,
    },
    Multicast {
        src: PublicKey,
        data: T,
    },
}

impl<T> Event<T> {
    pub fn source(&self) -> &PublicKey {
        match self {
            Self::Unicast { src, .. } => src,
            Self::Multicast { src, .. } => src,
        }
    }

    pub fn data(&self) -> &T {
        match self {
            Self::Unicast { data, .. } => data,
            Self::Multicast { data, .. } => data,
        }
    }

    pub fn into_data(self) -> T {
        match self {
            Self::Unicast { data, .. } => data,
            Self::Multicast { data, .. } => data,
        }
    }
}

impl<T: Clone> Star<T> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            inbound: rx,
            outbound: tx,
            members: HashMap::new(),
        }
    }

    pub fn join(&mut self, id: PublicKey) -> Conn<T> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.members.insert(id, tx);
        Conn {
            id,
            tx: self.outbound.clone(),
            rx,
        }
    }

    pub fn leave(&mut self, id: PublicKey, _: Conn<T>) -> bool {
        self.members.remove(&id).is_some()
    }

    pub async fn recv(&mut self) -> Event<T> {
        self.inbound
            .recv()
            .await
            .expect("sender and receiver have equal lifetimes")
    }

    pub fn send(&mut self, to: PublicKey, msg: T) -> Result<(), T> {
        if let Some(tx) = self.members.get(&to) {
            if let Err(e) = tx.send(msg) {
                self.members.remove(&to);
                return Err(e.0);
            }
            return Ok(());
        }
        Err(msg)
    }

    pub fn events(&mut self) -> impl Iterator<Item = Event<T>> + '_ {
        iter::from_fn(|| self.inbound.try_recv().ok())
    }

    pub async fn run(mut self) {
        loop {
            match self.inbound.recv().await {
                Some(event) => match event {
                    Event::Unicast { dest, data, .. } => {
                        let tx = self.members.get_mut(&dest).unwrap();
                        tx.send(data).unwrap();
                    }
                    Event::Multicast { data, .. } => {
                        for (_, tx) in self.members.iter_mut() {
                            if let Err(e) = tx.send(data.clone()) {
                                warn!("Failed to send message to member: {:?}", e);
                            }
                        }
                    }
                },
                None => {
                    tracing::warn!("star channel closed");
                    return;
                }
            }
        }
    }
}

impl<T: Clone> Star<T> {
    pub fn broadcast(&mut self, msg: T) {
        let mut to_remove = Vec::new();
        for (id, tx) in &mut self.members {
            if tx.send(msg.clone()).is_err() {
                to_remove.push(*id)
            }
        }
        for id in to_remove {
            self.members.remove(&id);
        }
    }
}

#[async_trait]
impl<T: Committable + Clone + Send> Comm<T> for Star<Message<T, Validated>> {
    type Err = io::Error;
    type AddrInfo = Empty;

    async fn broadcast(&mut self, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        self.broadcast(msg);
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        self.send(to, msg)
            .map_err(|_| io::Error::other("Star network failed to send"))
    }

    async fn receive(&mut self) -> Result<Message<T, Validated>, Self::Err> {
        Ok(self.recv().await.data().clone())
    }
}

impl<T: Clone> Default for Star<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<T: Committable + Clone + Send> Comm<T> for Conn<Message<T, Validated>> {
    type Err = io::Error;
    type AddrInfo = Empty;

    async fn broadcast(&mut self, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        let e = Event::Multicast {
            src: self.id,
            data: msg,
        };
        self.tx
            .send(e)
            .map_err(|_| io::Error::other("Comm: failed to broadcast"))
    }

    async fn send(&mut self, to: PublicKey, msg: Message<T, Validated>) -> Result<(), Self::Err> {
        let e = Event::Unicast {
            src: self.id,
            dest: to,
            data: msg,
        };
        self.tx
            .send(e)
            .map_err(|_| io::Error::other("Comm: failed to send"))
    }

    async fn receive(&mut self) -> Result<Message<T, Validated>, Self::Err> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| io::ErrorKind::ConnectionAborted.into())
    }
}

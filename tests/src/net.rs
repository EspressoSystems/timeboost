use std::collections::HashMap;
use std::iter;

use async_trait::async_trait;
use hotshot::traits::NetworkError;
use sailfish::types::{comm::Comm, PublicKey};
use tokio::sync::mpsc;

/// Network with star topology.
///
/// Every `Conn` is connected to `Star` and messages are send to `Star` which
/// dispatches them to all connected `Conn` endpoints, or to specific ones.
#[derive(Debug)]
pub struct Star<T> {
    inbound: mpsc::UnboundedReceiver<Event<T>>,
    outbound: mpsc::UnboundedSender<Event<T>>,
    members: HashMap<PublicKey, mpsc::UnboundedSender<T>>
}

/// A single network connection.
#[derive(Debug)]
pub struct Conn<T> {
    id: PublicKey,
    tx: mpsc::UnboundedSender<Event<T>>,
    rx: mpsc::UnboundedReceiver<T>
}

/// A network event.
#[derive(Debug)]
pub enum Event<T> {
    Unicast {
        src: PublicKey,
        dest: PublicKey,
        data: T
    },
    Multicast {
        src: PublicKey,
        data: T
    }
}

impl<T> Event<T> {
    pub fn source(&self) -> &PublicKey {
        match self {
            Self::Unicast { src, .. } => src,
            Self::Multicast { src, .. } => src
        }
    }

    pub fn data(&self) -> &T {
        match self {
            Self::Unicast { data, .. } => data,
            Self::Multicast { data, .. } => data
        }
    }

    pub fn into_data(self) -> T {
        match self {
            Self::Unicast { data, .. } => data,
            Self::Multicast { data, .. } => data
        }
    }
}

impl<T> Star<T> {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            inbound: rx,
            outbound: tx,
            members: HashMap::new()
        }
    }

    pub fn join(&mut self, id: PublicKey) -> Conn<T> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.members.insert(id.clone(), tx);
        Conn { id, tx: self.outbound.clone(), rx }
    }

    pub fn leave(&mut self, id: PublicKey, _: Conn<T>) -> bool {
        self.members.remove(&id).is_some()
    }

    pub async fn recv(&mut self) -> Event<T> {
        self.inbound.recv().await.expect("sender and receiver have equal lifetimes")
    }

    pub fn send(&mut self, to: PublicKey, msg: T) -> Result<(), T> {
        if let Some(tx) = self.members.get(&to) {
            if let Err(e) = tx.send(msg) {
                self.members.remove(&to);
                return Err(e.0)
            }
            return Ok(())
        }
        Err(msg)
    }

    pub fn events(&mut self) -> impl Iterator<Item = Event<T>> + '_ {
        iter::from_fn(|| self.inbound.try_recv().ok())
    }
}

impl<T: Clone> Star<T> {
    pub fn broadcast(&mut self, msg: T) {
        let mut to_remove = Vec::new();
        for (id, tx) in &mut self.members {
            if tx.send(msg.clone()).is_err() {
                to_remove.push(id.clone())
            }
        }
        for id in to_remove {
            self.members.remove(&id);
        }
    }
}

#[async_trait]
impl Comm for Conn<Vec<u8>> {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        let e = Event::Multicast { src: self.id.clone(), data: msg };
        self.tx.send(e).map_err(|e| NetworkError::ChannelSendError(e.to_string()))
    }

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
        let e = Event::Unicast { src: self.id.clone(), dest: to, data: msg };
        self.tx.send(e).map_err(|e| NetworkError::ChannelSendError(e.to_string()))
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        self.rx.recv().await.ok_or_else(|| NetworkError::ChannelReceiveError("channel closed".to_string()))
    }
}

// const BUFSIZE: usize = 32;

// #[derive(Debug)]
// pub struct Conn<T> {
//     tx: mpsc::Sender<T>,
//     rx: mpsc::UnboundedReceiver<T>
// }

// impl<T> Conn<T> {
//     pub async fn send(&mut self, msg: T) -> Result<(), T> {
//         self.tx.send(msg).await.map_err(|e| e.0)
//     }

//     pub async fn recv(&mut self) -> Option<T> {
//         self.rx.recv().await
//     }
// }

// #[derive(Debug)]
// pub struct Group<T> {
//     inbound: mpsc::Receiver<T>,
//     outbound: mpsc::Sender<T>,
//     members: HashMap<PublicKey, mpsc::UnboundedSender<T>>
// }

// impl<T: Clone> Group<T> {
//     pub fn new() -> Self {
//         let (tx, rx) = mpsc::channel(BUFSIZE);
//         Self {
//             inbound: rx,
//             outbound: tx,
//             members: HashMap::new()
//         }
//     }

//     pub fn join(&mut self, id: PublicKey) -> Conn<T> {
//         let (tx, rx) = mpsc::unbounded_channel();
//         self.members.insert(id, tx);
//         Conn { tx: self.outbound.clone(), rx }
//     }

//     pub fn leave(&mut self, id: PublicKey, _: Conn<T>) -> bool {
//         self.members.remove(&id).is_some()
//     }

//    pub async fn typed_broadcast(&mut self, msg: T) {
//         let mut to_remove = Vec::new();
//         for (id, tx) in &mut self.members {
//             if tx.send(msg.clone()).is_err() {
//                 to_remove.push(id.clone())
//             }
//         }
//         for id in to_remove {
//             self.members.remove(&id);
//         }
//     }

//     pub async fn typed_send(&mut self, to: PublicKey, msg: T) -> Result<(), T> {
//         if let Some(tx) = self.members.get(&to) {
//             if let Err(e) = tx.send(msg) {
//                 self.members.remove(&to);
//                 return Err(e.0)
//             }
//             return Ok(())
//         }
//         Err(msg)
//     }

//     pub async fn typed_receive(&mut self) -> T {
//         self.inbound.recv().await.expect("receiver lives as long as the sender")
//     }
// }

// #[async_trait]
// impl Comm for Group<Vec<u8>> {
//     type Err = NetworkError;

//     async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
//         let mut to_remove = Vec::new();
//         for (id, tx) in &mut self.members {
//             if tx.send(msg.clone()).is_err() {
//                 to_remove.push(id.clone())
//             }
//         }
//         for id in to_remove {
//             self.members.remove(&id);
//         }
//         Ok(())
//     }

//     async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
//         let mut remove = false;
//         if let Some(tx) = self.members.get(&to) {
//             if tx.send(msg).is_err() {
//                 remove = true
//             }
//         }
//         if remove {
//             self.members.remove(&to);
//         }
//         Ok(())
//     }

//     async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
//         let m = self.inbound.recv().await.expect("receiver lives as long as the sender");
//         Ok(m)
//     }
// }

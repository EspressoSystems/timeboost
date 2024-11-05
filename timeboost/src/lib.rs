use async_broadcast::{broadcast, Receiver, Sender};
use libp2p_networking::reexport::Multiaddr;
use sailfish::sailfish::Sailfish;

use timeboost_core::types::{message::Action, Keypair, NodeId};

pub struct EventStream {
    #[allow(unused)]
    sender: Sender<Action>,

    #[allow(unused)]
    receiver: Receiver<Action>,
}

impl EventStream {
    pub fn new(size: usize) -> Self {
        let (sender, receiver) = broadcast(size);
        Self { sender, receiver }
    }
}

pub struct Timeboost {
    #[allow(unused)]
    id: NodeId,

    #[allow(unused)]
    sailfish: Sailfish,

    #[allow(unused)]
    event_stream: EventStream,
}

impl Timeboost {
    pub fn new(id: NodeId, kpair: Keypair, bind: Multiaddr) -> Self {
        Self {
            id,
            sailfish: Sailfish::new(id, kpair, bind).expect("Failed to create Sailfish instance"),
            event_stream: EventStream::new(100),
        }
    }
}

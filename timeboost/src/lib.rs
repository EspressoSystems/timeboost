use async_broadcast::{broadcast, Receiver, Sender};
use libp2p_networking::reexport::Multiaddr;
use sailfish::sailfish::Sailfish;

use timeboost_core::types::{message::Action, NodeId, PrivateKey, PublicKey};

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
    pub fn new(
        id: NodeId,
        public_key: PublicKey,
        private_key: PrivateKey,
        bind_addr: Multiaddr,
    ) -> Self {
        Self {
            id,
            sailfish: Sailfish::new(id, public_key, private_key, bind_addr)
                .expect("Failed to create Sailfish instance"),
            event_stream: EventStream::new(100),
        }
    }
}

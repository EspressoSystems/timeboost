use anyhow::Result;
use std::collections::HashSet;
use tokio::signal;
use tracing::{info, warn};

use async_broadcast::{broadcast, Receiver, Sender};

use hotshot_types::PeerConfig;
use multiaddr::{Multiaddr, PeerId};
use sailfish::sailfish::run_sailfish;
use timeboost_core::types::{event::SailfishStatusEvent, Keypair, NodeId, PublicKey};

pub mod config;
pub mod contracts;

pub struct EventStream {
    #[allow(unused)]
    sender: Sender<SailfishStatusEvent>,

    #[allow(unused)]
    receiver: Receiver<SailfishStatusEvent>,
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
    port: u16,

    event_stream: EventStream,
}

impl Timeboost {
    pub fn new(id: NodeId, port: u16, event_stream: EventStream) -> Self {
        Self {
            id,
            port,
            event_stream,
        }
    }

    pub async fn go(mut self) -> Result<()> {
        tokio::select! {
            event = self.event_stream.receiver.recv() => {
                info!("Received event: {:?}", event);
            }
            _ = signal::ctrl_c() => {
                warn!("Received termination signal, shutting down...");
            }
        }

        Ok(())
    }
}

pub async fn run_timeboost(
    id: NodeId,
    port: u16,
    bootstrap_nodes: HashSet<(PeerId, Multiaddr)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: Multiaddr,
) -> Result<()> {
    info!("Starting timeboost");
    let es = EventStream::new(100);

    // First, initialize and run the sailfish node.
    // TODO: Hand the event stream to the sailfish node.
    tokio::spawn(async move {
        run_sailfish(id, bootstrap_nodes, staked_nodes, keypair, bind_address).await
    });

    // Then, initialize and run the timeboost node.
    let timeboost = Timeboost::new(id, port, es);

    info!("Timeboost is running.");
    timeboost.go().await
}

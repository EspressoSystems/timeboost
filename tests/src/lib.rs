use std::sync::Arc;

use async_lock::RwLock;
use hotshot_types::{PeerConfig, ValidatorConfig};
use libp2p_identity::PeerId;
use multiaddr::{multiaddr, Multiaddr};
use sailfish::{
    consensus::ConsensusState,
    coordinator::Coordinator,
    sailfish::{Sailfish, SailfishConfigBuilder},
};
use timeboost_core::types::{
    committee::StaticCommittee,
    message::Message,
    metrics::ConsensusMetrics,
    test::net::{Conn, Star},
    Keypair, NodeId, PublicKey,
};
use timeboost_networking::backbone::client::derive_libp2p_peer_id;
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bench;

pub struct Group {
    pub fish: Vec<Coordinator<Conn<Message>>>,
    pub bootstrap_nodes: Arc<RwLock<Vec<(PeerId, Multiaddr)>>>,
    pub staked_nodes: Arc<Vec<PeerConfig<PublicKey>>>,
    pub net: Star<Message>,
}

impl Group {
    pub fn new(size: u16) -> Self {
        let mut nodes = vec![];
        let mut peer_ids = vec![];
        let mut bind_addrs = vec![];

        let vcgfs = (0..size)
            .map(|i| {
                ValidatorConfig::generated_from_seed_indexed(Keypair::ZERO_SEED, i as u64, 1, false)
            })
            .collect::<Vec<_>>();
        let staked_nodes: Vec<PeerConfig<PublicKey>> =
            vcgfs.iter().map(|c| c.public_config()).collect();
        let committee = StaticCommittee::new(
            staked_nodes
                .iter()
                .map(|c| c.stake_table_entry.stake_key)
                .collect::<Vec<_>>(),
        );

        let mut net = Star::new();
        for i in 0..size {
            let kpr = Keypair::zero(i as u64);

            let (sf_app_tx, sf_app_rx) = mpsc::channel(10000);
            let (tb_app_tx, tb_app_rx) = mpsc::channel(10000);

            let id = NodeId::from(i as u64);
            let metrics = Arc::new(ConsensusMetrics::default());
            let ch = net.join(kpr.public_key().clone());
            let state = ConsensusState::new(&committee);

            // Construct a partial SailfishConfig.
            let sailfish = SailfishConfigBuilder::default()
                .id(id)
                .keypair(kpr)
                .app_tx(sf_app_tx)
                .app_rx(tb_app_rx)
                .metrics(metrics)
                .net(ch)
                .state(state)
                .committee(committee.clone())
                .build()
                .expect("failed to build SailfishConfig")
                .build()
                .expect("failed to init Coordinator");

            peer_ids.push(derive_libp2p_peer_id::<PublicKey>(kpr.private_key()).unwrap());
            bind_addrs.push(multiaddr!(Ip4([0, 0, 0, 0]), Tcp(8000 + i)));

            nodes.push(sailfish);
        }

        let bootstrap_nodes: Vec<(PeerId, Multiaddr)> = peer_ids
            .iter()
            .zip(bind_addrs.iter())
            .map(|(peer_id, bind_addr)| (*peer_id, bind_addr.clone()))
            .collect();

        let bootstrap_nodes = Arc::new(RwLock::new(bootstrap_nodes));
        let staked_nodes = Arc::new(staked_nodes);

        Self {
            fish: nodes,
            bootstrap_nodes,
            staked_nodes,
            net,
        }
    }
}

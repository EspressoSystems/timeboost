use crate::rbc::Rbc;
use crate::{consensus::Consensus, coordinator::Coordinator};

use anyhow::Result;
use async_trait::async_trait;
use derive_builder::Builder;
use libp2p_identity::PeerId;
use multisig::{Committee, Keypair, PublicKey};
use std::collections::HashSet;
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::{
    traits::comm::Comm,
    types::{metrics::SailfishMetrics, NodeId},
};
use timeboost_networking::p2p::client::{
    derive_libp2p_multiaddr, derive_libp2p_peer_id, Libp2pInitializer,
};
use timeboost_utils::PeerConfig;

#[cfg(feature = "test")]
use timeboost_networking::p2p::client::derive_libp2p_keypair;

#[derive(Builder)]
#[builder(pattern = "owned")]
pub struct SailfishInitializer<N: Comm + Send + 'static> {
    /// The ID of the node.
    pub id: NodeId,

    /// The network.
    pub network: N,

    /// The keypair of the node.
    pub keypair: Keypair,

    /// The bind address of the node.
    pub bind_address: String,

    /// The metrics of the node.
    pub metrics: SailfishMetrics,

    /// The committee of the node.
    pub committee: Committee,

    /// The peer id of the node.
    pub peer_id: PeerId,
}

pub struct Sailfish<N: Comm + Send + 'static> {
    /// The ID of the sailfish node.
    id: NodeId,

    keypair: Keypair,

    /// The Libp2p PeerId of the sailfish node.
    peer_id: PeerId,

    /// The Libp2p multiaddr of the sailfish node.
    bind_address: String,

    /// The metrics of the sailfish node.
    metrics: SailfishMetrics,

    /// The committee of the sailfish node.
    committee: Committee,

    /// The network.
    network: N,
}

#[async_trait]
impl<N: Comm + Send + 'static> HasInitializer for Sailfish<N> {
    type Initializer = SailfishInitializer<N>;
    type Into = Self;

    async fn initialize(initializer: Self::Initializer) -> Result<Self::Into> {
        Ok(Sailfish {
            id: initializer.id,
            keypair: initializer.keypair,
            peer_id: initializer.peer_id,
            bind_address: initializer.bind_address,
            metrics: initializer.metrics,
            committee: initializer.committee,
            network: initializer.network,
        })
    }
}

impl<N: Comm + Send + 'static> Sailfish<N> {
    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    pub fn bind_addr(&self) -> &String {
        &self.bind_address
    }

    #[cfg(feature = "test")]
    pub fn derive_libp2p_keypair(&self) -> Result<libp2p_identity::Keypair> {
        derive_libp2p_keypair::<PublicKey>(&self.keypair.secret_key())
    }

    #[cfg(feature = "test")]
    pub fn network(&self) -> &N {
        &self.network
    }

    pub fn into_coordinator(self) -> Coordinator<N> {
        let consensus =
            Consensus::new(self.id, self.keypair, self.committee).with_metrics(self.metrics);

        Coordinator::new(self.id, self.network, consensus)
    }
}

/// Initializes and returns sailfish coordinator
///
/// # Arguments
///
/// * `id` - Node identifier.
/// * `bootstrap_nodes` - Libp2p bootstrap nodes.
/// * `staked_nodes` - Configurations of staked nodes.
/// * `keypair` - Libp2p keypair.
/// * `bind_address` - Addresses to bind to.
/// * `metrics` - Sailfish metrics
///
/// # Panics
///
/// Panics if any configuration or initialization step fails.
pub async fn sailfish_coordinator(
    id: NodeId,
    bootstrap_nodes: HashSet<(PeerId, String)>,
    staked_nodes: Vec<PeerConfig<PublicKey>>,
    keypair: Keypair,
    bind_address: String,
    metrics: SailfishMetrics,
) -> Coordinator<Rbc> {
    let bootstrap_nodes: HashSet<_> = bootstrap_nodes
        .into_iter()
        .map(|(peer_id, addr)| {
            (
                peer_id,
                derive_libp2p_multiaddr(&addr).expect("derive multiaddr"),
            )
        })
        .collect();
    let libp2p_address = derive_libp2p_multiaddr(&bind_address).expect("derive multiaddr");
    let p2p = Libp2pInitializer::new(
        &keypair.secret_key(),
        staked_nodes.clone(),
        bootstrap_nodes,
        libp2p_address,
    )
    .expect("libp2p network to be initialized");
    let net_inner = p2p
        .into_network(
            u64::from(id) as usize,
            keypair.public_key(),
            keypair.secret_key(),
        )
        .await
        .expect("libp2p network to be initialized");

    net_inner.wait_for_ready().await;
    let committee = Committee::new(
        staked_nodes
            .iter()
            .enumerate()
            .map(|(i, cfg)| (i as u8, cfg.stake_table_entry.stake_key)),
    );

    let rbc = Rbc::new(net_inner, keypair.clone(), committee.clone());
    let peer_id =
        derive_libp2p_peer_id::<PublicKey>(&keypair.secret_key()).expect("peer id to be derived");

    let initializer = SailfishInitializerBuilder::default()
        .id(id)
        .keypair(keypair)
        .bind_address(bind_address)
        .network(rbc)
        .committee(committee.clone())
        .metrics(metrics)
        .peer_id(peer_id)
        .build()
        .expect("sailfish initializer to be built");

    let s = Sailfish::initialize(initializer)
        .await
        .expect("setup failed");

    s.into_coordinator()
}

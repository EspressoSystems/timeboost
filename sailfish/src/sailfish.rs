use crate::metrics::SailfishMetrics;
use crate::rbc::{self, Rbc};
use crate::{consensus::Consensus, coordinator::Coordinator};
use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use derive_builder::Builder;
use multisig::{Committee, Keypair, PublicKey};
use timeboost_core::traits::has_initializer::HasInitializer;
use timeboost_core::{traits::comm::Comm, types::NodeId};
use timeboost_networking::metrics::NetworkMetrics;
use timeboost_networking::Network;

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
    pub bind_address: SocketAddr,

    /// The metrics of the node.
    pub metrics: SailfishMetrics,

    /// The committee of the node.
    pub committee: Committee,
}

pub struct Sailfish<N: Comm + Send + 'static> {
    /// The ID of the sailfish node.
    id: NodeId,

    keypair: Keypair,

    /// The Libp2p multiaddr of the sailfish node.
    bind_address: SocketAddr,

    /// The metrics of the sailfish node.
    metrics: SailfishMetrics,

    /// The committee of the sailfish node.
    committee: Committee,

    /// The network.
    network: N,
}

/// Implementation of the `HasInitializer` trait for `Sailfish<N>`, defining how to initialize
/// a `Sailfish` instance from an `SailfishInitializer`.
///
/// This impl provides an asynchronous method to construct a `Sailfish` from its initializer,
/// allowing for setup and configuration before the main structure is used.
///
/// # Type Parameters
///
/// * `N` - Must implement `Comm` for communication, `Send` for safe sending across threads,
///   and `'static` for lifetime requirements within async contexts.
///
/// # Associated Types
///
/// * `Initializer` - Set to `SailfishInitializer<N>`, which contains the initial configuration
///   needed to create a `Sailfish`.
/// * `Into` - Specifies that this method returns `Self`, meaning `Sailfish<N>`.
///
/// # Methods
///
/// ## `initialize`
///
/// Asynchronously initializes a new `Sailfish` instance from a given `SailfishInitializer`.
///
/// ### Arguments
///
/// * `initializer` - An instance of `SailfishInitializer<N>` containing the setup data.
#[async_trait]
impl<N: Comm + Send + 'static> HasInitializer for Sailfish<N> {
    type Initializer = SailfishInitializer<N>;
    type Into = Self;

    async fn initialize(initializer: Self::Initializer) -> Result<Self::Into> {
        Ok(Sailfish {
            id: initializer.id,
            keypair: initializer.keypair,
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

    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_address
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
/// * `peers` - Remote peers who we need to connect to
/// * `keypair` - Nodes Keypair.
/// * `bind_address` - Addresses to bind to.
/// * `sf_metrics` - Sailfish metrics
/// * `net_metrics` - Network metrics
///
/// # Panics
///
/// Panics if any configuration or initialization step fails.
pub async fn sailfish_coordinator(
    id: NodeId,
    peers: Vec<(PublicKey, SocketAddr)>,
    keypair: Keypair,
    bind_address: SocketAddr,
    sf_metrics: SailfishMetrics,
    net_metrics: NetworkMetrics,
) -> Coordinator<Rbc> {
    let network = Network::create(bind_address, keypair.clone(), peers.clone(), net_metrics)
        .await
        .unwrap();
    let committee = Committee::new(
        peers
            .iter()
            .map(|b| b.0)
            .enumerate()
            .map(|(i, key)| (i as u8, key)),
    );

    let rbc = Rbc::new(
        network,
        rbc::Config::new(keypair.clone(), committee.clone()),
    );

    let initializer = SailfishInitializerBuilder::default()
        .id(id)
        .keypair(keypair)
        .bind_address(bind_address)
        .network(rbc)
        .committee(committee.clone())
        .metrics(sf_metrics)
        .build()
        .expect("sailfish initializer to be built");

    let s = Sailfish::initialize(initializer)
        .await
        .expect("setup failed");

    s.into_coordinator()
}

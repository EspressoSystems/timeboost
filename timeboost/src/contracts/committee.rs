use std::net::SocketAddr;

use multisig::PublicKey;
use timeboost_core::types::NodeId;

/// A contract for managing the committee of nodes, this is a placeholder for now.
#[derive(Debug, Clone)]
pub struct CommitteeContract {
    /// A bootstrap node is a map from its public key to its peer-id/bind address combo.
    bootstrap_nodes: Vec<(PublicKey, SocketAddr)>,
}

impl CommitteeContract {
    pub async fn new(
        node_id: NodeId,
        public_key: PublicKey,
        node_port: u16,
        url: reqwest::Url,
    ) -> Self {
        // First, submit that we're ready
        crate::contracts::initializer::submit_ready(
            u64::from(node_id),
            node_port,
            public_key,
            url.clone(),
        )
        .await
        .expect("ready submission to succeed");

        // Then, wait for the rest of the committee to be ready.
        let bootstrap_nodes = crate::contracts::initializer::wait_for_committee(url)
            .await
            .expect("committee to be ready");
        Self { bootstrap_nodes }
    }

    /// Fetch the current bootstrap nodes from the contract, also a placeholder for now.
    pub fn bootstrap_nodes(&self) -> Vec<(PublicKey, SocketAddr)> {
        self.bootstrap_nodes.clone()
    }
}

use std::collections::BTreeMap;

use anyhow::Result;
use hotshot::{
    traits::election::static_committee::StaticCommittee,
    types::{BLSPrivKey, BLSPubKey},
};
use hotshot_types::{
    data::ViewNumber,
    traits::{election::Membership, node_implementation::ConsensusTime},
};
use tracing::warn;

use crate::{
    impls::sailfish_types::SailfishTypes,
    types::{message::SailfishEvent, vertex::Vertex},
};

/// The context of a task, including its public and private keys. The context is passed
/// immutably to the task function.
#[derive(Clone, Debug)]
pub struct TaskContext {
    /// The public key of the node running this task.
    pub public_key: BLSPubKey,

    /// The private key of the node running this task.
    pub private_key: BLSPrivKey,

    /// The ID of the node running this task.
    pub id: u64,

    /// The view number of the node running this task.
    pub view_number: ViewNumber,
}

/// The core consensus state.
pub struct Consensus {
    /// The quorum membership.
    quorum_membership: StaticCommittee<SailfishTypes>,

    /// The last committed round number.
    last_committed_round_number: ViewNumber,

    /// The depth of the garbage collector.
    gc_depth: ViewNumber,

    /// The map of certificates
    vertex_certificates: BTreeMap<ViewNumber, Vertex>,
}

impl Consensus {
    pub fn new() -> Self {
        Self {
            last_committed_round_number: ViewNumber::genesis(),
        }
    }

    pub fn handle_event(&mut self, event: SailfishEvent) -> Result<Vec<SailfishEvent>> {
        // Skip all send events. Those are not for us.
        if !matches!(
            event,
            SailfishEvent::DummySend(_)
                | SailfishEvent::VertexSend(_)
                | SailfishEvent::TimeoutSend(_)
                | SailfishEvent::NoVoteSend(_),
        ) {
            warn!("Somehow received a send event: {event}");
            return Ok(vec![]);
        }

        Ok(vec![])
    }

    pub fn last_committed_round_number(&self) -> ViewNumber {
        self.last_committed_round_number
    }
}

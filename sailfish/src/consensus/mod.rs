use std::collections::BTreeMap;

use anyhow::Result;
use hotshot::{
    traits::election::static_committee::StaticCommittee,
    types::{BLSPrivKey, BLSPubKey, SignatureKey},
};
use hotshot_types::{
    data::ViewNumber, traits::node_implementation::ConsensusTime, vote::VoteAccumulator,
};
use tracing::warn;

use crate::{
    impls::sailfish_types::SailfishTypes,
    types::{
        certificate::{NoVoteCertificate, TimeoutCertificate, VertexCertificate},
        message::SailfishEvent,
        sailfish_types::UnusedVersions,
        vertex::Vertex,
        vote::{NoVoteVote, TimeoutVote, VertexVote},
    },
};

/// The DAG is a mapping of the round number to the vertex and the signature computed over the
/// commitment to the vertex to prove the authenticity of the vertex.
pub type Dag = BTreeMap<
    ViewNumber,
    (
        Vertex,
        <BLSPubKey as SignatureKey>::PureAssembledSignatureType,
    ),
>;

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
    #[allow(dead_code)]
    quorum_membership: StaticCommittee<SailfishTypes>,

    /// The last committed round number.
    last_committed_round_number: ViewNumber,

    /// The depth of the garbage collector.
    #[allow(dead_code)]
    gc_depth: ViewNumber,

    /// The map of certificates
    #[allow(dead_code)]
    vertex_certificates: BTreeMap<ViewNumber, Vertex>,

    /// The DAG of vertices
    #[allow(dead_code)]
    dag: Dag,

    /// The accumulator for the vertices of a given round.
    #[allow(dead_code)]
    vertex_accumulator_map: BTreeMap<
        ViewNumber,
        VoteAccumulator<SailfishTypes, VertexVote, VertexCertificate, UnusedVersions>,
    >,

    /// The accumulator for the timeouts of a given round.
    #[allow(dead_code)]
    timeout_accumulator_map: BTreeMap<
        ViewNumber,
        VoteAccumulator<SailfishTypes, TimeoutVote, TimeoutCertificate, UnusedVersions>,
    >,

    /// The accumulator for the no votes of a given round.
    #[allow(dead_code)]
    no_vote_accumulator_map: BTreeMap<
        ViewNumber,
        VoteAccumulator<SailfishTypes, NoVoteVote, NoVoteCertificate, UnusedVersions>,
    >,
}

impl Consensus {
    pub fn new(quorum_membership: StaticCommittee<SailfishTypes>, gc_depth: ViewNumber) -> Self {
        Self {
            quorum_membership,
            last_committed_round_number: ViewNumber::genesis(),
            gc_depth,
            vertex_certificates: BTreeMap::new(),
            dag: Dag::new(),
            vertex_accumulator_map: BTreeMap::new(),
            timeout_accumulator_map: BTreeMap::new(),
            no_vote_accumulator_map: BTreeMap::new(),
        }
    }

    pub fn handle_event(&mut self, event: SailfishEvent) -> Result<Vec<SailfishEvent>> {
        // Skip all send events. Those are not for us.
        if matches!(
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

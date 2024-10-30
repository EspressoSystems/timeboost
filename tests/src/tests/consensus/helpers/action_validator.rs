use std::collections::HashSet;

use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::NodeId;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) enum ActionTaken {
    ResetTimer,
    Deliver,
    SendNoVote,
    SendProposal,
    SendTimeout,
    SendTimeoutCert,
}

#[derive(Debug, Clone)]
pub struct ProcessedState {
    #[allow(dead_code)]
    node_id: NodeId,
    #[allow(dead_code)]
    round: RoundNumber,
    actions_taken: HashSet<ActionTaken>,
}

impl ProcessedState {
    pub fn new(node_id: NodeId, round: RoundNumber, actions_taken: HashSet<ActionTaken>) -> Self {
        Self {
            node_id,
            round,
            actions_taken,
        }
    }
}

pub struct ConsensusValidator {
    pub expected: HashSet<ActionTaken>,
}

impl ConsensusValidator {
    pub fn new(expected: HashSet<ActionTaken>) -> Self {
        Self { expected }
    }
    pub fn validate_state(&self, processed: ProcessedState, is_leader: bool) {
        tracing::error!("state: {:?} {}", processed, is_leader);
        for a in processed.actions_taken {
            assert!(
                self.expected.contains(&a),
                "Action: {:?} not found in expected",
                a
            );
        }
    }
}

impl Default for ConsensusValidator {
    fn default() -> Self {
        Self {
            expected: HashSet::from([
                ActionTaken::Deliver,
                ActionTaken::ResetTimer,
                ActionTaken::SendProposal,
            ]),
        }
    }
}

use std::num::NonZeroU64;

use ethereum_types::U256;
use hotshot::types::BLSPubKey;
use hotshot_types::{data::ViewNumber, stake_table::StakeTableEntry};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]

/// The static committee is just a list of public keys whose stake is equivalent across all nodes.
pub struct StaticCommittee {
    stake_table: Vec<BLSPubKey>,
}

impl StaticCommittee {
    /// Create a new election
    pub fn new(nodes: Vec<BLSPubKey>) -> Self {
        Self { stake_table: nodes }
    }

    /// Get the stake table for the current view
    pub fn committee(&self) -> &Vec<BLSPubKey> {
        &self.stake_table
    }

    /// The committee
    pub fn stake_table(&self) -> Vec<StakeTableEntry<BLSPubKey>> {
        self.stake_table
            .iter()
            .map(|k| StakeTableEntry {
                stake_key: *k,
                stake_amount: U256::from(0),
            })
            .collect()
    }

    /// Get the total number of nodes in the committee
    pub fn total_nodes(&self) -> usize {
        self.stake_table.len()
    }

    pub fn leader(&self, round_number: ViewNumber) -> BLSPubKey {
        self.stake_table[*round_number as usize % self.stake_table.len()]
    }

    /// Get the voting success threshold for the committee
    pub fn success_threshold(&self) -> NonZeroU64 {
        NonZeroU64::new(((self.stake_table.len() as u64 * 2) / 3) + 1)
            .expect("Failed to create NonZeroU64 for success threshold")
    }

    /// Get the voting failure threshold for the committee
    pub fn failure_threshold(&self) -> NonZeroU64 {
        NonZeroU64::new(((self.stake_table.len() as u64) / 3) + 1)
            .expect("Failed to create NonZeroU64 for failure threshold")
    }
}

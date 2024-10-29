use std::{num::NonZeroU64, sync::Arc};

use ethereum_types::U256;
use hotshot_types::stake_table::StakeTableEntry;

use crate::types::{round_number::RoundNumber, PublicKey};

/// The static committee is just a list of public keys whose stake is equivalent across all nodes.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct StaticCommittee {
    stake_table: Arc<Vec<PublicKey>>,
}

impl StaticCommittee {
    /// Create a new election
    pub fn new(nodes: Vec<PublicKey>) -> Self {
        assert!(!nodes.is_empty());
        Self {
            stake_table: Arc::new(nodes),
        }
    }

    /// Get the stake table for the current view
    pub fn committee(&self) -> &Vec<PublicKey> {
        &self.stake_table
    }

    /// The committee
    pub fn stake_table(&self) -> Vec<StakeTableEntry<PublicKey>> {
        self.stake_table
            .iter()
            .map(|k| StakeTableEntry {
                stake_key: *k,
                stake_amount: U256::from(1),
            })
            .collect()
    }

    /// Get the total number of nodes in the committee
    pub fn total_nodes(&self) -> usize {
        self.stake_table.len()
    }

    pub fn leader(&self, round_number: RoundNumber) -> PublicKey {
        self.stake_table[*round_number as usize % self.stake_table.len()]
    }

    /// Get the voting success threshold for the committee
    pub fn success_threshold(&self) -> NonZeroU64 {
        let t = (self.stake_table.len() * 2).div_ceil(3);
        NonZeroU64::new(t as u64).expect("ceil(2n/3) with n > 0 never gives 0")
    }

    /// Get the voting failure threshold for the committee
    pub fn failure_threshold(&self) -> NonZeroU64 {
        let t = self.stake_table.len().div_ceil(3);
        NonZeroU64::new(t as u64).expect("ceil(n/3) with n > 0 never gives 0")
    }
}

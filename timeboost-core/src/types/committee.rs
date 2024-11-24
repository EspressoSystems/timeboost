use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
};

use ethereum_types::U256;
use hotshot_types::stake_table::StakeTableEntry;
use serde::{Deserialize, Serialize};
use timeboost_util::types::PeerConfig;

use crate::types::{round_number::RoundNumber, PublicKey};

/// The static committee is just a list of public keys whose stake is equivalent across all nodes.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
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
    pub fn committee(&self) -> &[PublicKey] {
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
    pub fn size(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.stake_table.len())
            .expect("`StaticCommittee::new` ensures non-empty committee")
    }

    pub fn leader(&self, round_number: RoundNumber) -> PublicKey {
        self.stake_table[*round_number as usize % self.stake_table.len()]
    }

    /// Get the quorum size for the committee
    pub fn quorum_size(&self) -> NonZeroU64 {
        let q = self.size().get() * 2 / 3 + 1;
        NonZeroU64::new(q as u64).expect("n + 1 > 0")
    }

    /// Get the voting threshold for the committee
    pub fn threshold(&self) -> NonZeroU64 {
        let t = self.stake_table.len().div_ceil(3);
        NonZeroU64::new(t as u64).expect("ceil(n/3) with n > 0 never gives 0")
    }
}

impl From<&[PeerConfig<PublicKey>]> for StaticCommittee {
    fn from(value: &[PeerConfig<PublicKey>]) -> Self {
        Self::new(
            value
                .iter()
                .map(|cfg| cfg.stake_table_entry.stake_key)
                .collect(),
        )
    }
}

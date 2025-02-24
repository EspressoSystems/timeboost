use serde::{Deserialize, Serialize};

use super::block::timeboost::TimeboostBlock;
use crate::types::transaction::Transaction;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeboostEventType {
    /// New transactions that have been received from the network.
    Transactions { transactions: Vec<Transaction> },

    /// A block has been built.
    BlockBuilt { block: TimeboostBlock },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeboostStatusEvent {
    pub event: TimeboostEventType,
}

impl std::fmt::Display for TimeboostStatusEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.event {
            TimeboostEventType::Transactions { transactions } => {
                write!(f, "Transactions({})", transactions.len())
            }
            TimeboostEventType::BlockBuilt { block } => {
                write!(
                    f,
                    "BlockBuilt({}, {}kb)",
                    block.len(),
                    block.size_bytes() / 1024
                )
            }
        }
    }
}

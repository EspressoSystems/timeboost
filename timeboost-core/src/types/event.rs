use serde::{Deserialize, Serialize};

use crate::types::{block::Transaction, error::SailfishError, round_number::RoundNumber};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SailfishEventType {
    /// Consensus has encountered an error.
    Error { error: SailfishError },

    /// Consensus has finished a round.
    RoundFinished { round: RoundNumber },

    /// Consensus timed out for a round.
    Timeout { round: RoundNumber },

    /// Consensus has committed a round.
    Committed { round: RoundNumber },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SailfishStatusEvent {
    pub round: RoundNumber,
    pub event: SailfishEventType,
}

impl std::fmt::Display for SailfishStatusEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.event {
            SailfishEventType::Error { error } => write!(f, "Error({})", error),
            SailfishEventType::RoundFinished { round } => write!(f, "RoundFinished({})", round),
            SailfishEventType::Timeout { round } => write!(f, "Timeout({})", round),
            SailfishEventType::Committed { round } => write!(f, "Committed({})", round),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeboostEventType {
    /// New transactions that have been received from the network.
    Transactions { transactions: Vec<Transaction> },
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
        }
    }
}

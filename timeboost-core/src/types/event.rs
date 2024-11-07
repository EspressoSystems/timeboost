use serde::{Deserialize, Serialize};

use crate::types::{block::Transaction, error::SailfishError, round_number::RoundNumber};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    /// Consensus has encountered an error.
    Error { error: SailfishError },

    /// Consensus has finished a round.
    RoundFinished { round: RoundNumber },

    /// New transactions that have been received from the network.
    Transactions { transactions: Vec<Transaction> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SailfishStatusEvent {
    pub round: RoundNumber,
    pub event: EventType,
}

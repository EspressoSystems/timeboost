use hotshot_types::data::ViewNumber;
use serde::{Deserialize, Serialize};

use crate::types::{block::Transaction, error::SailfishError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    /// Consensus has encountered an error.
    Error { error: SailfishError },

    /// Consensus has finished a round.
    RoundFinished { round: ViewNumber },

    /// New transactions that have been received from the network.
    Transactions { transactions: Vec<Transaction> },
}

pub struct SailfishStatusEvent {
    pub round: ViewNumber,
    pub event: EventType,
}

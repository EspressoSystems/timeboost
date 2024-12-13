use serde::{Deserialize, Serialize};

use crate::types::{time::Timestamp, transaction::Transaction};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeboostBlock {
    pub transactions: Vec<Transaction>,
    pub timestamp: Timestamp,
}

impl TimeboostBlock {
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn size_bytes(&self) -> usize {
        self.transactions.iter().map(|tx| tx.size_bytes()).sum()
    }
}

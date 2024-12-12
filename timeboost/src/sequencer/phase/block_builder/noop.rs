use anyhow::Result;
use timeboost_core::types::{
    block::timeboost::TimeboostBlock, time::Timestamp, transaction::Transaction,
};

use super::BlockBuilder;
pub struct NoOpBlockBuilder;
impl BlockBuilder for NoOpBlockBuilder {
    fn build(&self, ordered_transactions: (Timestamp, Vec<Transaction>)) -> Result<TimeboostBlock> {
        Ok(TimeboostBlock {
            transactions: ordered_transactions.1,
            timestamp: ordered_transactions.0,
        })
    }
}

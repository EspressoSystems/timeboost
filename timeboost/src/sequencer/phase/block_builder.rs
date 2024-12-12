use anyhow::Result;
use timeboost_core::types::{
    block::timeboost::TimeboostBlock, time::Timestamp, transaction::Transaction,
};

pub mod noop;
pub trait BlockBuilder {
    fn build(&self, ordered_transactions: (Timestamp, Vec<Transaction>)) -> Result<TimeboostBlock>;
}

use anyhow::Result;
use timeboost_core::types::block::timeboost::{InclusionPhaseBlock, TimeboostBlock};

use super::BlockBuilder;
pub struct NoOpBlockBuilder;
impl BlockBuilder for NoOpBlockBuilder {
    fn build(&self, ordered_transactions: Vec<InclusionPhaseBlock>) -> Result<TimeboostBlock> {
        Ok(TimeboostBlock {
            transactions: ordered_transactions,
        })
    }
}

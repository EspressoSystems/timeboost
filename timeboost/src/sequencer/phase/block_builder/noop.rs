use anyhow::Result;

use crate::sequencer::phase::inclusion::block::InclusionPhaseBlock;

use super::{block::TimeboostBlock, BlockBuilder};
pub struct NoOpBlockBuilder;
impl BlockBuilder for NoOpBlockBuilder {
    fn build(&self, ordered_transactions: Vec<InclusionPhaseBlock>) -> Result<TimeboostBlock> {
        Ok(TimeboostBlock {
            transactions: ordered_transactions,
        })
    }
}

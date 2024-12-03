use anyhow::Result;
use timeboost_core::types::block::timeboost::TimeboostBlock;

use crate::sequencer::phase::inclusion::InclusionList;

use super::BlockBuilder;
pub struct NoOpBlockBuilder;
impl BlockBuilder for NoOpBlockBuilder {
    fn build(&self, ordered_transactions: InclusionList) -> Result<TimeboostBlock> {
        Ok(TimeboostBlock {
            transactions: ordered_transactions.transactions,
        })
    }
}

use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

use super::traits::BlockBuilder;

pub struct NoOpBlockBuilder;
impl BlockBuilder for NoOpBlockBuilder {
    fn build(&self, _ordered_transactions: Vec<SailfishBlock>) -> Result<SailfishBlock> {
        Ok(SailfishBlock::new())
    }
}

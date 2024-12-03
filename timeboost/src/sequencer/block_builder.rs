use anyhow::Result;
use timeboost_core::types::block::Block;

use super::traits::BlockBuilder;

pub struct NoOpBlockBuilder;
impl BlockBuilder for NoOpBlockBuilder {
    fn build(&self, _ordered_transactions: Vec<Block>) -> Result<Block> {
        Ok(Block::new())
    }
}

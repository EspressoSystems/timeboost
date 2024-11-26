use anyhow::Result;
use timeboost_core::types::block::Block;

use super::traits::InclusionPhase;

pub struct NoOpInclusionPhase;
impl InclusionPhase for NoOpInclusionPhase {
    fn produce_inclusion_list(&self, mempool_snapshot: Vec<Block>) -> Result<Vec<Block>> {
        Ok(mempool_snapshot)
    }
}

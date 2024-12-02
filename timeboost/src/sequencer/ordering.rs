use anyhow::Result;
use timeboost_core::types::block::Block;

use super::traits::OrderingPhase;

pub struct NoOpOrderingPhase;
impl OrderingPhase for NoOpOrderingPhase {
    fn order(&self, _decrypted_list: Vec<Block>) -> Result<Vec<Block>> {
        Ok(_decrypted_list)
    }
}

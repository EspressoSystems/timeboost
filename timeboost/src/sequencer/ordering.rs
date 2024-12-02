use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

use super::traits::OrderingPhase;

pub struct NoOpOrderingPhase;
impl OrderingPhase for NoOpOrderingPhase {
    fn order(&self, _decrypted_list: Vec<SailfishBlock>) -> Result<Vec<SailfishBlock>> {
        Ok(_decrypted_list)
    }
}

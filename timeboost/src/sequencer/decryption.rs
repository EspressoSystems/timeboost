use anyhow::Result;
use timeboost_core::types::block::Block;

use super::traits::DecryptionPhase;

pub struct NoOpDecryptionPhase;
impl DecryptionPhase for NoOpDecryptionPhase {
    fn decrypt(&self, _inclusion_list: Vec<Block>) -> Result<Vec<Block>> {
        Ok(_inclusion_list)
    }
}

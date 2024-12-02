use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

use super::traits::DecryptionPhase;

pub struct NoOpDecryptionPhase;
impl DecryptionPhase for NoOpDecryptionPhase {
    fn decrypt(&self, _inclusion_list: Vec<SailfishBlock>) -> Result<Vec<SailfishBlock>> {
        Ok(_inclusion_list)
    }
}

use anyhow::Result;
use timeboost_core::types::block::timeboost::InclusionPhaseBlock;

use super::DecryptionPhase;

pub struct NoOpDecryptionPhase;
impl DecryptionPhase for NoOpDecryptionPhase {
    fn decrypt(
        &self,
        inclusion_list: Vec<InclusionPhaseBlock>,
    ) -> Result<Vec<InclusionPhaseBlock>> {
        Ok(inclusion_list)
    }
}

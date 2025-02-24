use anyhow::Result;

use crate::sequencer::phase::inclusion::InclusionList;

use super::DecryptionPhase;

pub struct NoOpDecryptionPhase;
impl DecryptionPhase for NoOpDecryptionPhase {
    async fn decrypt(&mut self, inclusion_list: InclusionList) -> Result<InclusionList> {
        Ok(inclusion_list)
    }
}

use anyhow::Result;

use crate::sequencer::phase::inclusion::InclusionList;

use super::DecryptionPhase;

pub struct NoOpDecryptionPhase;
impl DecryptionPhase for NoOpDecryptionPhase {
    fn decrypt(&self, inclusion_list: InclusionList) -> Result<InclusionList> {
        Ok(inclusion_list)
    }
}

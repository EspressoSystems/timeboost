use anyhow::Result;

use crate::sequencer::phase::inclusion::InclusionList;

use super::OrderingPhase;

pub struct NoOpOrderingPhase;
impl OrderingPhase for NoOpOrderingPhase {
    fn order(&self, decrypted_list: InclusionList) -> Result<InclusionList> {
        Ok(decrypted_list)
    }
}

use anyhow::Result;

use crate::sequencer::phase::inclusion::block::InclusionPhaseBlock;

use super::OrderingPhase;

pub struct NoOpOrderingPhase;
impl OrderingPhase for NoOpOrderingPhase {
    fn order(&self, decrypted_list: Vec<InclusionPhaseBlock>) -> Result<Vec<InclusionPhaseBlock>> {
        Ok(decrypted_list)
    }
}

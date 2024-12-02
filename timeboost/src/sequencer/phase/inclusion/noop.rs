use super::InclusionPhase;
use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

pub struct NoOpInclusionPhase;
impl InclusionPhase for NoOpInclusionPhase {
    type Block = ();

    fn produce_inclusion_list(
        &self,
        candidate_list: Vec<SailfishBlock>,
    ) -> Result<Vec<Self::Block>> {
        Ok(candidate_list)
    }
}

use anyhow::Result;
use block::InclusionPhaseBlock;
use timeboost_core::types::block::SailfishBlock;

pub mod block;
pub mod noop;

pub struct CandidateList {}

pub trait InclusionPhase {
    fn produce_inclusion_list(
        &self,
        candidate_list: Vec<SailfishBlock>,
    ) -> Result<Vec<InclusionPhaseBlock>>;
}

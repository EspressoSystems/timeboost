use anyhow::Result;
use timeboost_core::types::{block::timeboost::InclusionPhaseBlock, sailfish_block::SailfishBlock};

pub mod noop;

pub struct CandidateList {}

pub trait InclusionPhase {
    fn produce_inclusion_list(
        &self,
        candidate_list: Vec<SailfishBlock>,
    ) -> Result<Vec<InclusionPhaseBlock>>;
}

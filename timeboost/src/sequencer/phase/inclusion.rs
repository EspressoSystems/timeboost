use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

pub mod block;
pub mod noop;

pub struct CandidateList {

}

pub trait InclusionPhase {
    type Block;

    fn produce_inclusion_list(
        &self,
        candidate_list: Vec<SailfishBlock>,
    ) -> Result<Vec<Self::Block>>;
}

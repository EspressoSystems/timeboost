use std::collections::BTreeSet;

use super::InclusionPhase;
use anyhow::Result;
use timeboost_core::types::{
    block::timeboost::InclusionPhaseBlock, round_number::RoundNumber, sailfish_block::SailfishBlock,
};

pub struct NoOpInclusionPhase;
impl InclusionPhase for NoOpInclusionPhase {
    fn produce_inclusion_list(
        &self,
        candidate_list: Vec<SailfishBlock>,
    ) -> Result<Vec<InclusionPhaseBlock>> {
        Ok(candidate_list
            .into_iter()
            .map(|block| {
                InclusionPhaseBlock::from_sailfish_block(
                    block,
                    RoundNumber::genesis() + 1,
                    RoundNumber::genesis(),
                    BTreeSet::new(),
                    0,
                )
                .unwrap() // This is safe
            })
            .collect())
    }
}

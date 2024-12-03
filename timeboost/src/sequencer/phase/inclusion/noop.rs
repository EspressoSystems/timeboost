use std::collections::BTreeSet;

use super::{CandidateList, InclusionList, InclusionPhase};
use anyhow::Result;
use timeboost_core::types::block::timeboost::InclusionPhaseBlock;
use timeboost_utils::types::round_number::RoundNumber;

pub struct NoOpInclusionPhase;
impl InclusionPhase for NoOpInclusionPhase {
    fn produce_inclusion_list(&self, candidate_list: CandidateList) -> Result<InclusionList> {
        Ok(InclusionList {
            timestamp: candidate_list.timestamp,
            round_number: candidate_list.recovery_state.round_number,
            transactions: candidate_list
                .transactions
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
                .collect(),
            delayed_inbox_index: 0,
            priority_bundle_sequence_no: 0,
        })
    }
}

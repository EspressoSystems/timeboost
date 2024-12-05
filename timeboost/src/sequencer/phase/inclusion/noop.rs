use super::{CandidateList, InclusionList, InclusionPhase};
use anyhow::Result;
use timeboost_core::types::block::{sailfish::SailfishBlock, timeboost::InclusionPhaseBlock};
use timeboost_utils::types::round_number::RoundNumber;

pub struct NoOpInclusionPhase;
impl InclusionPhase for NoOpInclusionPhase {
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        candidate_list: CandidateList,
        last_delayed_inbox_index: u64,
        _previous_bundles: &[SailfishBlock],
    ) -> Result<InclusionList> {
        let epoch = candidate_list.timestamp.into_epoch();
        let delayed_inbox_index = std::cmp::max(
            last_delayed_inbox_index,
            candidate_list.median_delayed_inbox_index(),
        );

        Ok(InclusionList {
            timestamp: candidate_list.timestamp,
            round_number,
            bundles: candidate_list
                .bundles
                .into_iter()
                .map(|block| {
                    InclusionPhaseBlock::from_sailfish_block(
                        block.into_transactions().into_iter().collect(),
                        round_number,
                        round_number - 1,
                        last_delayed_inbox_index,
                    )
                    .unwrap() // This is safe
                })
                .collect(),
            delayed_inbox_index,
            priority_bundle_sequence_no: 0,
            epoch,
        })
    }
}

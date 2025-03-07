use super::{CandidateList, InclusionList, InclusionPhase};
use anyhow::Result;
use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::seqno::SeqNo;

pub struct NoOpInclusionPhase;
impl InclusionPhase for NoOpInclusionPhase {
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        candidate_list: CandidateList,
        last_delayed_inbox_index: u64,
    ) -> Result<InclusionList> {
        let epoch = candidate_list.epoch;
        let delayed_inbox_index = std::cmp::max(
            last_delayed_inbox_index,
            candidate_list.median_delayed_inbox_index,
        );

        Ok(InclusionList {
            timestamp: candidate_list.median_timestamp,
            round_number,
            txns: candidate_list.transactions.into_iter().collect(),
            delayed_inbox_index,
            priority_bundle_sequence_no: SeqNo::zero(),
            epoch,
        })
    }
}

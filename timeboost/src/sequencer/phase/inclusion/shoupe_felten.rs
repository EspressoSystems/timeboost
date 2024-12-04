use super::{CandidateList, InclusionList, InclusionPhase};
use anyhow::Result;
use timeboost_utils::types::round_number::RoundNumber;

/// An implementation of the Shoupe-Felden Inclusion phase specification of
/// the
/// [Decentralized Timeboost](https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md)
/// protocol.
pub struct ShoupeFeltenInclusionPhase {}

impl InclusionPhase for ShoupeFeltenInclusionPhase {
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        candidate_list: CandidateList,
        last_delayed_inbox_index: u64,
    ) -> Result<InclusionList> {
        // The consensus timestamp is the maximum of the consensus timestamp from the last successful round
        // and the media of the timestamps of the candidate list bundles/transactions.
        let consensus_timestamp = std::cmp::max(
            candidate_list.recovery_state.consensus_timestamp,
            candidate_list.median_timestep(),
        );

        let priority_epoch_number = consensus_timestamp.clone().into_epoch();

        let delayed_inbox_index = std::cmp::max(
            last_delayed_inbox_index,
            candidate_list.last_successful_delayed_inbox_index,
        );

        let tx = candidate_list.filter_valid_tx_candidates();
    }
}

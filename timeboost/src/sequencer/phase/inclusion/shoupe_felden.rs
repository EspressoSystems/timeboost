use super::{CandidateList, InclusionList, InclusionPhase};
use anyhow::Result;
use timeboost_utils::types::round_number::RoundNumber;

/// An implementation of the Shoupe-Felden Inclusion phase specification of
/// the
/// [Decentralized Timeboost](https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md)
/// protocol.
pub struct ShoupeFeldenInclusionPhase {}

impl InclusionPhase for ShoupeFeldenInclusionPhase {
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        candidate_list: CandidateList,
    ) -> Result<InclusionList> {
        // The consensus timestamp is the maximum of the consensus timestamp from the last successful round
        // and the media of the timestamps of the candidate list bundles/transactions.
        let consensus_timestamp = std::cmp::max(
            candidate_list.recovery_state.consensus_timestamp,
            candidate_list.avg_timestamp(),
        );
    }
}

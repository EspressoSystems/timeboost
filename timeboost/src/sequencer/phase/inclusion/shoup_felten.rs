use std::hash::{DefaultHasher, Hash, Hasher};

use super::{CandidateList, InclusionList, InclusionPhase};
use anyhow::{bail, Result};
use timeboost_core::types::block::{sailfish::SailfishBlock, timeboost::InclusionPhaseBlock};
use timeboost_utils::types::round_number::RoundNumber;

/// An implementation of the Shoupe-Felten Inclusion phase specification of
/// the
/// [Decentralized Timeboost](https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md)
/// protocol.
pub struct ShoupeFeltenInclusionPhase {}

impl InclusionPhase for ShoupeFeltenInclusionPhase {
    /// Breakdown of the K loop routine:
    /// 1. Look for Bundles in the Current Epoch
    /// 2. Find the Sequence Numbers
    /// 3. Check Previously Included Bundles
    /// 4. Pick the Largest Sequence Number
    /// 5. Fallback if None Exist
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        mut candidate_list: CandidateList,
        last_delayed_inbox_index: u64,
        previous_bundles: &[SailfishBlock],
    ) -> Result<InclusionList> {
        // The consensus timestamp is the maximum of the consensus timestamp from the last successful round
        // and the media of the timestamps of the candidate list bundles/transactions.
        let consensus_timestamp = std::cmp::max(
            candidate_list.recovery_state.consensus_timestamp,
            candidate_list.median_timestep(),
        );

        // The priority epoch number is the epoch of the consensus timestamp.
        let priority_epoch_number = consensus_timestamp.into_epoch();

        // The delayed inbox index is the max of the last successful delayed inbox index and the
        // median delayed inbox index of the candidate list.
        let median_delayed_inbox_index = candidate_list.median_delayed_inbox_index();
        let delayed_inbox_index =
            std::cmp::max(last_delayed_inbox_index, median_delayed_inbox_index);

        // Among all priority bundle transactions seen in the consensus output that are tagged with
        // the current consensus epoch number, first discard any that are not from the current consensus
        // epoch and any that are not properly signed by the priority controller for the current epoch.
        let mut priority_bundles = candidate_list.priority_bundles();
        priority_bundles.retain(|bundle| {
            bundle.epoch() == priority_epoch_number
                && bundle.is_priority_bundle()
                && bundle.is_valid()
        });

        // Let K be the largest sequence number of any bundle from the current consensus epoch number
        // that has been included by a previous successful round’s invocation of this procedure,
        // or -1 if there is no such bundle
        let mut k: i64 = priority_bundles
            .iter()
            .filter(|bundle| previous_bundles.contains(bundle))
            .enumerate()
            // TODO: BUG BUG BUG -> This is likely NOT how the sequence number is determined. But, it works for now
            // since we do NOT have a PLC. Ordering is based on insertion order.
            .map(|(i, _)| i as i64)
            .max()
            .unwrap_or(-1);

        let mut bundles: Vec<InclusionPhaseBlock> = Vec::new();
        loop {
            // Let S be the set of bundles from the current consensus epoch number that have sequence number K + 1.
            let s: Vec<_> = priority_bundles
                .iter()
                .enumerate()
                // TODO: This is the extension of the above potentially problemtic code.
                .filter(|(i, _)| *i as i64 == k + 1)
                .collect();

            // If S is empty, exit.
            if s.is_empty() {
                break;
            }

            // Otherwise include the contents (calldata) of the member of S with smallest hash,
            // increment K, and continue.
            let (_, selected_bundle) = s
                .iter()
                .min_by_key(|(_, bundle)| {
                    let mut hasher = DefaultHasher::new();
                    bundle.hash(&mut hasher);
                    hasher.finish()
                })
                .unwrap(); // This is safe because S is not empty.

            let bundle = InclusionPhaseBlock::from_sailfish_block(
                (*selected_bundle)
                    .clone()
                    .into_transactions()
                    .into_iter()
                    .collect(),
                round_number,
                candidate_list.recovery_state.round_number,
                delayed_inbox_index,
            )?;

            bundles.push(bundle);
            k += 1;
        }

        bail!("fuck");
    }
}

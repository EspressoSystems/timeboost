use std::collections::BTreeSet;

use anyhow::Result;
use timeboost_core::types::{
    block::{sailfish::SailfishBlock, timeboost::InclusionPhaseBlock},
    time::{Epoch, Timestamp},
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::sequencer::protocol::RoundState;

pub mod noop;
pub mod shoup_felten;

/// A member's candidate list that serves as input to a consensus round R.
///
/// Taken directly from the spec:
/// https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md?plain=1#L111-L121
pub struct CandidateList<'a> {
    /// The timestamp of the node at the start of round R, which defines start(m,R).
    pub(crate) timestamp: Timestamp,

    /// The node's current delayed inbox index which defines index(m,R). This is distinct from
    /// the median fields which are computed from this list as the bundles also have potentially
    /// distinct delayed inbox indices.
    pub(crate) delayed_inbox_index: u64,

    /// The set of transactions in the candidate list, including:
    /// - All priority bundle transactions from the priority epoch e=epoch(start(m,R))
    /// - All non-priority transactions that arrived at least 250ms ago
    pub(crate) bundles: BTreeSet<SailfishBlock>,

    /// The recovery state of the node.
    pub(crate) recovery_state: &'a RoundState,

    /// The epoch of the candidate list. This one is not in the spec, but is
    /// used internally to track the epoch of the candidate list.
    epoch: Epoch,
}

impl<'a> CandidateList<'a> {
    pub fn from_mempool_snapshot(
        last_successful_delayed_inbox_index: u64,
        mempool_snapshot: Vec<SailfishBlock>,
        recovery_state: &'a RoundState,
    ) -> Self {
        let transactions: BTreeSet<SailfishBlock> = mempool_snapshot.into_iter().collect();

        let timestamp = Timestamp::now();
        Self {
            timestamp,
            delayed_inbox_index: last_successful_delayed_inbox_index,
            bundles: transactions,
            recovery_state,
            epoch: timestamp.into_epoch(),
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    fn calculate_median<T, F>(&self, values: Vec<T>, default: T, get_value: F) -> T
    where
        T: Ord + Copy + From<u64>,
        F: Fn(&T) -> u64,
    {
        let mut sorted_values = values.iter().map(get_value).collect::<Vec<_>>();
        sorted_values.sort_unstable();
        let median = if values.len() % 2 == 0 {
            (sorted_values[sorted_values.len() / 2] + sorted_values[sorted_values.len() / 2 + 1])
                / 2
        } else {
            sorted_values[(sorted_values.len() / 2) + 1]
        };

        std::cmp::max(default, median.into())
    }

    /// The average timestamp of the transactions in the candidate list. This is
    /// used to determine the consensus timestamp during the inclusion phase run.
    ///
    /// Average timestamp is either the media of the delayed inbox indices of the candidate lists
    /// or, if there's an event number of transactions, then it's the floor of the mean
    /// of the two central items in the sorted list of timestamps.
    pub fn median_timestamp(&self) -> Timestamp {
        self.calculate_median(
            self.bundles.iter().map(|t| t.timestamp()).collect(),
            self.recovery_state.consensus_timestamp,
            |t| **t,
        )
    }

    /// The median delayed inbox index is the median over the delayed inbox indices of the
    /// candidate lists. If there's an even number of transactions, then it's the floor of the mean
    /// of the two central items in the sorted list of delayed inbox indices.
    pub fn median_delayed_inbox_index(&self) -> u64 {
        self.calculate_median(
            self.bundles
                .iter()
                .map(|t| t.delayed_inbox_index())
                .collect(),
            self.delayed_inbox_index,
            |t| *t,
        )
    }

    /// The priority bundles in the candidate list. This is a method which removes the bundles from
    /// the candidate list which are priority bundles and returns them.
    pub fn priority_bundles(&mut self) -> Vec<SailfishBlock> {
        let to_remove: BTreeSet<_> = self
            .bundles
            .iter()
            .filter(|item| item.is_priority_bundle())
            .cloned()
            .collect();

        for item in &to_remove {
            self.bundles.remove(item);
        }

        to_remove.into_iter().collect()
    }

    pub fn non_priority_bundles(&mut self) -> Vec<SailfishBlock> {
        let to_remove: BTreeSet<_> = self
            .bundles
            .iter()
            .filter(|item| !item.is_priority_bundle())
            .cloned()
            .collect();

        for item in &to_remove {
            self.bundles.remove(item);
        }

        to_remove.into_iter().collect()
    }
}

/// When the consensus sub-protocol commits a result, all honest members use this
/// consensus result to compute the result of the inclusion phase, called the round’s *inclusion list*, which consists of:
///
/// * The round number
/// * A consensus timestamp, which is the maximum of:
///   * the consensus timestamp of the latest successful round, and
///   * the median of the timestamps of the candidate lists output by the consensus protocol
///     * if there are an even number of candidate lists, define the median as the *floor* of the mean of the two central items
/// * A consensus priority epoch number, which is computed from the consensus timestamp
/// * A consensus delayed inbox index, which is the maximum of:
///   * the consensus delayed inbox index of the latest successful round, and
///   * the median of the delayed inbox indexes of the candidate lists output by the consensus protocol
///     * if there are an even number of candidate lists, define the median as the *floor* of the mean of the two central items
/// * Among all priority bundle transactions seen in the consensus output that are
///     tagged with the current consensus epoch number, first discard any that are not from the current consensus
///     epoch and any that are not properly signed by the priority controller for the current epoch.
///     Then include those that are designated as included by this procedure:
///   * Let K be the largest sequence number of any bundle from the current consensus epoch number that has been included by a previous successful round’s invocation of this procedure, or -1 if there is no such bundle
///   * Loop:
///     * Let S be the set of bundles from the current epoch with sequence number K+1
///     * If S is empty, exit
///     * Otherwise include the contents (calldata) of the member of S with smallest hash, increment K, and continue
/// * All non-priority transactions that appeared in at least $F+1$ of the candidate lists output by the
///     consensus round, and for each of the previous 8 rounds, did not appear in at least $F+1$ of the
///     candidate lists output by that previous round.
///
/// Taken directly from the spec:
/// https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md?plain=1#L125-L143
pub struct InclusionList {
    /// The consensus timestamp of the inclusion list. This is the *same* as the
    /// [`CandidateList::timestamp`] and only is created when the candidate list is
    /// successfully generated.
    pub(crate) timestamp: Timestamp,

    /// The round number of the inclusion list.
    pub(crate) round_number: RoundNumber,

    /// The set of transactions and bundles in the inclusion list.
    pub(crate) bundles: Vec<InclusionPhaseBlock>,

    /// The delayed inbox index of the inclusion list.
    pub(crate) delayed_inbox_index: u64,

    /// The sequence number of the included priority bundle.
    pub(crate) priority_bundle_sequence_no: u64,

    /// The epoch of the inclusion list.
    pub(crate) epoch: Epoch,
}

impl InclusionList {
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

pub trait InclusionPhase {
    /// Phases are stateless, so this method is pure and takes states in the parent
    /// protocol state. However, we need to pass in some relevant states from the parent
    /// to inform the decision making of the inclusion list.
    ///
    /// - `round_number`: The current round number that the protocol is executing in.
    /// - `candidate_list`: The input candidate list of sailfish bundles and transactions.
    /// - `last_delayed_inbox_index`: The last delayed inbox index of the inclusion list. This is the
    ///     last *successful* delayed inbox index of the inclusion list, so the different can be > 1.
    /// - `previous_bundles`: This is the previous set of priority bundles that were included in the
    ///     prior inclusion list phase. This is important to determine the K value in the loop.
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        candidate_list: CandidateList,
        last_delayed_inbox_index: u64,
        previous_bundles: &[SailfishBlock],
    ) -> Result<InclusionList>;
}

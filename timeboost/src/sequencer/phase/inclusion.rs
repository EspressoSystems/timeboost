use std::{
    collections::{BTreeMap, BTreeSet},
    hash::{DefaultHasher, Hash, Hasher},
};

use anyhow::Result;
use committable::{Commitment, Committable};
use tide_disco::http::headers::LAST_MODIFIED;
use timeboost_core::types::{
    block::{sailfish::SailfishBlock, timeboost::InclusionPhaseBlock},
    seqno::SeqNo,
    time::{Epoch, Timestamp},
    transaction::Transaction,
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::sequencer::protocol::RoundState;

pub mod noop;
pub mod shoupe_felten;

/// A member's candidate list that serves as input to a consensus round R.
pub struct CandidateList<'a> {
    /// The timestamp of the node at the start of round R, which defines start(m,R).
    pub(crate) timestamp: Timestamp,

    /// The last successful delayed inbox index of the node, which defines index(m,R).
    pub(crate) last_successful_delayed_inbox_index: u64,

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
            last_successful_delayed_inbox_index,
            bundles: transactions,
            recovery_state,
            epoch: timestamp.into_epoch(),
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The average timestamp of the transactions in the candidate list. This is
    /// used to determine the consensus timestamp during the inclusion phase run.
    ///
    /// Average timestamp is either the media of the delayed inbox indices of the candidate lists
    /// or, if there's an event number of transactions, then it's the floor of the mean
    /// of the two central items in the sorted list of timestamps.
    pub fn median_timestep(&self) -> Timestamp {
        let median = if self.bundles.len() % 2 == 0 {
            self.bundles.iter().map(|t| *t.timestamp()).sum::<u64>() / self.bundles.len() as u64
        } else {
            // the floor of the mean of the two central items in the sorted list of timestamps.
            let mut sorted_timestamps = self
                .bundles
                .iter()
                .map(|t| *t.timestamp())
                .collect::<Vec<_>>();
            sorted_timestamps.sort_unstable();
            (sorted_timestamps[sorted_timestamps.len() / 2]
                + sorted_timestamps[sorted_timestamps.len() / 2 - 1])
                / 2
        };

        Timestamp::from(median)
    }

    /// The median delayed inbox index is the median over the delayed inbox indices of the
    /// candidate lists. If there's an even number of transactions, then it's the floor of the mean
    /// of the two central items in the sorted list of delayed inbox indices.
    pub fn median_delayed_inbox_index(&self) -> u64 {
        let median = if self.bundles.len() % 2 == 0 {
            self.bundles
                .iter()
                .map(|t| t.delayed_inbox_index())
                .sum::<u64>()
                / self.bundles.len() as u64
        } else {
            let mut sorted_delayed_inbox_indices = self
                .bundles
                .iter()
                .map(|t| t.delayed_inbox_index())
                .collect::<Vec<_>>();
            sorted_delayed_inbox_indices.sort_unstable();
            (sorted_delayed_inbox_indices[sorted_delayed_inbox_indices.len() / 2]
                + sorted_delayed_inbox_indices[sorted_delayed_inbox_indices.len() / 2 - 1])
                / 2
        };

        std::cmp::max(self.last_successful_delayed_inbox_index, median)
    }

    /// Among all priority bundle transactions seen in the consensus output that
    /// are tagged with the current consensus epoch number, first discard any that
    /// are not from the current consensus epoch and any that are not properly
    /// signed by the priority controller for the current epoch. Then include
    /// those that are designated as included by this procedure:
    /// - Let K be the largest sequence number of any bundle from the current
    ///     consensus epoch number that has been included by a previous
    ///     successful round’s invocation of this procedure, or -1 if there
    ///     is no such bundle
    /// - Loop:
    ///     - Let S be the set of bundles from the current epoch with sequence
    ///       number K + 1
    ///     - If S is empty, then terminate the loop
    ///     - Otherwise, include the contents of the member of S with the smallest hash,
    ///       increment K by 1, and go to the next iteration of the loop.
    ///
    /// Here, the transactions included are implicitly obtained only for the epoch that
    /// is the same as the epoch of the candidate list. So we can just get K from the
    /// set of transactions in the candidate list.
    pub fn filter_valid_tx_candidates(
        mut self,
        round_number: RoundNumber,
        prior_priority_txns: Vec<Transaction>,
    ) -> BTreeSet<SailfishBlock> {
        let mut ret = BTreeSet::new();

        let k = prior_priority_txns
            .iter()
            .map(|tx| tx.nonce().seqno())
            .max()
            .unwrap_or(SeqNo::zero());

        let mut bundles = self.bundles;

        loop {
            // Let S be the set of bundles from the current epoch with sequence
            // number K + 1.
            let s: Vec<_> = bundles
                .clone()
                .into_iter()
                .filter(|block| {
                    block
                        .transactions()
                        .iter()
                        .all(|tx| tx.nonce().seqno() == SeqNo::from(*k + 1))
                })
                .collect();

            if s.is_empty() {
                break;
            }

            // Select the member of S with the smallest hash.
            // The min hash here is safe to unwrap because we know that the set is not empty.
            // TODO: THIS IS LIKELY WRONG!! The hash function is underspecified.
            let selected = s
                .iter()
                .min_by_key(|b| {
                    let mut hasher = DefaultHasher::new();
                    b.hash(&mut hasher);
                    hasher.finish()
                })
                .unwrap();
        }

        ret
    }
}

impl InclusionList {
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

pub trait InclusionPhase {
    fn produce_inclusion_list(
        &self,
        round_number: RoundNumber,
        candidate_list: CandidateList,
        last_delayed_inbox_index: u64,
    ) -> Result<InclusionList>;
}

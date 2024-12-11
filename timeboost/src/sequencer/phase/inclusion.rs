use std::{
    cmp::max,
    collections::{BTreeSet, HashMap, HashSet},
};

use anyhow::Result;
use committable::{Commitment, Committable};
use serde::{Deserialize, Serialize};
use timeboost_core::types::{
    block::sailfish::SailfishBlock,
    time::{Epoch, Timestamp},
    transaction::Transaction,
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::sequencer::{protocol::RoundState, util::median};

pub mod noop;

/// A member's candidate list that serves as input to a consensus round R.
///
/// Taken directly from the spec:
/// https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md?plain=1#L111-L121
pub struct CandidateList {
    /// The median timestamp of the candidate list.
    median_timestamp: Timestamp,

    /// The median delayed inbox index of the candidate list.
    median_delayed_inbox_index: u64,

    /// The node's current delayed inbox index which defines index(m,R). This is distinct from
    /// the median fields which are computed from this list as the bundles also have potentially
    /// distinct delayed inbox indices.
    #[allow(unused)]
    pub(crate) delayed_inbox_index: u64,

    /// The set of transactions in the candidate list, including:
    /// - All priority bundle transactions from the priority epoch e=epoch(start(m,R))
    /// - All non-priority transactions that arrived at least 250ms ago
    pub(crate) transactions: BTreeSet<Transaction>,

    /// The recovery state of the node.
    #[allow(unused)]
    pub(crate) recovery_state: RoundState,

    /// The epoch of the candidate list. This one is not in the spec, but is
    /// used internally to track the epoch of the candidate list.
    epoch: Epoch,
}

impl CandidateList {
    pub fn from_mempool_snapshot(
        last_successful_delayed_inbox_index: u64,
        mempool_snapshot: Vec<SailfishBlock>,
        recovery_state: RoundState,
        prior_tx_hashes: &HashSet<Commitment<Transaction>>,
        committee_size: usize,
    ) -> Self {
        let threshold = (committee_size / 3) + 1;

        let median_timestamp = Self::median_timestamp(&mempool_snapshot, &recovery_state);
        let median_delayed_inbox_index =
            Self::median_delayed_inbox_index(&mempool_snapshot, &recovery_state);

        // Only take the transactions that exist in at least threshold blocks in the mempool snapshot.
        let mut counts = HashMap::new();
        for block in mempool_snapshot {
            for txn in block.transactions() {
                *counts.entry(txn).or_insert(0) += 1;
            }
        }

        // Transactions are a BTree set so the priority bundles are always at the front.
        let transactions = counts
            .into_iter()
            // Priority bundles are always taken no matter what.
            .filter(|(txn, count)| txn.is_priority() || *count >= threshold)
            // Unpair the pairs
            .map(|(txn, _)| txn)
            // Remove all the transactions that have been successfully included before.
            .filter(|txn| !prior_tx_hashes.contains(&txn.commit()))
            .collect();

        Self {
            median_timestamp,
            median_delayed_inbox_index,
            delayed_inbox_index: last_successful_delayed_inbox_index,
            transactions,
            recovery_state,
            epoch: median_timestamp.epoch(),
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The median timestamp of the transactions in the candidate list. This is
    /// used to determine the consensus timestamp during the inclusion phase run.
    ///
    /// Median timestamp is either the median of the timestamps of the candidate lists
    /// or, if there's an event number of transactions, then it's the floor of the mean
    /// of the two central items in the sorted list of timestamps.
    fn median_timestamp(
        mempool_snapshot: &[SailfishBlock],
        recovery_state: &RoundState,
    ) -> Timestamp {
        if let Some(ts) = median(mempool_snapshot.iter().map(|b| b.timestamp())) {
            max(ts, recovery_state.consensus_timestamp)
        } else {
            recovery_state.consensus_timestamp
        }
    }

    /// The median delayed inbox index is the median over the delayed inbox indices of the
    /// candidate lists. If there's an even number of transactions, then it's the floor of the mean
    /// of the two central items in the sorted list of delayed inbox indices.
    fn median_delayed_inbox_index(
        mempool_snapshot: &[SailfishBlock],
        recovery_state: &RoundState,
    ) -> u64 {
        if let Some(idx) = median(mempool_snapshot.iter().map(|b| b.delayed_inbox_index())) {
            max(idx, recovery_state.delayed_inbox_index)
        } else {
            recovery_state.delayed_inbox_index
        }
    }

    /// The priority bundles in the candidate list. This is a method which removes the bundles from
    /// the candidate list which are priority bundles and returns them.
    pub fn priority_txns(&mut self) -> Vec<Transaction> {
        self.transactions
            .iter()
            .filter(|t| t.is_priority())
            .cloned()
            .collect()
    }

    pub fn non_priority_txns(&mut self) -> Vec<Transaction> {
        self.transactions
            .iter()
            .filter(|t| !t.is_priority())
            .cloned()
            .collect()
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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InclusionList {
    /// The consensus timestamp of the inclusion list. This is the *same* as the
    /// [`CandidateList::timestamp`] and only is created when the candidate list is
    /// successfully generated.
    pub(crate) timestamp: Timestamp,

    /// The round number of the inclusion list.
    pub(crate) round_number: RoundNumber,

    /// The set of transactions and bundles in the inclusion list.
    pub(crate) txns: Vec<Transaction>,

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

    pub fn into_transactions(self) -> Vec<Transaction> {
        self.txns
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
        previous_bundles: &[Transaction],
    ) -> Result<InclusionList>;
}

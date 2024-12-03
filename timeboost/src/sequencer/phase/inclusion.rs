use std::collections::BTreeSet;

use anyhow::Result;
use timeboost_core::types::{
    block::{sailfish::SailfishBlock, timeboost::InclusionPhaseBlock},
    time::{Epoch, Timestamp},
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::sequencer::protocol::RoundState;

pub mod noop;
pub mod shoupe_felden;

/// A member's candidate list that serves as input to a consensus round R.
pub struct CandidateList<'a> {
    /// The timestamp of the node at the start of round R, which defines start(m,R).
    pub(crate) timestamp: Timestamp,

    /// The delayed inbox index of the node, which defines index(m,R).
    #[allow(dead_code)]
    pub(crate) delayed_box_index: u64,

    /// The set of transactions in the candidate list, including:
    /// - All priority bundle transactions from the priority epoch e=epoch(start(m,R))
    /// - All non-priority transactions that arrived at least 250ms ago
    pub(crate) transactions: BTreeSet<SailfishBlock>,

    /// The average timestamp of the transactions in the candidate list. This is
    /// used to determine the consensus timestamp during the inclusion phase run.
    avg_timestamp: Timestamp,

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
    pub(crate) transactions: Vec<InclusionPhaseBlock>,

    /// The delayed inbox index of the inclusion list.
    pub(crate) delayed_inbox_index: u64,

    /// The sequence number of the included priority bundle.
    pub(crate) priority_bundle_sequence_no: u64,

    /// The epoch of the inclusion list.
    pub(crate) epoch: Epoch,
}

impl<'a> CandidateList<'a> {
    pub fn from_mempool_snapshot(
        mempool_snapshot: Vec<SailfishBlock>,
        recovery_state: &'a RoundState,
    ) -> Self {
        let transactions: BTreeSet<SailfishBlock> = mempool_snapshot.into_iter().collect();
        let avg_timestamp =
            transactions.iter().map(|t| *t.timestamp()).sum::<u64>() / transactions.len() as u64;
        let timestamp = Timestamp::now();
        Self {
            timestamp,
            // TODO: This is always 0 for now, but will change in the future.
            delayed_box_index: 0,
            transactions,
            recovery_state,
            avg_timestamp: Timestamp::from(avg_timestamp),
            epoch: timestamp.into_epoch(),
        }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn avg_timestamp(&self) -> Timestamp {
        self.avg_timestamp
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
    ) -> Result<InclusionList>;
}

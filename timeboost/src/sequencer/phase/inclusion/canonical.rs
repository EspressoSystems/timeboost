use std::collections::HashSet;

use timeboost_core::types::{seqno::SeqNo, transaction::Transaction};

use super::{InclusionList, InclusionPhase};

/// Implements the canonical inclusion phase based on the spec.
pub struct CanonicalInclusionPhase {}

impl InclusionPhase for CanonicalInclusionPhase {
    fn produce_inclusion_list(
        &self,
        round_number: timeboost_utils::types::round_number::RoundNumber,
        mut candidate_list: super::CandidateList,
        last_delayed_inbox_index: u64,
    ) -> anyhow::Result<super::InclusionList> {
        let timestamp = candidate_list.median_timestamp;
        let committing_epoch = candidate_list.epoch;
        let delayed_inbox_index = std::cmp::max(
            last_delayed_inbox_index,
            candidate_list.median_delayed_inbox_index,
        );

        // First get all the priority transactions from the candidate list that are associated
        // with the committing epoch and without gaps in the sequence number.
        // From the spec, line 110.
        // Let B_{r^*} = {txn ^ txn.priority = true ^ txn.nonce.epoch = committingEpoch}
        let mut priority: Vec<Transaction> = candidate_list
            .priority_txns()
            .into_iter()
            .filter(|txn| txn.is_priority() && txn.nonce().epoch() == committing_epoch)
            .collect();

        let seqnos: Vec<SeqNo> = priority.iter().map(|txn| txn.nonce().seqno()).collect();
        let max_seqno = seqnos.iter().max().cloned().unwrap_or(SeqNo::zero());
        let expected: Vec<SeqNo> = (0..=*max_seqno).map(|i| i.into()).collect();
        let actual: HashSet<SeqNo> = priority.iter().map(|txn| txn.nonce().seqno()).collect();

        // If there are gaps in the sequence numbers, exclude this priority bundle.
        if !expected.iter().all(|seqno| actual.contains(seqno)) {
            priority.clear();
        }

        // If there are no priority transactions, we don't have a priority bundle sequence number.
        let seqno = if priority.is_empty() {
            SeqNo::zero()
        } else {
            max_seqno
        };

        let non_priority: Vec<Transaction> = candidate_list.non_priority_txns();

        // Combine the priority and non-priority transactions.
        let mut txns = [priority, non_priority].concat();

        // Make sure the priority transactions are on top.
        txns.sort();

        Ok(InclusionList {
            timestamp,
            round_number,
            txns,
            delayed_inbox_index,
            priority_bundle_sequence_no: seqno,
            epoch: committing_epoch,
        })
    }
}

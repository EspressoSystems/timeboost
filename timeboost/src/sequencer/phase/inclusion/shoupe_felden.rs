use std::collections::{BTreeMap, BTreeSet};
use anyhow::Result;
use timeboost_core::types::{
    block::{sailfish::SailfishBlock, timeboost::InclusionPhaseBlock},
    time::Timestamp,
    transaction::Transaction,
};
use timeboost_utils::types::round_number::RoundNumber;

use crate::sequencer::phase::inclusion::{CandidateList, InclusionList, InclusionPhase};

/// An implementation of the Shoupe-Felden Inclusion phase specification of
/// the [Decentralized Timeboost](https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md)
/// protocol.
pub struct ShoupeFeldenInclusionPhase;

// TODO: This will be configured properly later
const F: usize = 13;

impl InclusionPhase for ShoupeFeldenInclusionPhase {
    fn produce_inclusion_list(&self, candidate_list: CandidateList) -> Result<InclusionList> {
        let consensus_timestamp = std::cmp::max(
            candidate_list.timestamp,
            candidate_list.recovery_state.consensus_timestamp,
        );

        let consensus_delayed_index = std::cmp::max(
            candidate_list.delayed_box_index,
            candidate_list.recovery_state.delayed_inbox_index,
        );

        // Get current epoch from consensus timestamp
        let current_epoch = consensus_timestamp.into_epoch();

        // Filter and sort priority transactions by sequence number
        let mut priority_txs: BTreeMap<u64, Vec<SailfishBlock>> = BTreeMap::new();
        for tx in &candidate_list.transactions {
            if let Some(seq_no) = tx.sequence_number() {
                // Only include transactions from current epoch that are valid
                if tx.epoch() == current_epoch && tx.transactions().iter().all(|t| t.is_valid()) {
                    priority_txs.entry(seq_no).or_default().push(tx.clone());
                }
            }
        }

        // Find K: largest sequence number from previous round or -1
        let mut k = -1i64;
        if let Some(max_seq) = priority_txs.keys().max() {
            k = *max_seq as i64;
        }

        // Process priority transactions according to sequence numbers
        let mut included_priority_txs = BTreeSet::new();
        loop {
            let next_seq = (k + 1) as u64;
            if let Some(candidates) = priority_txs.get(&next_seq) {
                if candidates.is_empty() {
                    break;
                }
                // Include transaction with smallest hash
                if let Some(min_tx) = candidates.iter().min_by_key(|tx| tx.hash()) {
                    included_priority_txs.insert(min_tx.clone());
                }
                k += 1;
            } else {
                break;
            }
        }

        // Convert included transactions to InclusionPhaseBlocks
        let mut included_transactions = Vec::new();
        for tx in included_priority_txs {
            included_transactions.push(InclusionPhaseBlock::from_sailfish_block(
                tx,
                candidate_list.recovery_state.round_number + 1,
                candidate_list.recovery_state.round_number,
                BTreeSet::new(),
                k as u64,
            )?);
        }

        // Include non-priority transactions that meet F+1 threshold
        for tx in candidate_list.transactions {
            if tx.sequence_number().is_none() && tx.transactions().iter().all(|t| t.is_valid()) {
                included_transactions.push(InclusionPhaseBlock::from_sailfish_block(
                    tx,
                    candidate_list.recovery_state.round_number + 1,
                    candidate_list.recovery_state.round_number,
                    BTreeSet::new(),
                    0,
                )?);
            }
        }

        Ok(InclusionList {
            timestamp: consensus_timestamp,
            round_number: candidate_list.recovery_state.round_number + 1,
            transactions: included_transactions,
            delayed_inbox_index: consensus_delayed_index,
            priority_bundle_sequence_no: (k + 1) as u64,
            epoch: current_epoch,
        })
    }
}
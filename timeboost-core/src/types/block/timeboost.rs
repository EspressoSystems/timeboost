use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::types::{block::sailfish::SailfishBlock, time::Timestamp, transaction::Transaction};
use timeboost_utils::types::round_number::RoundNumber;

/// An inclusion phase block is a block which is emitted by the inclusion phase
/// of the sequencer protocol. Per the spec, the result of a round is either
/// FAILURE or a block ([`InclusionPhaseBlock`]) that contains:
/// * a round number $R$
/// * a predecessor round number $P$
/// * a consensus timestamp $T_R$
/// * a consensus delayed inbox index $I_R$
/// * an unordered set $N_R$ of non-priority transactions. A subset of
///     these may be encrypted.
///     If a non-priority transaction is encrypted, then the entire
///     transaction is encrypted as a single ciphertext.
/// * an ordered set $B_R$ of priority bundles. A subset of these may be encrypted.
///     If a priority bundle is encrypted, then the payload
///     (i.e. the contents of all transactions contained in the bundle)
///     is encrypted as a single ciphertext, with the other fields of
///     the bundle (including epoch number, sequence number, and signature)
///     remaining in plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionPhaseBlock {
    /// The round number of the block.
    round: RoundNumber,

    /// The predecessor round number of the block. This value is obtained
    /// from prior state that exists in the Timeboost impl.
    predecessor_round: RoundNumber,

    /// The consensus timestamp of the block. This is *not* the sailfish block
    /// timestamp, but the timestamp of the inclusion phase block, which is always
    /// the current timestamp.
    consensus_timestamp: Timestamp,

    /// The consensus delayed inbox index of the block. The delayed
    /// inbox is derived from the L1 delayed inbox
    /// (a contract on the L1 chain) which has a finality number,
    /// that is non-decreasing.
    ///
    /// Each member will have a view of this number, called the `delayed_inbox_index`,
    /// which satisfies:
    /// * safety: the member’s view is ≤ the true number
    /// * liveness: if the true number is `i`,
    ///     then the member’s view will eventually be ≥ `i`.
    delayed_inbox_index: u64,

    /// The set of transactions in the block. This includes both
    /// priority and non-priority transactions. As the [`Transaction`]
    /// type is overloaded, so we use a [`BTreeSet`] to store the
    /// transactions where the Priority is always on top.
    tx: BTreeSet<Transaction>,
}

impl InclusionPhaseBlock {
    pub fn from_sailfish_block(
        block: SailfishBlock,
        round: RoundNumber,
        predecessor_round: RoundNumber,
        priority_tx: BTreeSet<Transaction>,
        delayed_inbox_index: u64,
    ) -> Result<Self> {
        ensure!(
            round > predecessor_round,
            "round must be greater than predecessor round"
        );

        let mut tx: BTreeSet<Transaction> = block.transactions().into_iter().collect();

        // Merge the priority transactions with the non-priority transactions.
        tx.extend(priority_tx);

        Ok(Self {
            round,
            predecessor_round,
            consensus_timestamp: Timestamp::now(),
            delayed_inbox_index,
            tx,
        })
    }

    pub fn size_bytes(&self) -> usize {
        self.tx.iter().map(|tx| tx.size_bytes()).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeboostBlock {
    pub transactions: Vec<Transaction>,
}

impl TimeboostBlock {
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn size_bytes(&self) -> usize {
        self.transactions.iter().map(|tx| tx.size_bytes()).sum()
    }
}

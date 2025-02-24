use std::{
    collections::{BTreeMap, HashSet},
    future::pending,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use committable::{Commitment, Committable};
use futures::{future::BoxFuture, FutureExt};
use multisig::Committee;
use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::{
    block::timeboost::TimeboostBlock,
    event::{TimeboostEventType, TimeboostStatusEvent},
    seqno::SeqNo,
    time::Timestamp,
    transaction::Transaction,
};
use tokio::{sync::mpsc::Sender, time::sleep};
use tracing::{error, info, instrument};

use crate::{
    mempool::Mempool, metrics::TimeboostMetrics, sequencer::phase::inclusion::CandidateList,
};

use super::phase::{
    block_builder::BlockBuilder,
    decryption::DecryptionPhase,
    inclusion::{InclusionList, InclusionPhase},
    ordering::OrderingPhase,
};

/// The time between consensus intervals in ms.
const CONSENSUS_INTERVAL: Duration = Duration::from_millis(250);

/// Members must keep the following state between rounds:
/// - The number of the last successfully completed round.
/// - The consensus timestamp of the last successfully completed round.
/// - The delayed inbox index of the last successfully completed round.
/// - The next expected priority bundle sequence number of the last successfully completed round.
///
/// This is essentially information about (this node's view of) the latest consensus inclusion list that was
/// produced by a previous round. This information helps crashed/restarted nodes recover.
#[derive(Debug, Clone, Default)]
pub struct RoundState {
    /// The number of the last successfully completed round.
    pub(crate) round_number: RoundNumber,

    /// The consensus timestamp of the last successfully completed round.
    pub(crate) consensus_timestamp: Timestamp,

    /// The delayed inbox index of the last successfully completed round.
    pub(crate) delayed_inbox_index: u64,

    /// The next expected priority bundle sequence number of the last successfully completed round.
    pub(crate) next_expected_priority_bundle_sequence_no: SeqNo,
}

impl RoundState {
    /// Updates the round state with the new last-successful inclusion list.
    pub(crate) fn update(&mut self, inclusion_list: &InclusionList) {
        self.round_number = inclusion_list.round_number;
        self.consensus_timestamp = inclusion_list.timestamp;
        self.delayed_inbox_index = inclusion_list.delayed_inbox_index;
        self.next_expected_priority_bundle_sequence_no =
            SeqNo::from(*inclusion_list.priority_bundle_sequence_no + 1);
    }
}

pub struct Sequencer<I, D, O, B>
where
    I: InclusionPhase + 'static,
    D: DecryptionPhase + 'static,
    O: OrderingPhase + 'static,
    B: BlockBuilder + 'static,
{
    inclusion_phase: I,
    decryption_phase: D,
    ordering_phase: O,
    block_builder: B,
    #[allow(unused)]
    metrics: Arc<TimeboostMetrics>,

    committee: Committee,
    /// The round recovery state if a given node crashes and restarts.
    round_state: RoundState,

    /// The consensus interval clock.
    consensus_interval_clock: BoxFuture<'static, u64>,

    /// The current round (distinct from the Sailfish round).
    round: RoundNumber,

    /// The mempool for the timeboost node.
    mempool: Arc<Mempool>,

    /// The transactions/bundles seen at some point in the previous 8 rounds.
    prior_tx_hashes: BTreeMap<RoundNumber, HashSet<Commitment<Transaction>>>,
}

impl<I, D, O, B> Sequencer<I, D, O, B>
where
    I: InclusionPhase + 'static,
    D: DecryptionPhase + 'static,
    O: OrderingPhase + 'static,
    B: BlockBuilder + 'static,
{
    pub fn new(
        inclusion_phase: I,
        decryption_phase: D,
        ordering_phase: O,
        block_builder: B,
        committee: Committee,
        metrics: Arc<TimeboostMetrics>,
        mempool: Arc<Mempool>,
    ) -> Self {
        Self {
            inclusion_phase,
            decryption_phase,
            ordering_phase,
            block_builder,
            committee,
            metrics,
            round_state: RoundState::default(),
            consensus_interval_clock: pending().boxed(),
            round: RoundNumber::genesis(),
            mempool,
            prior_tx_hashes: BTreeMap::new(),
        }
    }

    /// Runs the main loop of the Timeboost node, handling consensus rounds until shutdown.
    ///
    /// This method:
    /// - Manages a consensus loop where each iteration represents a round of consensus.
    /// - Processes transactions from the mempool, builds blocks, and updates state.
    /// - Communicates status updates to an application via a channel.
    /// - Handles shutdown signals to gracefully exit the loop.
    pub async fn go(mut self, app_tx: Sender<TimeboostStatusEvent>) {
        self.consensus_interval_clock = sleep(CONSENSUS_INTERVAL).map(|_| 0).fuse().boxed();
        loop {
            tokio::select! {
                round = &mut self.consensus_interval_clock => {
                    info!(%round, "starting timeboost consensus");
                    self.round = round.into();
                    self.consensus_interval_clock = sleep(CONSENSUS_INTERVAL)
                        .map(move |_| round + 1)
                        .fuse()
                        .boxed();

                    // Drain the snapshot
                    let mempool_snapshot = self.mempool.drain_to_limit();

                    let candidate_list = CandidateList::from_mempool_snapshot(
                        self.round_state.delayed_inbox_index,
                        mempool_snapshot,
                        self.round_state.clone(),
                        &self.prior_tx_hashes.values().flatten().cloned().collect(),
                        usize::from(self.committee.size())
                    );

                    // We add the mempool snapshot to the prior tx hashes only if it succeeds, so we have
                    // to make a copy here.
                    let tmp_previous_bundles = candidate_list.transactions.clone();

                    // Build the block from the snapshot.
                    let Ok(block) = self.build(candidate_list).await else {
                        error!(%self.round, "failed to build block");
                        continue;
                    };

                    // Notify the application that a block was built.
                    if let Err(e) = app_tx.send(TimeboostStatusEvent {
                        event: TimeboostEventType::BlockBuilt { block },
                    }).await {
                        error!(%e, "failed to send block built event");
                    }

                    // Add the mempool snapshot to the prior tx hashes.
                    self.prior_tx_hashes
                        .entry(self.round_state.round_number)
                        .or_default()
                        .extend(tmp_previous_bundles.iter().map(|tx| tx.commit()));

                    // Remove the prior tx hashes that are not in the 8-round window.
                    self.prior_tx_hashes.retain(|round, _| *self.round - **round <= 8);
                }
            }
        }
    }

    /// Constructs a `TimeboostBlock` from a `CandidateList` through multiple phases of processing.
    ///
    /// This method goes through four distinct phases to build a block:
    /// 1. **Inclusion**: Selects transactions to include from the candidate list.
    /// 2. **Decryption**: Decrypts the selected transactions.
    /// 3. **Ordering**: Orders the decrypted transactions.
    /// 4. **Block Building**: Assembles the final block from the ordered transactions.
    #[instrument(
        level = "debug",
        skip_all,
        fields(round = %self.round)
    )]
    pub async fn build(&mut self, candidate_list: CandidateList) -> Result<TimeboostBlock> {
        let epoch = candidate_list.epoch();

        // Phase 1: Inclusion
        let Ok(inclusion_list) = self.inclusion_phase.produce_inclusion_list(
            self.round,
            candidate_list,
            self.round_state.delayed_inbox_index,
        ) else {
            error!(%epoch, %self.round, "failed to produce inclusion list");
            bail!("failed to produce inclusion list")
        };

        // Update the round state with the new inclusion list.
        self.round_state.update(&inclusion_list);

        // Phase 2: Decryption
        let Ok(decrypted_transactions) = self.decryption_phase.decrypt(inclusion_list).await else {
            error!(%epoch, %self.round, "failed to decrypt transactions");
            bail!("failed to decrypt transactions")
        };

        // Phase 3: Ordering
        let Ok(ordered_transactions) = self.ordering_phase.order(decrypted_transactions) else {
            error!(%epoch, %self.round, "failed to order transactions");
            bail!("failed to order transactions")
        };

        // Phase 4: Block Building
        let Ok(block) = self.block_builder.build(ordered_transactions) else {
            error!(%epoch, %self.round, "failed to build block");
            bail!("failed to build block")
        };

        tracing::debug!(%self.round, "built block");

        Ok(block)
    }
}

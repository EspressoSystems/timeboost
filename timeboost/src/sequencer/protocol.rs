use std::{
    collections::{BTreeMap, HashSet},
    future::pending,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Result};
use committable::{Commitment, Committable};
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::types::{
    block::{sailfish::SailfishBlock, timeboost::TimeboostBlock},
    event::{TimeboostEventType, TimeboostStatusEvent},
    metrics::TimeboostMetrics,
    time::Timestamp,
};
use timeboost_utils::types::round_number::RoundNumber;
use tokio::{
    sync::{mpsc::Sender, watch, RwLock},
    time::sleep,
};
use tracing::{error, info, instrument};

use crate::{
    mempool::{self, Mempool},
    sequencer::phase::inclusion::CandidateList,
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
    pub(crate) next_expected_priority_bundle_sequence_no: u64,
}

impl RoundState {
    /// Updates the round state with the new last-successful inclusion list.
    pub(crate) fn update(&mut self, inclusion_list: &InclusionList) {
        self.round_number = inclusion_list.round_number;
        self.consensus_timestamp = inclusion_list.timestamp;
        self.delayed_inbox_index = inclusion_list.delayed_inbox_index;
        self.next_expected_priority_bundle_sequence_no =
            inclusion_list.priority_bundle_sequence_no + 1;
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
    metrics: TimeboostMetrics,

    /// The round recovery state if a given node crashes and restarts.
    round_state: RoundState,

    /// The consensus interval clock.
    consensus_interval_clock: BoxFuture<'static, u64>,

    /// The current round (distinct from the Sailfish round).
    round: RoundNumber,

    /// The mempool for the timeboost node.
    mempool: Arc<RwLock<Mempool>>,

    /// The transactions/bundles seen at some point in the previous 8 rounds.
    prior_tx_hashes: BTreeMap<RoundNumber, HashSet<Commitment<SailfishBlock>>>,

    /// The previous successful round's bundles.
    previous_bundles: Vec<SailfishBlock>,
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
        metrics: TimeboostMetrics,
        mempool: Arc<RwLock<Mempool>>,
    ) -> Self {
        Self {
            inclusion_phase,
            decryption_phase,
            ordering_phase,
            block_builder,
            metrics,
            round_state: RoundState::default(),
            consensus_interval_clock: pending().boxed(),
            round: RoundNumber::genesis(),
            mempool,
            prior_tx_hashes: BTreeMap::new(),
            previous_bundles: Vec::new(),
        }
    }

    pub async fn go(
        mut self,
        mut shutdown_rx: watch::Receiver<()>,
        app_tx: Sender<TimeboostStatusEvent>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    return Ok(());
                }
                round = &mut self.consensus_interval_clock => {
                    info!(%round, "starting timeboost consensus");
                    self.consensus_interval_clock = sleep(CONSENSUS_INTERVAL)
                        .map(move |_| round + 1)
                        .fuse()
                        .boxed();

                    // "...Members should make a reasonable best effort to exclude from their candidate lists any transactions or bundles
                    // that have already been part of the consensus inclusion list produced by a previous round."
                    //
                    // First, remove all the transactions/bundles that have been included in the
                    // previous 8 rounds.
                    //
                    // This might be flawed as a prior round might sneak in, but that's okay since it should
                    // be caught regardless.
                    let prior_tx_hashes: HashSet<Commitment<SailfishBlock>> =
                        self.prior_tx_hashes.values().flatten().cloned().collect();
                    self.mempool.write().await.remove_duplicate_bundles(
                        &prior_tx_hashes,
                    );

                    // Drain the snapshot
                    let mempool_snapshot = self.mempool.write().await.drain_to_limit(mempool::MEMPOOL_LIMIT_BYTES);

                    // This is required for the Shoupe-Felten inclusion phase. We *must* know which of the current bundle
                    // set has been included in a prior successful round.
                    let tmp_previous_bundles = mempool_snapshot.clone();

                    // Pre-calculate the commitments so that way if this operation succeeds, we can drop the
                    // snapshot into the appropriate storage for the round. We do this here because we
                    // move the mempool snapshot into the builder function.
                    let mempool_snapshot_commitments: HashSet<Commitment<SailfishBlock>> =
                        mempool_snapshot.iter().map(|b| b.commit()).collect();

                    // Build the block from the snapshot.
                    let Ok(block) = self.build(mempool_snapshot) else {
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
                        .extend(mempool_snapshot_commitments);

                    // Remove the prior tx hashes that are not in the 8-round window.
                    self.prior_tx_hashes.retain(|round, _| *self.round - **round <= 8);

                    // The round was successful, so we update the previous bundles.
                    self.previous_bundles = tmp_previous_bundles;
                }
            }
        }
    }

    #[instrument(
        level = "debug",
        skip_all,
        fields(round = %self.round)
    )]
    pub fn build(&mut self, mempool_snapshot: Vec<SailfishBlock>) -> Result<TimeboostBlock> {
        let candidate_list = CandidateList::from_mempool_snapshot(
            self.round_state.delayed_inbox_index,
            mempool_snapshot,
            &self.round_state,
        );
        let epoch = candidate_list.epoch();

        // Phase 1: Inclusion
        let Ok(inclusion_list) = self.inclusion_phase.produce_inclusion_list(
            self.round,
            candidate_list,
            self.round_state.delayed_inbox_index,
            &self.previous_bundles,
        ) else {
            self.metrics.get_failures_in_epoch(epoch).add(1);
            error!(%epoch, %self.round, "failed to produce inclusion list");
            bail!("failed to produce inclusion list")
        };

        // Update the round state with the new inclusion list.
        self.round_state.update(&inclusion_list);

        // Phase 2: Decryption
        let Ok(decrypted_transactions) = self.decryption_phase.decrypt(inclusion_list) else {
            self.metrics.get_failures_in_epoch(epoch).add(1);
            error!(%epoch, %self.round, "failed to decrypt transactions");
            bail!("failed to decrypt transactions")
        };

        // Phase 3: Ordering
        let Ok(ordered_transactions) = self.ordering_phase.order(decrypted_transactions) else {
            self.metrics.get_failures_in_epoch(epoch).add(1);
            error!(%epoch, %self.round, "failed to order transactions");
            bail!("failed to order transactions")
        };

        // Phase 4: Block Building
        let Ok(block) = self.block_builder.build(ordered_transactions) else {
            self.metrics.get_failures_in_epoch(epoch).add(1);
            error!(%epoch, %self.round, "failed to build block");
            bail!("failed to build block")
        };

        info!(%self.round, "built block");

        Ok(block)
    }
}

use std::{collections::BTreeMap, future::pending, sync::Arc, time::Duration};

use anyhow::{bail, Result};
use committable::{Commitment, Committable};
use futures::{future::BoxFuture, FutureExt};
use timeboost_core::types::{
    block::{
        sailfish::SailfishBlock,
        timeboost::{InclusionPhaseBlock, TimeboostBlock},
    },
    event::{TimeboostEventType, TimeboostStatusEvent},
    metrics::TimeboostMetrics,
    time::{Epoch, Timestamp},
};
use timeboost_utils::types::round_number::RoundNumber;
use tokio::{
    sync::{mpsc::Sender, watch, RwLock},
    time::{sleep, Instant},
};
use tracing::{error, info};

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

/// The duration of an epoch in seconds.
const EPOCH_TIME_SECS: u64 = 60;

/// The time between consensus intervals in ms.
const CONSENSUS_INTERVAL_MS: u64 = 250;

/// Members must keep the following state between rounds:
/// - The number of the last successfully completed round.
/// - The consensus timestamp of the last successfully completed round.
/// - The delayed inbox index of the last successfully completed round.
/// - The next expected priority bundle sequence number of the last successfully completed round.
/// - The hashes of all the non-priority transactions that, in any of the previous 8 rounds,
///     were seen in at least F + 1 candidate lists produced by the consensus protocol for that round.
///
/// This is essentially information about (this node's view of) the latest consensus inclusion list that was
/// produced by a previous round. This information helps crashed/restarted nodes recover.
#[derive(Debug, Clone, Default)]
pub(crate) struct RoundState {
    /// The number of the last successfully completed round.
    pub(crate) round_number: RoundNumber,

    /// The consensus timestamp of the last successfully completed round.
    pub(crate) consensus_timestamp: Timestamp,

    /// The delayed inbox index of the last successfully completed round.
    pub(crate) delayed_inbox_index: u64,

    /// The next expected priority bundle sequence number of the last successfully completed round.
    pub(crate) next_expected_priority_bundle_sequence_no: u64,

    /// The hashes of all the non-priority transactions that, in any of the previous 8 rounds,
    /// were seen in at least F + 1 candidate lists produced by the consensus protocol for that round.
    pub(crate) non_priority_tx_hashes: BTreeMap<RoundNumber, Vec<Commitment<InclusionPhaseBlock>>>,
}

impl RoundState {
    pub(crate) fn update(&mut self, inclusion_list: &InclusionList) {
        self.round_number = inclusion_list.round_number;
        self.consensus_timestamp = inclusion_list.timestamp;
        self.delayed_inbox_index = inclusion_list.delayed_inbox_index;
        self.next_expected_priority_bundle_sequence_no =
            inclusion_list.priority_bundle_sequence_no + 1;
        self.collect_garbage();
        self.non_priority_tx_hashes
            .entry(inclusion_list.round_number)
            .or_default()
            .extend(inclusion_list.transactions.iter().map(|t| t.commit()));
    }

    /// Garbage collects the round state to remove non-priority transactions that are no longer
    /// in the 8-round window.
    pub(crate) fn collect_garbage(&mut self) {
        self.non_priority_tx_hashes
            .retain(|round, _| *self.round_number - **round <= 8);
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
    metrics: Arc<TimeboostMetrics>,
    round_state: RoundState,

    /// The timeboost clock
    epoch_clock: BoxFuture<'static, u64>,

    /// The time the clock started.
    epoch_clock_start_time: Instant,

    /// The consensus interval clock.
    consensus_interval_clock: BoxFuture<'static, u64>,

    /// The current epoch.
    epoch: Epoch,

    /// The current round (distinct from the Sailfish round).
    round: RoundNumber,

    /// The mempool for the timeboost node.
    mempool: Arc<RwLock<Mempool>>,
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
        metrics: Arc<TimeboostMetrics>,
        mempool: Arc<RwLock<Mempool>>,
    ) -> Self {
        Self {
            inclusion_phase,
            decryption_phase,
            ordering_phase,
            block_builder,
            metrics,
            round_state: RoundState::default(),
            epoch_clock: pending().boxed(),
            epoch_clock_start_time: Instant::now(),
            consensus_interval_clock: pending().boxed(),
            epoch: Epoch::genesis(),
            round: RoundNumber::genesis(),
            mempool,
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
                    self.consensus_interval_clock = sleep(Duration::from_millis(CONSENSUS_INTERVAL_MS))
                        .map(move |_| round + 1)
                        .fuse()
                        .boxed();

                        // Drain the snapshot
                    let mempool_snapshot = self.mempool.write().await.drain_to_limit(mempool::MEMPOOL_LIMIT_BYTES);

                    // Build the block from the snapshoty.
                    let Ok(block) = self.build(self.epoch, self.round, mempool_snapshot) else {
                        error!(%self.epoch, %self.round, "failed to build block");
                        continue;
                    };

                    // Notify the application that a block was built.
                    if let Err(e) = app_tx.send(TimeboostStatusEvent {
                        event: TimeboostEventType::BlockBuilt { block },
                    }).await {
                        error!(%e, "failed to send block built event");
                    }
                }
                _ = &mut self.epoch_clock => {
                    self.epoch_clock = sleep(Duration::from_secs(EPOCH_TIME_SECS))
                        .map(move |_| {
                            let elapsed = Instant::now().duration_since(self.epoch_clock_start_time);
                            let epoch = elapsed.as_secs() / EPOCH_TIME_SECS;
                            self.epoch = Epoch::new(epoch.into());
                            epoch
                        })
                        .fuse()
                        .boxed();
                }

            }
        }
    }

    pub fn build(
        &mut self,
        epochno: Epoch,
        round: RoundNumber,
        mempool_snapshot: Vec<SailfishBlock>,
    ) -> Result<TimeboostBlock> {
        let candidate_list =
            CandidateList::from_mempool_snapshot(mempool_snapshot, &self.round_state);

        // Phase 1: Inclusion
        let Ok(inclusion_list) = self.inclusion_phase.produce_inclusion_list(candidate_list) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, %round, "failed to produce inclusion list");
            bail!("failed to produce inclusion list")
        };

        // Update the round state with the new inclusion list.
        self.round_state.update(&inclusion_list);

        // Phase 2: Decryption
        let Ok(decrypted_transactions) = self.decryption_phase.decrypt(inclusion_list) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, %round, "failed to decrypt transactions");
            bail!("failed to decrypt transactions")
        };

        // Phase 3: Ordering
        let Ok(ordered_transactions) = self.ordering_phase.order(decrypted_transactions) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, %round, "failed to order transactions");
            bail!("failed to order transactions")
        };

        // Phase 4: Block Building
        let Ok(block) = self.block_builder.build(ordered_transactions) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, %round, "failed to build block");
            bail!("failed to build block")
        };

        info!(%epochno, %round, "built block");

        Ok(block)
    }
}

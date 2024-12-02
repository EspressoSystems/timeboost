use std::sync::Arc;

use anyhow::{bail, Result};
use timeboost_core::types::{block::SailfishBlock, metrics::TimeboostMetrics};
use tracing::{error, info};

use super::phase::{
    block_builder::{block::TimeboostBlock, BlockBuilder},
    decryption::DecryptionPhase,
    inclusion::InclusionPhase,
    ordering::OrderingPhase,
};

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
    ) -> Self {
        Self {
            inclusion_phase,
            decryption_phase,
            ordering_phase,
            block_builder,
            metrics,
        }
    }

    pub fn build(
        &self,
        epochno: u64,
        round: u64,
        mempool_snapshot: Vec<SailfishBlock>,
    ) -> Result<TimeboostBlock> {
        // Phase 1: Inclusion
        let Ok(inclusion_list) = self
            .inclusion_phase
            .produce_inclusion_list(mempool_snapshot)
        else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, %round, "failed to produce inclusion list");
            bail!("failed to produce inclusion list")
        };

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

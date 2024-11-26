use std::sync::Arc;

use anyhow::{bail, Result};
use timeboost_core::types::{block::Block, metrics::TimeboostMetrics};
use tracing::error;

use crate::consensus::traits::*;

pub struct Consensus<I, D, O, B>
where
    I: InclusionPhase + Send + Sync + 'static,
    D: DecryptionPhase + Send + Sync + 'static,
    O: OrderingPhase + Send + Sync + 'static,
    B: BlockBuilder + Send + Sync + 'static,
{
    inclusion_phase: Arc<I>,
    decryption_phase: Arc<D>,
    ordering_phase: Arc<O>,
    block_builder: Arc<B>,
    metrics: Arc<TimeboostMetrics>,
}

impl<I, D, O, B> Consensus<I, D, O, B>
where
    I: InclusionPhase + Send + Sync + 'static,
    D: DecryptionPhase + Send + Sync + 'static,
    O: OrderingPhase + Send + Sync + 'static,
    B: BlockBuilder + Send + Sync + 'static,
{
    pub fn new(
        inclusion_phase: Arc<I>,
        decryption_phase: Arc<D>,
        ordering_phase: Arc<O>,
        block_builder: Arc<B>,
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

    pub async fn start(&self, epochno: u64, mempool_snapshot: Vec<Block>) -> Result<Block> {
        // Phase 1: Inclusion
        let Ok(inclusion_list) = self
            .inclusion_phase
            .produce_inclusion_list(mempool_snapshot)
        else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, "failed to produce inclusion list");
            bail!("failed to produce inclusion list")
        };

        // Phase 2: Decryption
        let Ok(decrypted_transactions) = self.decryption_phase.decrypt(inclusion_list) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, "failed to decrypt transactions");
            bail!("failed to decrypt transactions")
        };

        // Phase 3: Ordering
        let Ok(ordered_transactions) = self.ordering_phase.order(decrypted_transactions) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, "failed to order transactions");
            bail!("failed to order transactions")
        };

        // Phase 4: Block Building
        let Ok(block) = self.block_builder.build(ordered_transactions) else {
            self.metrics.failed_epochs.add(1);
            error!(%epochno, "failed to build block");
            bail!("failed to build block")
        };

        // Timeboost protocol delay
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        Ok(block)
    }
}

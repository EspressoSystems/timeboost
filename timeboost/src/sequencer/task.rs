use std::sync::Arc;

use timeboost_core::types::{
    block::SailfishBlock,
    event::{TimeboostEventType, TimeboostStatusEvent},
};
use tokio::sync::{mpsc::Sender, watch};
use tracing::error;

use super::{
    phase::{
        block_builder::BlockBuilder, decryption::DecryptionPhase, inclusion::InclusionPhase,
        ordering::OrderingPhase,
    },
    protocol::Sequencer,
};

pub async fn run_sequencer_task<
    I: InclusionPhase + Send + Sync + 'static,
    D: DecryptionPhase + Send + Sync + 'static,
    O: OrderingPhase + Send + Sync + 'static,
    B: BlockBuilder + Send + Sync + 'static,
>(
    cx: Arc<Sequencer<I, D, O, B>>,
    epoch: u64,
    round: u64,
    candidate_list: Vec<SailfishBlock>,
    app_tx: Sender<TimeboostStatusEvent>,
    mut shutdown_rx: watch::Receiver<()>,
) {
    let handle = tokio::spawn(async move { cx.build(epoch, round, candidate_list) });
    let abort_handle = handle.abort_handle();

    tokio::select! {
        _ = shutdown_rx.changed() => {
            abort_handle.abort();
        }
        handle_result = handle => {
            let block_result = match handle_result {
                Ok(block) => block,
                Err(e) => {
                    error!(%e, "tokio::spawn failed");
                    return;
                }
            };

            let block = match block_result {
                Ok(block) => block,
                Err(e) => {
                    error!(%e, "consensus task failed");
                    return;
                }
            };

            if let Err(e) = app_tx.send(TimeboostStatusEvent {
                event: TimeboostEventType::BlockBuilt { block },
            }).await {
                error!(%e, "failed to send block built event");
            }
        }
    }
}

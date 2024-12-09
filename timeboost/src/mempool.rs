use committable::{Commitment, Committable};
use std::collections::{HashSet, VecDeque};
use timeboost_core::types::block::sailfish::SailfishBlock;
use tokio::sync::RwLock;

/// The mempool limit in bytes is 500mb.
pub const MEMPOOL_LIMIT_BYTES: usize = 500 * 1024 * 1024;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of bundles in the mempool.
    bundles: RwLock<VecDeque<SailfishBlock>>,
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new() -> Self {
        Self {
            bundles: RwLock::new(VecDeque::new()),
        }
    }

    pub async fn insert(&self, block: SailfishBlock) {
        self.bundles.write().await.push_back(block);
    }

    /// Members should make a reasonable best effort to exclude from their candidate lists any transactions
    /// or bundles that have already been part of the consensus inclusion list produced by a previous round.
    /// (Failures to do so will reduce efficiency but won’t compromise the safety or liveness of the protocol).
    ///
    /// As Per: https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md?plain=1#L123
    pub async fn remove_duplicate_bundles(
        &self,
        prior_tx_hashes: &HashSet<Commitment<SailfishBlock>>,
    ) {
        self.bundles
            .write()
            .await
            .retain(|block| !prior_tx_hashes.contains(&block.commit()));
    }

    /// Drains blocks from the mempool until the total size reaches `limit_bytes`.
    pub async fn drain_to_limit(&self, limit_bytes: usize) -> Vec<SailfishBlock> {
        let mut total_size = 0;
        self.bundles
            .write()
            .await
            .drain(..)
            .take_while(|block| {
                let should_take = total_size + block.size_bytes() <= limit_bytes;
                if should_take {
                    total_size += block.size_bytes();
                }
                should_take
            })
            .collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

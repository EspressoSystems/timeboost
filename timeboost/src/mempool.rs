use committable::{Commitment, Committable};
use std::collections::{HashSet, VecDeque};
use timeboost_core::types::block::sailfish::SailfishBlock;

/// The mempool limit in bytes is 500mb.
pub const MEMPOOL_LIMIT_BYTES: usize = 500 * 1024 * 1024;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of bundles in the mempool.
    bundles: VecDeque<SailfishBlock>,
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new() -> Self {
        Self {
            bundles: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, block: SailfishBlock) {
        self.bundles.push_back(block);
    }

    /// Members should make a reasonable best effort to exclude from their candidate lists any transactions
    /// or bundles that have already been part of the consensus inclusion list produced by a previous round.
    /// (Failures to do so will reduce efficiency but won’t compromise the safety or liveness of the protocol).
    ///
    /// As Per: https://github.com/OffchainLabs/decentralized-timeboost-spec/blob/main/inclusion.md?plain=1#L123
    pub fn remove_duplicate_bundles(
        &mut self,
        prior_tx_hashes: &HashSet<Commitment<SailfishBlock>>,
    ) {
        self.bundles
            .retain(|block| !prior_tx_hashes.contains(&block.commit()));
    }

    /// Drains blocks from the mempool until the total size reaches `limit_bytes`.
    pub fn drain_to_limit(&mut self, limit_bytes: usize) -> Vec<SailfishBlock> {
        let mut total_size = 0;
        self.bundles
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

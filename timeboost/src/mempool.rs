use parking_lot::RwLock;
use std::collections::VecDeque;
use timeboost_core::types::block::sailfish::SailfishBlock;

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

    pub fn insert(&self, block: SailfishBlock) {
        self.bundles.write().push_back(block);
    }

    /// Drains blocks from the mempool until the total size reaches `limit_bytes`.
    pub fn drain_to_limit(&self, limit_bytes: usize) -> Vec<SailfishBlock> {
        let mut total_size = 0;
        self.bundles
            .write()
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

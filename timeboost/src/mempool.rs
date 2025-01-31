use futures::future::join_all;
use parking_lot::RwLock;
use std::collections::VecDeque;
use timeboost_core::types::block::sailfish::SailfishBlock;
use tracing::{info, warn};

use crate::gas::gas_estimator::{EstimatorError, GasEstimator};

/// Max gas limit for transaction in a block (32M)
const MAX_GAS_LIMIT: u64 = 32_000_000 * 64;
const DRAIN_BUNDLE_SIZE: usize = 10;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of bundles in the mempool.
    bundles: RwLock<VecDeque<SailfishBlock>>,
    estimator: GasEstimator,
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new() -> Self {
        Self {
            bundles: RwLock::new(VecDeque::new()),
            estimator: GasEstimator::new("http://localhost:8547"),
        }
    }

    pub fn insert(&self, block: SailfishBlock) {
        self.bundles.write().push_back(block);
    }

    /// Drains blocks from the mempool until we reach our gas limit for block
    pub async fn drain_to_limit(&self) -> Vec<SailfishBlock> {
        let bundles = self.next_bundles();
        let results = join_all(bundles.into_iter().map(|b| self.estimator.estimate(b)))
            .await
            .into_iter();

        let mut accum = 0;
        let mut drained = Vec::new();
        let mut keep = VecDeque::new();
        for r in results {
            match r {
                Ok((est, b)) => {
                    if accum + est <= MAX_GAS_LIMIT {
                        accum += est;
                        drained.push(b);
                    } else {
                        warn!("estimate hit: {} {}", accum, est);
                        keep.push_back(b);
                    }
                }
                Err(e) => {
                    warn!("error getting block estimate: {:?}", e);
                    if let EstimatorError::FailedToEstimateTxn(b) = e {
                        keep.push_back(b);
                    }
                }
            }
        }

        info!(
            "mempool drained {} blocks and kept {} blocks",
            drained.len(),
            keep.len()
        );
        if !keep.is_empty() {
            let mut b = self.bundles.write();
            for k in keep {
                b.push_front(k);
            }
        }

        drained
    }

    fn next_bundles(&self) -> Vec<SailfishBlock> {
        let len = self.bundles.read().len();
        let mut c = 0;
        self.bundles
            .write()
            .drain(..)
            .filter(|b| !b.is_empty())
            .take_while(|_b| {
                c += 1;
                c <= len.min(DRAIN_BUNDLE_SIZE)
            })
            .collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

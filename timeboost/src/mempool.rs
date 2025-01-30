use futures::future::join_all;
use parking_lot::RwLock;
use std::collections::VecDeque;
use timeboost_core::types::block::sailfish::SailfishBlock;
use tracing::{error, warn};

use crate::api::gas_estimator::{EstimatorError, GasEstimator};

/// Max gas limit for transaction in a block (32M)
const MAX_GAS_LIMIT: u64 = 32_000_000 * 64;

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
        let len = self.bundles.read().len();
        error!("start: {}", len);
        let mut count = 0;
        let bundles: Vec<_> = self
            .bundles
            .write()
            .drain(..)
            .filter(|b| !b.is_empty())
            .take_while(|_b| {
                count += 1;
                count <= len.min(15)
            })
            .collect();
        let estimates = join_all(bundles.into_iter().map(|b| self.estimator.estimate(b)))
            .await
            .into_iter();

        let mut accum = 0;
        let mut drained = Vec::new();
        let mut keep = VecDeque::new();
        for r in estimates {
            match r {
                Ok((g, b)) => {
                    if accum + g <= MAX_GAS_LIMIT {
                        accum += g;
                        drained.push(b);
                    } else {
                        warn!("estimate hit: {} {}", accum, g);
                        keep.push_back(b);
                    }
                }
                Err(e) => {
                    error!("error getting block estimate: {:?}", e);
                    if let EstimatorError::FailedToEstimateTxn(b) = e {
                        keep.push_back(b);
                    }
                }
            }
        }
        if !keep.is_empty() {
            let mut b = self.bundles.write();
            for k in keep {
                b.push_front(k);
            }
        }
        error!("done: {}", self.bundles.read().len());
        drained
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

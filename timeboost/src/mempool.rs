use futures::future::join_all;
use parking_lot::RwLock;
use std::collections::VecDeque;
use timeboost_core::types::block::sailfish::SailfishBlock;
use tracing::{error, warn};

use crate::api::gas_estimator::GasEstimator;

/// Max gas limit for transaction in a block (32M)
const MAX_GAS_LIMIT: u64 = 32_000_000;

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
            estimator: GasEstimator::default(),
        }
    }

    pub fn insert(&self, block: SailfishBlock) {
        self.bundles.write().push_back(block);
    }

    /// Drains blocks from the mempool until we reach our gas limit for block
    pub async fn drain_to_limit(&self) -> Vec<SailfishBlock> {
        let mut total_gas = 0;
        let mut drained = Vec::new();
        let mut keep = VecDeque::new();
        let bundles: Vec<_> = self.bundles.write().drain(..).collect();
        let estimates = join_all(bundles.into_iter().map(|b| self.estimator.estimate(b)))
            .await
            .into_iter();
        for r in estimates {
            match r {
                Ok((g, b)) => {
                    if total_gas + g <= MAX_GAS_LIMIT {
                        total_gas += g;
                        drained.push(b);
                    } else {
                        warn!("estimate hit: {}", total_gas);
                        keep.push_back(b);
                    }
                }
                Err((e, block)) => {
                    error!("error getting block estimate: {}", e);
                    keep.push_back(block);
                }
            }
        }
        if !keep.is_empty() {
            self.bundles.write().extend(keep);
        }
        drained
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

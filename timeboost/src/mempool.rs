use alloy::providers::ProviderBuilder;
use committable::{Commitment, Committable};
use dashmap::DashMap;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use timeboost_core::types::block::sailfish::SailfishBlock;
use tokio::{sync::RwLock, task::JoinHandle};
use tracing::warn;

use crate::gas::gas_estimator::GasEstimator;

/// Max gas limit for transaction in a block (32M)
const MAX_GAS_LIMIT: u64 = 32_000_000 * 64;
const DRAIN_BUNDLE_SIZE: usize = 10;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of bundles in the mempool.
    bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
    estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new() -> Self {
        let bundles = Arc::new(RwLock::new(VecDeque::new()));
        let estimates = Arc::new(DashMap::new());
        Self::start_estimation_task(bundles.clone(), estimates.clone());
        Self { bundles, estimates }
    }

    fn start_estimation_task(
        bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
        estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
    ) -> JoinHandle<()> {
        tokio::spawn({
            async move {
                let estimator = GasEstimator::new(
                    ProviderBuilder::new()
                        .on_http("http://localhost:8547".parse().expect("valid url")),
                );
                loop {
                    for block in bundles.read().await.iter() {
                        if let Ok(est) = estimator.estimate(block).await {
                            estimates.insert(block.commit(), est);
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        })
    }

    pub async fn insert(&self, block: SailfishBlock) {
        self.bundles.write().await.push_back(block);
    }

    /// Drains blocks from the mempool until we reach our gas limit for block
    pub async fn drain_to_limit(&self) -> Vec<SailfishBlock> {
        let bundles = self.next_bundles().await;
        let mut accum = 0;
        let mut drained = Vec::new();
        let mut keep = VecDeque::new();

        for block in bundles {
            if let Some(est) = self.estimates.get(&block.commit()) {
                if accum + *est <= MAX_GAS_LIMIT {
                    accum += *est;
                    self.estimates.remove(&block.commit());
                    drained.push(block);
                } else {
                    warn!("estimate hit: {} {}", accum, *est);
                    keep.push_back(block);
                }
            } else {
                warn!("no gas estimate available for block: {:?}", block);
                keep.push_back(block);
            }
        }

        tracing::error!(
            "mempool drained {} blocks and kept {} blocks",
            drained.len(),
            keep.len()
        );
        if !keep.is_empty() {
            let mut b = self.bundles.write().await;
            for k in keep {
                b.push_front(k);
            }
        }

        drained
    }

    async fn next_bundles(&self) -> Vec<SailfishBlock> {
        let mut c = 0;
        let len = self.bundles.read().await.len();
        self.bundles
            .write()
            .await
            .drain(..)
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

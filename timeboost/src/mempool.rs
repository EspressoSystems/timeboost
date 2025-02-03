use alloy::providers::ProviderBuilder;
use alloy_chains::NamedChain;
use committable::{Commitment, Committable};
use dashmap::DashMap;
use futures::future::join_all;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use timeboost_core::types::block::sailfish::SailfishBlock;
use tokio::{
    sync::RwLock,
    task::JoinHandle,
    time::{interval, MissedTickBehavior},
};
use tracing::{debug, warn};

use crate::gas::gas_estimator::GasEstimator;

/// Max gas limit for transaction in a block (32M)
const MAX_GAS_LIMIT: u64 = 32_000_000 * 64;
/// Max number of bundles we want to try and drain at a time
const DRAIN_BUNDLE_SIZE: usize = 10;
/// How often we run gas estimation
const ESTIMATION_INTERVAL_MS: u64 = 225;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of bundles in the mempool.
    bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
    estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
    jh: JoinHandle<()>,
}

impl Drop for Mempool {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new() -> Self {
        let bundles = Arc::new(RwLock::new(VecDeque::new()));
        let estimates = Arc::new(DashMap::new());
        let jh = Self::run_estimation_task(bundles.clone(), estimates.clone());
        Self {
            bundles,
            estimates,
            jh,
        }
    }

    fn run_estimation_task(
        bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
        estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
    ) -> JoinHandle<()> {
        tokio::spawn({
            async move {
                let estimator = GasEstimator::new(
                    ProviderBuilder::new()
                        .with_chain(NamedChain::ArbitrumSepolia)
                        .on_http("http://localhost:8547".parse().expect("valid url")),
                );
                let mut timer = interval(Duration::from_millis(ESTIMATION_INTERVAL_MS));
                timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = timer.tick() => {
                            let res = join_all(bundles.read().await
                                .iter()
                                .take(DRAIN_BUNDLE_SIZE*2)
                                .map(|b| estimator.estimate(b)))
                                .await;
                            for r in res.into_iter() {
                                if let Ok((c, est)) = r {
                                    estimates.insert(c, est);
                                } else {
                                    warn!(
                                        "failed to get gas estimation for block"
                                    );
                                }
                            }
                        }
                    }
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

        for b in bundles {
            let c = b.commit();
            let mut remove = false;
            if let Some(est) = self.estimates.get(&c) {
                if accum + *est <= MAX_GAS_LIMIT {
                    accum += *est;
                    drained.push(b);
                    remove = true;
                } else {
                    warn!("estimate hit: {} {}", accum, *est);
                    keep.push_back(b);
                }
            } else {
                warn!("no gas estimate available for block: {}", b.round_number());
                keep.push_back(b);
            }

            if remove {
                self.estimates.remove(&c);
            }
        }

        debug!(
            "mempool drained {} blocks and kept {} blocks",
            drained.len(),
            keep.len()
        );
        if !keep.is_empty() {
            let mut b = self.bundles.write().await;
            for block in keep {
                b.push_front(block);
            }
        }

        drained
    }

    async fn next_bundles(&self) -> Vec<SailfishBlock> {
        let mut b = self.bundles.write().await;
        (0..DRAIN_BUNDLE_SIZE)
            .map_while(|_| b.pop_front())
            .collect()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

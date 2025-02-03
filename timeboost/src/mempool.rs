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

/// TODO: Sometimes a block may exceed gas limit and as a result we dont drain it
/// So we set the gas limit high enough to prevent this
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
    /// Gas estimates for a block that is updated every `ESTIMATION_INTERVAL_MS`
    estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
    /// Handle for the estimation task
    jh: JoinHandle<()>,
}

impl Drop for Mempool {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl Mempool {
    // TODO: Restart behavior.
    pub fn new(nitro_url: reqwest::Url) -> Self {
        let bundles = Arc::new(RwLock::new(VecDeque::new()));
        let estimates = Arc::new(DashMap::new());
        let jh = Self::run_estimation_task(bundles.clone(), estimates.clone(), nitro_url);
        Self {
            bundles,
            estimates,
            jh,
        }
    }

    /// Spawn a task that will continuously get gas estimates for transactions in sailfish blocks
    fn run_estimation_task(
        bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
        estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
        nitro_url: reqwest::Url,
    ) -> JoinHandle<()> {
        tokio::spawn({
            async move {
                let estimator = GasEstimator::new(
                    ProviderBuilder::new()
                        .with_chain(NamedChain::ArbitrumSepolia)
                        .on_http(nitro_url),
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
            for block in keep {
                self.bundles.write().await.push_front(block);
            }
        }

        drained
    }

    async fn next_bundles(&self) -> Vec<SailfishBlock> {
        let mut c = 0;
        self.bundles
            .write()
            .await
            .drain(..)
            .take_while(|_| {
                c += 1;
                c <= DRAIN_BUNDLE_SIZE
            })
            .collect()
    }
}

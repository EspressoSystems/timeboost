use alloy::providers::ProviderBuilder;
use alloy_chains::NamedChain;
use committable::{Commitment, Committable};
use dashmap::DashMap;
use futures::future::join_all;
use parking_lot::RwLock;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use timeboost_core::types::block::sailfish::SailfishBlock;
use tokio::{
    sync::mpsc::Receiver,
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
const DRAIN_BUNDLE_SIZE: usize = 75;
/// How often we run gas estimation
const ESTIMATION_INTERVAL_MS: u64 = 1500;

/// The Timeboost mempool.
pub struct Mempool {
    /// The set of bundles in the mempool.
    bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
    /// Gas estimates for a block that is updated every `ESTIMATION_INTERVAL_MS`
    estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
    /// Run estimation task if nitro node url has been set
    run_estimator: bool,
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
    pub fn new(nitro_url: Option<reqwest::Url>, block_rx: Receiver<SailfishBlock>) -> Self {
        let bundles = Arc::new(RwLock::new(VecDeque::new()));
        let estimates = Arc::new(DashMap::new());
        match nitro_url {
            Some(url) => {
                tracing::info!("starting estimation task in mempool. nitrol url: {}", url);
                let jh =
                    Self::run_estimation_task(bundles.clone(), estimates.clone(), url, block_rx);
                Self {
                    bundles,
                    estimates,
                    run_estimator: true,
                    jh,
                }
            }
            None => Self {
                bundles,
                estimates,
                run_estimator: false,
                jh: tokio::spawn(async {}),
            },
        }
    }

    /// Spawn a task that will continuously get gas estimates for transactions in sailfish blocks
    fn run_estimation_task(
        bundles: Arc<RwLock<VecDeque<SailfishBlock>>>,
        estimates: Arc<DashMap<Commitment<SailfishBlock>, u64>>,
        nitro_url: reqwest::Url,
        mut block_rx: Receiver<SailfishBlock>,
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
                        b = block_rx.recv() => {
                            match b {
                                Some(b) => {
                                    match estimator.estimate(&b).await {
                                        Ok((c, e)) => {
                                            estimates.insert(c, e);
                                        }
                                        Err(e) => {
                                            warn!("failed to estimate for block: {}, error: {}", b.round_number(), e);
                                        }
                                    }
                                    bundles.write().push_back(b);
                                }
                                None => {
                                    warn!("block channel is closed");
                                    return;
                                }
                            }
                        },
                        _ = timer.tick() => {
                            let blocks: Vec<_> = {
                                let b = bundles.read();
                                b.iter().take(DRAIN_BUNDLE_SIZE * 2).cloned().collect()
                            };
                            let res = join_all(blocks.iter().map(|b| estimator.estimate(b))).await;
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

    pub fn insert(&self, block: SailfishBlock) {
        self.bundles.write().push_back(block);
    }

    /// Run the estimator if we started timeboost with nitrol node url
    pub fn run_estimator(&self) -> bool {
        self.run_estimator
    }

    /// Drains blocks from the mempool until we reach our gas limit for block
    pub fn drain_to_limit(&self) -> Vec<SailfishBlock> {
        let bundles = self.next_bundles();
        let mut accum = 0;
        let mut drained = Vec::new();
        let mut keep = Vec::new();

        if self.run_estimator {
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
                        keep.push(b);
                    }
                } else {
                    warn!("no gas estimate available for block: {}", b.round_number());
                    keep.push(b);
                }

                if remove {
                    self.estimates.remove(&c);
                }
            }
        } else {
            return bundles.into_iter().collect();
        }

        debug!(
            "mempool drained {} blocks and kept {} blocks",
            drained.len(),
            keep.len()
        );
        for b in keep {
            self.bundles.write().push_front(b);
        }

        drained
    }

    /// Drain the mempool `DRAIN_BUNDLE_SIZE`
    /// Some of these may get added back in `drain_to_limit` if gas price is too high
    fn next_bundles(&self) -> VecDeque<SailfishBlock> {
        let mut bundles = self.bundles.write();
        let limit = bundles.len().min(DRAIN_BUNDLE_SIZE);
        let mut next = bundles.split_off(limit);
        std::mem::swap(&mut next, &mut bundles);
        next
    }
}

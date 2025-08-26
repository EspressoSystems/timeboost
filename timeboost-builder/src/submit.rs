use std::{cmp::min, collections::BTreeSet, sync::Arc, time::Duration};

use multisig::{Committee, PublicKey, Validated};
use parking_lot::Mutex;
use robusta::espresso_types::NamespaceId;
use timeboost_types::{
    BlockNumber, CertifiedBlock,
    sailfish::{CommitteeVec, Empty},
};
use tokio::{
    spawn,
    sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::{Instant, error::Elapsed, sleep, timeout},
};
use tokio_util::task::TaskTracker;
use tracing::{debug, warn};

use crate::{config::SubmitterConfig, metrics::BuilderMetrics};

const CACHE_SIZE: usize = 15_000;
const MAX_TASKS: usize = 1000;

pub struct Submitter {
    config: SubmitterConfig,
    verify_task: JoinHandle<Empty>,
    submitters: TaskTracker,
    handler: Handler,
    committees: Arc<AsyncMutex<CommitteeVec<2>>>,
    task_permits: Arc<Semaphore>,
    metrics: BuilderMetrics,
}

impl Drop for Submitter {
    fn drop(&mut self) {
        self.verify_task.abort();
    }
}

impl Submitter {
    pub fn new<M>(cfg: SubmitterConfig, metrics: &M) -> Self
    where
        M: ::metrics::Metrics,
    {
        let client = robusta::Client::new(cfg.robusta.0.clone());
        let verified = Arc::new(Mutex::new(BTreeSet::new()));
        let committees = Arc::new(AsyncMutex::new(CommitteeVec::new(cfg.committee.clone())));
        let handler = Handler {
            label: cfg.pubkey,
            nsid: cfg.namespace,
            client: client.clone(),
            verified: verified.clone(),
        };
        let verifier = Verifier {
            label: cfg.pubkey,
            nsid: cfg.namespace,
            committees: committees.clone(),
            client: client.clone(),
            verified,
        };
        let mut configs = vec![cfg.robusta.0.clone()];
        configs.extend(cfg.robusta.1.iter().cloned());
        Submitter {
            handler,
            config: cfg,
            verify_task: spawn(verifier.verify(configs)),
            submitters: TaskTracker::new(),
            committees,
            task_permits: Arc::new(Semaphore::new(MAX_TASKS)),
            metrics: BuilderMetrics::new(metrics),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.config.pubkey
    }

    pub async fn add_committe(&mut self, c: Committee) {
        self.committees.lock().await.add(c);
    }

    pub async fn submit(&mut self, cb: CertifiedBlock<Validated>) {
        let Ok(permit) = Semaphore::acquire_owned(self.task_permits.clone()).await else {
            return;
        };
        let num = cb.cert().data().num();
        debug!(
            node  = %self.public_key(),
            num   = %num,
            tasks = %self.submitters.len(),
            "creating block handler"
        );
        self.submitters
            .spawn(self.handler.clone().handle(permit, cb));
        self.metrics.block_submit.set(*num as usize);
        self.metrics.submit_tasks.set(self.submitters.len());
    }

    pub async fn join(self) {
        self.submitters.close();
        self.submitters.wait().await
    }
}

struct Verifier {
    label: PublicKey,
    nsid: NamespaceId,
    client: robusta::Client,
    committees: Arc<AsyncMutex<CommitteeVec<2>>>,
    verified: Arc<Mutex<BTreeSet<BlockNumber>>>,
}

impl Verifier {
    async fn verify(self, configs: Vec<robusta::Config>) -> Empty {
        let mut delays = self.client.config().delay_iter();
        let height = loop {
            if let Ok(h) = self.client.height().await {
                break h;
            };
            let d = delays.next().expect("delay iterator repeats endlessly");
            sleep(d).await;
        };
        let threshold = 2 * configs.len() / 3 + 1;
        let mut watcher = robusta::Multiwatcher::new(configs, height, self.nsid, threshold);
        loop {
            let h = watcher.next().await;
            let committees = self.committees.lock().await;
            let numbers = self.client.verified(self.nsid, &h, &committees).await;
            let mut set = self.verified.lock();
            for n in numbers {
                debug!(node = %self.label, num = %n, "verified");
                if set.len() == CACHE_SIZE {
                    set.pop_first();
                }
                set.insert(n);
            }
        }
    }
}

#[derive(Clone)]
struct Handler {
    label: PublicKey,
    nsid: NamespaceId,
    client: robusta::Client,
    verified: Arc<Mutex<BTreeSet<BlockNumber>>>,
}

impl Handler {
    async fn handle(mut self, _: OwnedSemaphorePermit, cb: CertifiedBlock<Validated>) {
        enum State {
            Submit(bool),
            Wait(Duration),
            Verify(Duration),
        }

        let num = cb.cert().data().num();

        // Maybe the block has already been verified?
        if self.verified.lock().remove(&num) {
            debug!(node = %self.label, %num, "block submission verified");
            return;
        }

        let max_delay = Duration::from_secs(30);
        let mut state = State::Submit(false);

        loop {
            match state {
                State::Submit(force) => {
                    let now = Instant::now();
                    match timeout(max_delay, self.submit_block(&cb, force)).await {
                        Ok(()) => state = State::Wait(max_delay.saturating_sub(now.elapsed())),
                        Err(e) => {
                            debug!(node = %self.label, %num, "block submission timeout");
                            let _: Elapsed = e;
                            state = State::Submit(true)
                        }
                    }
                }
                State::Wait(delay) => {
                    let d = min(Duration::from_secs(3), delay);
                    sleep(d).await;
                    state = State::Verify(delay.saturating_sub(d))
                }
                State::Verify(delay) => {
                    if self.verified.lock().remove(&num) {
                        debug!(node = %self.label, %num, "block submission verified");
                        return;
                    } else {
                        state = if delay.is_zero() {
                            debug!(node = %self.label, %num, "block submission verification timeout");
                            State::Submit(true)
                        } else {
                            State::Wait(delay)
                        }
                    }
                }
            }
        }
    }

    pub async fn submit_block(&mut self, cb: &CertifiedBlock<Validated>, force: bool) {
        if !(cb.is_leader() || force) {
            return;
        }
        let mut delays = self.client.config().delay_iter();
        debug!(
            node      = %self.label,
            is_leader = cb.is_leader(),
            force     = %force,
            num       = %cb.cert().data().num(),
            round     = %cb.cert().data().round(),
            "submitting block"
        );
        while let Err(err) = self.client.submit(self.nsid, cb).await {
            warn!(node = %self.label, %err, "error submitting block");
            let d = delays.next().expect("delay iterator repeats");
            sleep(d).await
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use metrics::NoMetrics;
    use multisig::{Committee, Keypair, PublicKey, Signed, VoteAccumulator};
    use timeboost_types::{Block, BlockInfo, BlockNumber, sailfish::Round};
    use tokio::task::JoinSet;

    use super::*;

    struct BlockGen {
        p: PublicKey,
        r: Round,
        i: BlockNumber,
        k: Vec<Keypair>,
        c: Committee,
    }

    impl BlockGen {
        fn next(&mut self) -> CertifiedBlock<Validated> {
            let b = Block::new(self.i, self.r.num(), Bytes::new());
            let i = BlockInfo::new(self.i, self.r, b.hash());
            self.i += 1;
            self.r.set_num(self.r.num() + 1);
            let mut a = VoteAccumulator::new(self.c.clone());
            for k in &self.k {
                if a.add(Signed::new(i.clone(), k)).unwrap().is_some() {
                    break;
                }
            }
            let l = self.c.leader(*i.round().num() as usize) == self.p;
            CertifiedBlock::v1(a.certificate().cloned().unwrap(), b, l)
        }
    }

    #[tokio::test]
    async fn submit_random_block() {
        const NODES: usize = 5;

        let _ = tracing_subscriber::fmt()
            .with_env_filter("timeboost_builder=debug,robusta=debug")
            .try_init();

        let keys: Vec<Keypair> = (0..NODES).map(|_| Keypair::generate()).collect();

        let committee = Committee::new(
            0,
            keys.iter()
                .enumerate()
                .map(|(i, k)| (i as u8, k.public_key())),
        );

        let mut tasks = JoinSet::new();

        for k in &keys {
            let mut g = BlockGen {
                p: k.public_key(),
                r: Round::new(1, 0),
                i: BlockNumber::from(1),
                k: keys.clone(),
                c: committee.clone(),
            };

            let rcfg = robusta::Config::builder()
                .base_url(
                    "https://query.decaf.testnet.espresso.network/v1/"
                        .parse()
                        .unwrap(),
                )
                .wss_base_url(
                    "wss://query.decaf.testnet.espresso.network/v1/"
                        .parse()
                        .unwrap(),
                )
                .label(k.public_key().to_string())
                .build();

            let scfg = SubmitterConfig::builder()
                .pubkey(k.public_key())
                .robusta((rcfg.clone(), Vec::new()))
                .namespace(10_101u64)
                .committee(committee.clone())
                .build();

            let mut s = Submitter::new(scfg, &NoMetrics);

            tasks.spawn(async move {
                for _ in 0..NODES {
                    s.submit(g.next()).await;
                }
                s.join().await
            });
        }

        tasks.join_all().await;
    }
}

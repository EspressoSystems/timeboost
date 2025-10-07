use std::{
    collections::{BTreeMap, VecDeque},
    mem,
    sync::Arc,
    time::Duration,
};

use bon::Builder;
use multisig::{Committee, PublicKey, Validated};
use rand::seq::IndexedRandom;
use robusta::{Client, Config, espresso_types::NamespaceId};
use timeboost_types::{
    CertifiedBlock,
    sailfish::{CommitteeVec, Empty},
};
use tokio::{
    select, spawn,
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval, sleep},
};
use tracing::{Level, debug, enabled, error, trace, warn};

mod verify;

use crate::{config::SubmitterConfig, metrics::BuilderMetrics};
use verify::{Verified, Verifier};

const DELAY: Duration = Duration::from_secs(30);

pub struct Submitter {
    config: SubmitterConfig,
    verified: Verified<15_000>,
    committees: Arc<Mutex<CommitteeVec<2>>>,
    sender: mpsc::Sender<CertifiedBlock<Validated>>,
    verify_task: JoinHandle<Empty>,
    sender_task: JoinHandle<()>,
    metrics: Arc<BuilderMetrics>,
}

impl Drop for Submitter {
    fn drop(&mut self) {
        self.sender_task.abort();
        self.verify_task.abort();
    }
}

impl Submitter {
    pub fn new<M>(cfg: SubmitterConfig, metrics: &M) -> Self
    where
        M: ::metrics::Metrics,
    {
        let verified = Verified::default();
        let committees = Arc::new(Mutex::new(CommitteeVec::new(cfg.committee.clone())));
        let metrics = Arc::new(BuilderMetrics::new(metrics));
        let verifier = Verifier::builder()
            .label(cfg.pubkey)
            .nsid(cfg.namespace)
            .committees(committees.clone())
            .client(Client::new(cfg.robusta.0.clone()))
            .verified(verified.clone())
            .metrics(metrics.clone())
            .build();
        let (tx, rx) = mpsc::channel(10_000);
        let sender = Sender::builder()
            .label(cfg.pubkey)
            .nsid(cfg.namespace)
            .verified(verified.clone())
            .receiver(rx)
            .clock(Instant::now())
            .size_limit(cfg.max_transaction_size)
            .config(cfg.robusta.0.clone())
            .build();
        let mut configs = vec![cfg.robusta.0.clone()];
        configs.extend(cfg.robusta.1.iter().cloned());
        Submitter {
            config: cfg,
            verified,
            committees,
            metrics,
            sender: tx,
            verify_task: spawn(verifier.verify(configs.clone())),
            sender_task: spawn(sender.send(configs)),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.config.pubkey
    }

    pub async fn add_committee(&mut self, c: Committee) {
        self.committees.lock().await.add(c);
    }

    pub async fn submit(&mut self, cb: CertifiedBlock<Validated>) -> Result<(), SenderTaskDown> {
        self.metrics.blocks_submitted.add(1);
        if self.verified.contains(cb.cert().data().num()) {
            return Ok(());
        }
        self.sender.send(cb).await.map_err(|_| SenderTaskDown(()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("submit sender task terminated")]
pub struct SenderTaskDown(());

#[derive(Builder)]
struct Sender {
    label: PublicKey,
    nsid: NamespaceId,
    verified: Verified<15_000>,
    receiver: mpsc::Receiver<CertifiedBlock<Validated>>,
    clock: Instant,
    #[builder(default)]
    pending: BTreeMap<Instant, Vec<CertifiedBlock<Validated>>>,
    size_limit: usize,
    config: Config,
}

impl Sender {
    async fn send(mut self, configs: Vec<Config>) {
        let clients: Vec<Client> = configs.into_iter().map(Client::new).collect();
        assert!(!clients.is_empty());

        // Blocks we receive from the application:
        let mut inbox = Vec::new();
        // Blocks scheduled for submission:
        let mut outbox = VecDeque::new();
        // A subset of `outbox` that fits into one transaction:
        let mut transaction = Vec::new();

        let drop_verified_blocks = |v: &mut Vec<CertifiedBlock<Validated>>| {
            v.retain(|b| !self.verified.contains(b.cert().data().num()));
        };

        let random_client = || {
            clients
                .choose(&mut rand::rng())
                .expect("Vec<Client> is non-empty")
        };

        let mut checkpoints = interval(Duration::from_secs(1));
        checkpoints.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            select! {
                k = self.receiver.recv_many(&mut inbox, 10) => {
                    if k == 0 { // channel is closed
                        return
                    }
                    for b in inbox.drain(..) {
                        if b.is_leader() {
                            trace!(node = %self.label, block = %b.cert().data().num(), "leader submits");
                            outbox.push_back(b)
                        } else {
                            self.pending.entry(self.clock + DELAY).or_default().push(b);
                        }
                    }
                }
                t = checkpoints.tick() => {
                    self.clock = t;
                    // Move blocks that timed out into `outbox`:
                    let mut blocks = self.pending.split_off(&self.clock);
                    mem::swap(&mut blocks, &mut self.pending);
                    outbox.extend(blocks.into_values().flatten());
                    if enabled!(Level::TRACE) {
                        for b in &outbox {
                            trace!(node = %self.label, block = %b.cert().data().num(), "timeout");
                        }
                    }
                }
            }

            debug_assert!(transaction.is_empty());

            'submit: while !outbox.is_empty() {
                let mut size: usize = 0;
                while let Some(b) = outbox.pop_front() {
                    if self.verified.contains(b.cert().data().num()) {
                        continue;
                    }
                    let n = minicbor::len(&b);
                    if n > self.size_limit {
                        error!(
                            node  = %self.label,
                            block = %b.cert().data().num(),
                            size  = %n,
                            limit = %self.size_limit,
                            "block exceeds max transaction size; dropping"
                        );
                        continue;
                    }
                    if size + n <= self.size_limit {
                        size += n;
                        transaction.push(b)
                    } else {
                        outbox.push_front(b);
                        break;
                    }
                }

                if transaction.is_empty() {
                    break;
                }

                debug!(node = %self.label, blocks = %transaction.len(), %size, "submitting blocks");

                let mut delays = self.config.delay_iter();

                while let Err(err) = random_client().submit(self.nsid, &transaction).await {
                    warn!(node= %self.label, %err, "error submitting blocks");
                    let d = delays.next().expect("delay iterator repeats");
                    sleep(d).await;
                    drop_verified_blocks(&mut transaction);
                    if transaction.is_empty() {
                        continue 'submit;
                    }
                }

                #[cfg(feature = "times")]
                for b in &transaction {
                    times::record_once("tb-submit", b.cert().data().num().into());
                }

                drop_verified_blocks(&mut transaction);
                if transaction.is_empty() {
                    continue;
                }

                self.pending
                    .entry(self.clock + DELAY)
                    .or_default()
                    .append(&mut transaction);
            }
        }
    }
}

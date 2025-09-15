use std::{collections::BTreeMap, mem, sync::Arc, time::Duration};

use bon::Builder;
use multisig::{Committee, PublicKey, Validated};
use robusta::{Client, espresso_types::NamespaceId};
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
use tracing::{debug, warn};

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
        let client = Client::new(cfg.robusta.0.clone());
        let verified = Verified::default();
        let committees = Arc::new(Mutex::new(CommitteeVec::new(cfg.committee.clone())));
        let metrics = Arc::new(BuilderMetrics::new(metrics));
        let verifier = Verifier::builder()
            .label(cfg.pubkey)
            .nsid(cfg.namespace)
            .committees(committees.clone())
            .client(client.clone())
            .verified(verified.clone())
            .metrics(metrics.clone())
            .build();
        let (tx, rx) = mpsc::channel(10_000);
        let sender = Sender::builder()
            .label(cfg.pubkey)
            .nsid(cfg.namespace)
            .client(client)
            .verified(verified.clone())
            .receiver(rx)
            .clock(Instant::now())
            .build();
        let mut configs = vec![cfg.robusta.0.clone()];
        configs.extend(cfg.robusta.1.iter().cloned());
        Submitter {
            config: cfg,
            verified,
            committees,
            metrics,
            sender: tx,
            verify_task: spawn(verifier.verify(configs)),
            sender_task: spawn(sender.go()),
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
    client: Client,
    verified: Verified<15_000>,
    receiver: mpsc::Receiver<CertifiedBlock<Validated>>,
    clock: Instant,
    #[builder(default)]
    pending: BTreeMap<Instant, Vec<CertifiedBlock<Validated>>>,
}

impl Sender {
    async fn go(mut self) {
        let mut inbox = Vec::new();
        let mut outbox = Vec::new();

        let drop_verified_blocks = |v: &mut Vec<CertifiedBlock<Validated>>| {
            v.retain(|b| !self.verified.contains(b.cert().data().num()));
        };

        let mut checkpoints = interval(Duration::from_secs(1));
        checkpoints.set_missed_tick_behavior(MissedTickBehavior::Skip);

        'main: loop {
            select! {
                k = self.receiver.recv_many(&mut inbox, 10) => {
                    if k == 0 { // channel is closed
                        return
                    }
                    for b in inbox.drain(..) {
                        if b.is_leader() {
                            outbox.push(b)
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
                }
            }

            drop_verified_blocks(&mut outbox);

            if outbox.is_empty() {
                continue;
            }

            // TODO: Ensure that the resulting payload size does not exceed the allowed maximum.

            debug!(node = %self.label, blocks = %outbox.len(), "submitting blocks");

            let mut delays = self.client.config().delay_iter();

            while let Err(err) = self.client.submit(self.nsid, &outbox).await {
                warn!(node= %self.label, %err, "error submitting blocks");
                let d = delays.next().expect("delay iterator repeats");
                sleep(d).await;
                drop_verified_blocks(&mut outbox);
                if outbox.is_empty() {
                    continue 'main;
                }
            }

            self.pending
                .entry(self.clock + DELAY)
                .or_default()
                .append(&mut outbox);
        }
    }
}

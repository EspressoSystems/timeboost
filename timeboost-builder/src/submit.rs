use std::{collections::HashMap, sync::Arc, time::Duration};

use bon::Builder;
use multisig::{Committee, PublicKey, Validated};
use robusta::{Client, espresso_types::NamespaceId};
use timeboost_types::{
    BlockNumber, CertifiedBlock,
    sailfish::{CommitteeVec, Empty},
};
use tokio::{
    select, spawn,
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::sleep,
};
use tracing::{debug, warn};

mod time;
mod verify;

use crate::{config::SubmitterConfig, metrics::BuilderMetrics};
use time::Timer;
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
            .timer(Timer::new(cfg.pubkey))
            .client(client)
            .verified(verified.clone())
            .receiver(rx)
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

    pub async fn submit(&mut self, cb: CertifiedBlock<Validated>) {
        self.metrics.blocks_submitted.add(1);
        if self.verified.contains(cb.cert().data().num()) {
            return;
        }
        self.sender.send(cb).await.unwrap() // TODO
    }
}

#[derive(Builder)]
struct Sender {
    label: PublicKey,
    timer: Timer<BlockNumber>,
    nsid: NamespaceId,
    client: Client,
    verified: Verified<15_000>,
    receiver: mpsc::Receiver<CertifiedBlock<Validated>>,
}

impl Sender {
    async fn go(mut self) {
        let mut pending = HashMap::new();
        let mut inbox = Vec::new();
        let mut outbox = Vec::new();
        let mut timeouts = Vec::new();

        loop {
            select! {
                k = self.receiver.recv_many(&mut inbox, 10) => {
                    if k == 0 {
                        return
                    } else {
                        for b in inbox.drain(..) {
                            let n = b.cert().data().num();
                            if self.verified.contains(n) {
                                continue
                            }
                            if b.is_leader() {
                                outbox.push(b)
                            } else {
                                pending.insert(n, b);
                            }
                            self.timer.set(n, DELAY)
                        }
                    }
                },
                n = self.timer.next() => {
                    timeouts.push(n);
                    while let Some(n) = self.timer.try_next() {
                        timeouts.push(n)
                    }
                    timeouts.sort();
                    for n in timeouts.drain(..) {
                        let Some(b) = pending.remove(&n) else {
                            continue
                        };
                        if self.verified.contains(n) {
                            continue
                        }
                        debug!(node = %self.label, num = %n, "block timeout");
                        outbox.push(b)
                    }
                }
            }

            if outbox.is_empty() {
                continue;
            }

            let mut delays = self.client.config().delay_iter();

            debug!(node = %self.label, blocks = %outbox.len(), "submitting blocks");

            while let Err(err) = self.client.submit(self.nsid, &outbox).await {
                warn!(node= %self.label, %err, "error submitting blocks");
                let d = delays.next().expect("delay iterator repeats");
                sleep(d).await
            }

            for b in outbox.drain(..) {
                pending.insert(b.cert().data().num(), b);
            }
        }
    }
}

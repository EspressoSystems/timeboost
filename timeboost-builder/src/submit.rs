use std::{cmp::min, collections::BTreeSet, sync::Arc, time::Duration};

use futures::stream::StreamExt;
use multisig::PublicKey;
use parking_lot::RwLock;
use robusta::{Height, espresso_types::NamespaceId};
use timeboost_types::{BlockNumber, CertifiedBlock, sailfish::Empty};
use tokio::{
    spawn,
    task::{JoinHandle, JoinSet},
    time::{Instant, error::Elapsed, sleep, timeout},
};
use tracing::{debug, warn};

use crate::config::SubmitterConfig;

const CACHE_SIZE: usize = 50_000;

pub struct Submitter {
    config: SubmitterConfig,
    verify_task: JoinHandle<Empty>,
    submitters: JoinSet<()>,
    handler: Handler,
}

impl Drop for Submitter {
    fn drop(&mut self) {
        self.verify_task.abort();
    }
}

impl Submitter {
    pub async fn create(cfg: SubmitterConfig) -> Self {
        let client = robusta::Client::new(cfg.robusta.clone());
        let verified = Arc::new(RwLock::new(BTreeSet::new()));
        let handler = Handler {
            label: cfg.pubkey,
            client: client.clone(),
            verified: verified.clone(),
        };
        let verifier = Verifier {
            label: cfg.pubkey,
            nsid: cfg.namespace,
            client: client.clone(),
            verified,
        };
        let mut delays = cfg.robusta.delay_iter();
        loop {
            let Ok(height) = client.height().await else {
                let d = delays.next().expect("delay iterator repeats");
                sleep(d).await;
                continue;
            };
            return Submitter {
                handler,
                config: cfg,
                verify_task: spawn(verifier.verify(height)),
                submitters: JoinSet::new(),
            };
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.config.pubkey
    }

    pub fn submit(&mut self, cb: CertifiedBlock) {
        debug!(node = %self.public_key(), num = %cb.cert().data().num(), "creating block handler");
        self.submitters.spawn(self.handler.clone().handle(cb));
    }

    pub async fn join(mut self) {
        while self.submitters.join_next().await.is_some() {}
    }
}

struct Verifier {
    label: PublicKey,
    nsid: NamespaceId,
    client: robusta::Client,
    verified: Arc<RwLock<BTreeSet<BlockNumber>>>,
}

impl Verifier {
    async fn verify(self, mut height: Height) -> Empty {
        loop {
            let mut headers;
            loop {
                if let Ok(it) = robusta::watch(self.client.config(), height, self.nsid).await {
                    headers = it.boxed();
                    break;
                }
            }
            while let Some(h) = headers.next().await {
                let numbers = self.client.verified_blocks(self.nsid, &h).await;
                let mut set = self.verified.write();
                for n in numbers {
                    debug!(node = %self.label, num = %n, "verified");
                    if set.len() == CACHE_SIZE {
                        set.pop_first();
                    }
                    set.insert(n);
                }
                height = h.height().into();
            }
        }
    }
}

#[derive(Clone)]
struct Handler {
    label: PublicKey,
    client: robusta::Client,
    verified: Arc<RwLock<BTreeSet<BlockNumber>>>,
}

impl Handler {
    async fn handle(mut self, cb: CertifiedBlock) {
        enum State {
            Submit(bool),
            Wait(Duration),
            Verify(Duration),
        }

        let num = cb.cert().data().num();
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
                    if self.verified.read().contains(&cb.cert().data().num()) {
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

    pub async fn submit_block(&mut self, cb: &CertifiedBlock, force: bool) {
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
        while let Err(err) = self.client.submit(cb).await {
            warn!(node = %self.label, %err, "error submitting block");
            let d = delays.next().expect("delay iterator repeats");
            sleep(d).await
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use multisig::{Committee, Keypair, PublicKey, Signed, VoteAccumulator};
    use timeboost_types::{Block, BlockHash, BlockInfo, BlockNumber, NamespaceId, sailfish::Round};
    use tokio::task::JoinSet;

    use super::*;

    struct BlockGen {
        p: PublicKey,
        n: NamespaceId,
        r: Round,
        i: BlockNumber,
        k: Vec<Keypair>,
        c: Committee,
    }

    impl BlockGen {
        fn next(&mut self) -> CertifiedBlock {
            let i = BlockInfo::new(self.i, self.r, BlockHash::default());
            self.i = self.i + 1;
            self.r.set_num(self.r.num() + 1);
            let mut a = VoteAccumulator::new(self.c.clone());
            for k in &self.k {
                if a.add(Signed::new(i.clone(), k)).unwrap().is_some() {
                    break;
                }
            }
            let b = Block::new(self.n, i.round().num(), *i.hash(), Bytes::new());
            let l = self.c.leader(*i.round().num() as usize) == self.p;
            CertifiedBlock::new(a.certificate().cloned().unwrap(), b, l)
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
                n: NamespaceId::from(10_101),
                r: Round::new(1, 0),
                i: BlockNumber::from(1),
                k: keys.clone(),
                c: committee.clone(),
            };

            let rcfg = robusta::Config::builder()
                .base_url("https://query.decaf.testnet.espresso.network/v1/")
                .unwrap()
                .wss_base_url("wss://query.decaf.testnet.espresso.network/v1/")
                .unwrap()
                .label(k.public_key().to_string())
                .build();

            let scfg = SubmitterConfig::builder()
                .pubkey(k.public_key())
                .robusta(rcfg.clone())
                .namespace(10_101u64)
                .build();

            let mut s = Submitter::create(scfg).await;

            tasks.spawn(async move {
                for _ in 0..NODES {
                    s.submit(g.next());
                }
                s.join().await
            });
        }

        tasks.join_all().await;
    }
}

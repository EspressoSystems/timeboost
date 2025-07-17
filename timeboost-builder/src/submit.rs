use std::{iter::repeat, time::Duration};

use multisig::PublicKey;
use robusta::{Error, Height, espresso_types::NamespaceId};
use timeboost_types::CertifiedBlock;
use tokio::time::{error::Elapsed, sleep, timeout};
use tracing::{debug, warn};

use crate::config::SubmitterConfig;

pub struct Submitter<H> {
    config: SubmitterConfig,
    client: robusta::Client,
    height: H,
}

impl Submitter<()> {
    pub fn new(cfg: SubmitterConfig) -> Self {
        Self {
            client: robusta::Client::new(cfg.robusta.clone()),
            config: cfg,
            height: (),
        }
    }
}

impl<H> Submitter<H> {
    pub fn public_key(&self) -> &PublicKey {
        &self.config.pubkey
    }

    pub async fn init(mut self) -> Submitter<Height> {
        let mut delays = delay_iter();
        loop {
            let Ok(h) = self.client.height().await else {
                let d = delays.next().expect("delay iterator repeats");
                sleep(d).await;
                continue;
            };
            debug!(node = %self.public_key(), height = %h, "initialized");
            return Submitter {
                client: self.client,
                config: self.config,
                height: h,
            };
        }
    }
}

impl Submitter<Height> {
    pub async fn submit(&mut self, cb: CertifiedBlock) {
        enum State {
            Submit(bool),
            Verify,
        }

        let delay = Duration::from_secs(30);
        let mut state = State::Submit(false);

        loop {
            match state {
                State::Submit(force) => match timeout(delay, self.submit_block(&cb, force)).await {
                    Ok(()) => state = State::Verify,
                    Err(e) => {
                        debug!(
                            node = %self.public_key(),
                            num  = %cb.cert().data().num(),
                            "block submission timeout"
                        );
                        let _: Elapsed = e;
                        state = State::Submit(true)
                    }
                },
                State::Verify => match timeout(delay, self.verify_inclusion(&cb)).await {
                    Ok(Ok(())) => {
                        debug!(
                            node = %self.public_key(),
                            num  = %cb.cert().data().num(),
                            "block submission verified"
                        );
                        return;
                    }
                    Ok(Err(())) => {
                        debug!(
                            node = %self.public_key(),
                            num  = %cb.cert().data().num(),
                            "block submission verification failed"
                        );
                        state = State::Submit(true)
                    }
                    Err(e) => {
                        debug!(
                            node = %self.public_key(),
                            num  = %cb.cert().data().num(),
                            "block submission verification timeout"
                        );
                        let _: Elapsed = e;
                        state = State::Submit(true)
                    }
                },
            }
        }
    }

    pub async fn submit_block(&mut self, cb: &CertifiedBlock, force: bool) {
        if !(cb.is_leader() || force) {
            return;
        }
        let mut delays = delay_iter();
        debug!(
            node      = %self.public_key(),
            is_leader = cb.is_leader(),
            force     = %force,
            num       = %cb.cert().data().num(),
            round     = %cb.cert().data().round(),
            "submitting block"
        );
        while let Err(err) = self.client.submit(cb).await {
            warn!(node = %self.public_key(), %err, "error submitting block");
            let d = delays.next().expect("delay iterator repeats");
            sleep(d).await
        }
    }

    pub async fn verify_inclusion(&mut self, cb: &CertifiedBlock) -> Result<(), ()> {
        debug!(
            node  = %self.public_key(),
            num   = %cb.cert().data().num(),
            round = %cb.cert().data().round(),
            "verifying block inclusion"
        );
        let nsid = NamespaceId::from(u64::from(u32::from(cb.data().namespace())));
        let mut delays = delay_iter();
        loop {
            let Ok(header) = robusta::watch(&self.config.robusta, self.height, nsid).await else {
                let d = delays.next().expect("delay iterator repeats");
                sleep(d).await;
                continue;
            };
            delays = delay_iter();
            match self.client.verify(&header, cb).await {
                Ok(()) => {
                    self.height = Height::from(header.height() + 1);
                    return Ok(());
                }
                Err(Error::TransactionNotFound) => {
                    self.height = Height::from(header.height() + 1);
                }
                Err(Error::Proof(err)) => {
                    warn!(node = %self.config.pubkey, %err, "proof validation failed");
                    self.height = Height::from(header.height() + 1);
                    return Err(());
                }
                Err(err) => {
                    warn!(node = %self.config.pubkey, %err, "error during verification");
                    let d = delays.next().expect("delay iterator repeats");
                    sleep(d).await
                }
            }
        }
    }
}

fn delay_iter() -> impl Iterator<Item = Duration> {
    [1, 1, 1, 3]
        .into_iter()
        .chain(repeat(5))
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use multisig::{Committee, Keypair, PublicKey, Signed, VoteAccumulator};
    use timeboost_types::{Block, BlockHash, BlockInfo, BlockNumber, NamespaceId, sailfish::Round};
    use tokio::{task::JoinSet, time::sleep};

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

        let rcfg = robusta::Config::builder()
            .base_url("https://query.decaf.testnet.espresso.network/v1/")
            .unwrap()
            .wss_base_url("wss://query.decaf.testnet.espresso.network/v1/")
            .unwrap()
            .build();

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

            let scfg = SubmitterConfig::builder()
                .pubkey(k.public_key())
                .robusta(rcfg.clone())
                .build();

            let mut s = Submitter::new(scfg).init().await;

            tasks.spawn(async move {
                for _ in 0..3 {
                    s.submit(g.next()).await;
                    sleep(Duration::from_secs(rand::random_range(0..5))).await
                }
            });
        }

        tasks.join_all().await;
    }
}

mod certifier;
mod config;
mod submit;

pub use certifier::{Certifier, CertifierDown, CertifierError, Handle};
pub use config::{CertifierConfig, CertifierConfigBuilder};
pub use config::{SubmitterConfig, SubmitterConfigBuilder};
pub use robusta;
pub use submit::Submitter;

use std::time::Duration;

use robusta::Height;
use timeboost_types::CertifiedBlock;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tracing::debug;

pub async fn submit(s: &mut Submitter<Height>, cb: CertifiedBlock) {
    enum State {
        Submit(bool),
        Verify,
    }

    let delay = Duration::from_secs(30);
    let mut state = State::Submit(false);

    loop {
        match state {
            State::Submit(force) => match timeout(delay, s.submit(&cb, force)).await {
                Ok(()) => state = State::Verify,
                Err(e) => {
                    debug!(
                        node = %s.public_key(),
                        num  = %cb.cert().data().num(),
                        "block submission timeout"
                    );
                    let _: Elapsed = e;
                    state = State::Submit(true)
                }
            },
            State::Verify => match timeout(delay, s.verify(&cb)).await {
                Ok(Ok(())) => {
                    debug!(
                        node = %s.public_key(),
                        num  = %cb.cert().data().num(),
                        "block submission verified"
                    );
                    return;
                }
                Ok(Err(())) => {
                    debug!(
                        node = %s.public_key(),
                        num  = %cb.cert().data().num(),
                        "block submission verification failed"
                    );
                    state = State::Submit(true)
                }
                Err(e) => {
                    debug!(
                        node = %s.public_key(),
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
                    submit(&mut s, g.next()).await;
                    sleep(Duration::from_secs(rand::random_range(0..5))).await
                }
            });
        }

        tasks.join_all().await;
    }
}

use std::{iter::repeat, time::Duration};

use multisig::PublicKey;
use robusta::{Error, Height, espresso_types::NamespaceId};
use timeboost_types::CertifiedBlock;
use tokio::time::sleep;
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
    pub async fn submit(&mut self, cb: &CertifiedBlock, force: bool) {
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

    pub async fn verify(&mut self, cb: &CertifiedBlock) -> Result<(), ()> {
        debug!(
            node  = %self.public_key(),
            num   = %cb.cert().data().num(),
            round = %cb.cert().data().round(),
            "verifying block submission"
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
                    warn!(node = %self.config.pubkey, %err, "error during validation");
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

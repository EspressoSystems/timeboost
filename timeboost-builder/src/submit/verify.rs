use std::{collections::BTreeSet, sync::Arc};

use bon::Builder;
use multisig::PublicKey;
use parking_lot::RwLock;
use robusta::{Client, Config, Multiwatcher, espresso_types::NamespaceId};
use timeboost_types::{
    BlockNumber,
    sailfish::{CommitteeVec, Empty, RoundNumber},
};
use tokio::{sync::Mutex, time::sleep};
use tracing::debug;

use crate::metrics::BuilderMetrics;

#[cfg(feature = "times")]
use crate::time_series::VERIFIED;

/// Verifies blocks and updates a sliding window of block numbers.
#[derive(Debug, Builder)]
pub struct Verifier {
    label: PublicKey,
    nsid: NamespaceId,
    client: Client,
    committees: Arc<Mutex<CommitteeVec<2>>>,
    verified: Verified<15_000>,
    metrics: Arc<BuilderMetrics>,
}

impl Verifier {
    pub async fn verify(self, configs: Vec<Config>) -> Empty {
        let mut delays = self.client.config().delay_iter();
        let height = loop {
            if let Ok(h) = self.client.height().await {
                break h;
            };
            let d = delays.next().expect("delay iterator repeats endlessly");
            sleep(d).await;
        };
        let threshold = 2 * configs.len() / 3 + 1;
        let mut watcher = Multiwatcher::new(configs, height, self.nsid, threshold);
        loop {
            let h = watcher.next().await;
            let committees = self.committees.lock().await;
            let numbers = self.client.verified(self.nsid, &h, &committees).await;
            let len = self.verified.insert(numbers);
            debug!(node = %self.label, blocks = %len, "blocks verified");
            self.metrics.blocks_verified.add(len);
        }
    }
}

/// The sliding window of verified block numbers.
#[derive(Debug, Default, Clone)]
pub struct Verified<const MAX_SIZE: usize> {
    set: Arc<RwLock<BTreeSet<BlockNumber>>>,
}

impl<const MAX_SIZE: usize> Verified<MAX_SIZE> {
    /// Is the given block number verified?
    pub fn contains(&self, n: BlockNumber) -> bool {
        self.set.read().contains(&n)
    }

    /// Add a sequence of block numbers as verified.
    ///
    /// Returns the number of (unique) block numbers added.
    fn insert<I>(&self, it: I) -> usize
    where
        I: IntoIterator<Item = (BlockNumber, RoundNumber)>,
    {
        let mut set = self.set.write();
        let len = set.len();
        for b in it {
            set.insert(b.0);
            #[cfg(feature = "times")]
            times::record(VERIFIED, *b.1)
        }
        let len = set.len() - len;
        while set.len() > MAX_SIZE {
            set.pop_first();
        }
        len
    }
}

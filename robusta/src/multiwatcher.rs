use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::{Config, Height, Watcher};
use either::Either;
use espresso_types::{Header, NamespaceId};
use futures::{StreamExt, stream::SelectAll};
use tokio::{
    spawn,
    sync::{Barrier, mpsc},
    task::JoinHandle,
    time::sleep,
};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct Multiwatcher {
    threshold: usize,
    lower_bound: Arc<AtomicU64>,
    watchers: Vec<JoinHandle<()>>,
    headers: BTreeMap<Height, HashMap<Header, HashSet<Id>>>,
    stream: SelectAll<ReceiverStream<(Id, Header)>>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct Id(usize);

impl Drop for Multiwatcher {
    fn drop(&mut self) {
        for w in &self.watchers {
            w.abort();
        }
    }
}

impl Multiwatcher {
    pub fn new<C, H, N>(configs: C, height: H, nsid: N, threshold: usize) -> Self
    where
        C: IntoIterator<Item = Config>,
        H: Into<Height>,
        N: Into<NamespaceId>,
    {
        let height = height.into();
        let nsid = nsid.into();

        // We require `threshold` watchers to deliver the next header.
        // Adversaries may produce headers in quick succession, causing
        // excessive memory usage.
        let barrier = Arc::new(Barrier::new(threshold));

        // We track the last delivered height as a lower bound.
        // Watchers skip over headers up to and including that height.
        let lower_bound = Arc::new(AtomicU64::new(height.into()));

        let mut stream = SelectAll::new();
        let mut watchers = Vec::new();

        for (i, c) in configs.into_iter().enumerate() {
            let (tx, rx) = mpsc::channel(10);
            stream.push(ReceiverStream::new(rx));
            let barrier = barrier.clone();
            let lower_bound = lower_bound.clone();
            watchers.push(spawn(async move {
                let i = Id(i);
                loop {
                    let height = lower_bound.load(Ordering::Relaxed);
                    let mut w = Watcher::new(c.clone(), height, nsid);
                    let mut expected = height + 1;
                    loop {
                        match w.next().await {
                            Either::Right(hdr) => {
                                if hdr.height() > expected {
                                    warn!(
                                        url      = %c.wss_base_url,
                                        height   = %hdr.height(),
                                        expected = %expected,
                                        "unexpected block height"
                                    );
                                    break;
                                }
                                expected += 1;
                                if hdr.height() <= lower_bound.load(Ordering::Relaxed) {
                                    continue;
                                }
                                if tx.send((i, hdr)).await.is_err() {
                                    return;
                                }
                            }
                            Either::Left(height) => {
                                if *height > expected {
                                    warn!(
                                        url      = %c.wss_base_url,
                                        height   = %height,
                                        expected = %expected,
                                        "unexpected block height"
                                    );
                                    break;
                                }
                                expected += 1;
                            }
                        }
                        barrier.wait().await;
                    }
                    drop(w);
                    sleep(Duration::from_secs(3)).await // wait a little before re-connecting
                }
            }));
        }

        assert!(!watchers.is_empty());

        Self {
            threshold,
            stream,
            watchers,
            lower_bound,
            headers: BTreeMap::from_iter([(height, HashMap::new())]),
        }
    }

    pub async fn next(&mut self) -> Header {
        loop {
            let (i, hdr) = self.stream.next().await.expect("watchers never terminate");
            let h = Height::from(hdr.height());
            if Some(h) < self.headers.first_entry().map(|e| *e.key()) {
                debug!(height = %h, "ignoring header below minimum height");
                continue;
            }
            if self.has_voted(h, i) {
                warn!(height = %h, "source sent multiple headers for same height");
                continue;
            }
            let counter = self.headers.entry(h).or_default();
            let votes = counter.get(&hdr).map(|ids| ids.len()).unwrap_or(0) + 1;
            if votes >= self.threshold {
                self.headers.retain(|k, _| *k > h);
                self.lower_bound.store(h.into(), Ordering::Relaxed);
                debug!(height = %h, "header available");
                return hdr;
            }
            debug!(height = %h, %votes, "vote added");
            counter.entry(hdr).or_default().insert(i);
        }
    }

    fn has_voted(&self, height: Height, id: Id) -> bool {
        let Some(m) = self.headers.get(&height) else {
            return false;
        };
        for ids in m.values() {
            if ids.contains(&id) {
                return true;
            }
        }
        false
    }
}

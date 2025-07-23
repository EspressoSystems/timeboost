use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Config, Height, Watcher};
use espresso_types::{Header, NamespaceId};
use futures::{StreamExt, stream::SelectAll};
use tokio::{spawn, sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug)]
pub struct Multiwatcher {
    height: Height,
    threshold: usize,
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
    pub fn new<C, H, I, N>(configs: C, height: H, nsid: N, threshold: usize) -> Self
    where
        C: IntoIterator<Item = Config>,
        H: Into<Height>,
        I: IntoIterator<Item = Url>,
        N: Into<NamespaceId>,
    {
        let height = height.into();
        let nsid = nsid.into();
        let mut stream = SelectAll::new();
        let mut watchers = Vec::new();
        for (i, c) in configs.into_iter().enumerate() {
            let (tx, rx) = mpsc::channel(32);
            stream.push(ReceiverStream::new(rx));
            watchers.push(spawn(async move {
                let id = Id(i);
                let mut w = Watcher::new(c, height, nsid);
                while tx.send((id, w.next().await)).await.is_ok() {}
            }));
        }
        Self {
            height,
            threshold,
            stream,
            watchers,
            headers: BTreeMap::from_iter([(height, HashMap::new())]),
        }
    }

    pub async fn next(&mut self) -> Option<Header> {
        loop {
            let (i, hdr) = self.stream.next().await?;
            let h = Height::from(hdr.height());
            if Some(h) < self.headers.first_entry().map(|e| *e.key()) {
                debug!(%h, "ignoring header below minimum height");
                continue;
            }
            if self.has_voted(h, i) {
                warn!(%h, "source sent multiple headers for same height");
                continue;
            }
            let votes = self.headers.entry(h).or_default();
            if let Some(ids) = votes.get(&hdr)
                && ids.len() + 1 >= self.threshold
            {
                self.gc(h);
                return Some(hdr);
            }
            votes.entry(hdr).or_default().insert(i);
        }
    }

    fn has_voted(&self, height: Height, id: Id) -> bool {
        let Some(m) = self.headers.get(&height) else {
            return false;
        };
        for v in m.values() {
            if v.contains(&id) {
                return true;
            }
        }
        false
    }

    fn gc(&mut self, height: Height) {
        self.headers.retain(|h, _| *h >= height);
        self.height = height;
    }
}

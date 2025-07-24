use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{Config, Height, Watcher};
use espresso_types::{Header, NamespaceId};
use futures::{StreamExt, stream::SelectAll};
use tokio::{spawn, sync::mpsc, task::JoinHandle};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct Multiwatcher {
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
    pub fn new<C, H, N>(configs: C, height: H, nsid: N, threshold: usize) -> Self
    where
        C: IntoIterator<Item = Config>,
        H: Into<Height>,
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
        assert!(!watchers.is_empty());
        Self {
            threshold,
            stream,
            watchers,
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

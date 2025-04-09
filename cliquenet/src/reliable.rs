use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use multisig::{Keypair, PublicKey};
use parking_lot::Mutex;
use tokio::spawn;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration, Instant};
use tracing::warn;

use crate::{Address, NetworkError, NetworkMetrics, unreliable};

type Result<T> = std::result::Result<T, NetworkError>;

#[derive(Debug)]
pub struct Network {
    this: PublicKey,
    net: unreliable::Network,
    parties: Vec<PublicKey>,
    buffer: Buffer,
    id: SeqId,
    retry: JoinHandle<Infallible>,
}

impl Drop for Network {
    fn drop(&mut self) {
        self.retry.abort()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeqId(u64);

#[derive(Debug, Clone, Default)]
struct Buffer(Arc<Mutex<BTreeMap<SeqId, Message>>>);

#[derive(Debug)]
struct Message {
    data: Bytes,
    time: Instant,
    retries: usize,
    remaining: Vec<PublicKey>,
}

impl Network {
    pub async fn create<P, A1, A2>(
        bind_to: A1,
        kp: Keypair,
        group: P,
        metrics: NetworkMetrics,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
    {
        let lbl = kp.public_key();
        let mut parties = Vec::new();
        let mut peers = Vec::new();
        for (k, a) in group {
            parties.push(k);
            peers.push((k, a));
        }
        let net = unreliable::Network::create(bind_to, kp, peers, metrics).await?;
        let buf = Buffer::default();
        let tsk = spawn(retry(buf.clone(), net.sender()));
        Ok(Self {
            this: lbl,
            net,
            parties,
            buffer: buf,
            id: SeqId(0),
            retry: tsk,
        })
    }

    #[cfg(feature = "turmoil")]
    pub async fn create_turmoil<P, A1, A2>(
        bind_to: A1,
        kp: Keypair,
        group: P,
        metrics: NetworkMetrics,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
    {
        let lbl = kp.public_key();
        let mut parties = Vec::new();
        let mut peers = Vec::new();
        for (k, a) in group {
            parties.push(k);
            peers.push((k, a));
        }
        let net = unreliable::Network::create_turmoil(bind_to, kp, peers, metrics).await?;
        let buf = Buffer::default();
        let tsk = spawn(retry(buf.clone(), net.sender()));
        Ok(Self {
            this: lbl,
            net,
            parties,
            buffer: buf,
            id: SeqId(0),
            retry: tsk,
        })
    }

    pub async fn send(&mut self, to: Option<PublicKey>, mut msg: BytesMut) -> Result<SeqId> {
        let id = self.next_id();

        msg.extend_from_slice(&id.0.to_be_bytes());
        let msg = msg.freeze();

        let rem = if let Some(to) = to {
            self.net.unicast(to, msg.clone()).await?;
            vec![to]
        } else {
            self.net.multicast(msg.clone()).await?;
            self.parties.clone()
        };

        self.buffer.0.lock().insert(
            id,
            Message {
                data: msg,
                time: Instant::now(),
                retries: 0,
                remaining: rem,
            },
        );

        Ok(id)
    }

    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
        loop {
            let (src, mut bytes) = self.net.receive().await?;

            if bytes.len() < 8 {
                warn!(node = %self.this, "received unexpected message");
                return Ok((src, bytes));
            }

            let tail: [u8; 8] = bytes
                .split_off(bytes.len() - 8)
                .as_ref()
                .try_into()
                .expect("bytes len checked above");

            if !bytes.is_empty() {
                // Send the Id value back as acknowledgement:
                self.net.unicast(src, Bytes::copy_from_slice(&tail)).await?;
                return Ok((src, bytes));
            }

            let id = SeqId(u64::from_be_bytes(tail));

            let mut messages = self.buffer.0.lock();
            if let Some(m) = messages.get_mut(&id) {
                m.remaining.retain(|k| *k != src);
                if m.remaining.is_empty() {
                    messages.remove(&id);
                }
            }
        }
    }

    pub fn gc(&mut self, id: SeqId) {
        self.buffer.0.lock().retain(|i, _| *i >= id);
    }

    fn next_id(&mut self) -> SeqId {
        let id = self.id;
        self.id = SeqId(self.id.0 + 1);
        id
    }
}

async fn retry(buf: Buffer, net: Sender<(Option<PublicKey>, Bytes)>) -> Infallible {
    const DELAYS: [u64; 4] = [3, 5, 10, 15];

    let mut i = time::interval(Duration::from_secs(1));
    i.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut ids = Vec::new();

    loop {
        let now = i.tick().await;

        debug_assert!(ids.is_empty());
        ids.extend(buf.0.lock().keys().copied());

        for id in ids.drain(..) {
            let message;
            let remaining;

            {
                let mut buf = buf.0.lock();
                let Some(m) = buf.get_mut(&id) else { continue };

                let delay = DELAYS.get(m.retries).copied().unwrap_or(30);
                if now.saturating_duration_since(m.time) < Duration::from_secs(delay) {
                    continue;
                }

                m.time = now;
                m.retries = m.retries.saturating_add(1);

                message = m.data.clone();
                remaining = m.remaining.clone();
            }

            for p in remaining {
                let _ = net.send((Some(p), message.clone())).await;
            }
        }
    }
}

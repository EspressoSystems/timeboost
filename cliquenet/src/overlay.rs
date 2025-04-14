use std::collections::BTreeMap;
use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use multisig::PublicKey;
use parking_lot::Mutex;
use thiserror::Error;
use tokio::spawn;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration, Instant};
use tracing::warn;

use crate::Network;

type Result<T> = std::result::Result<T, NetworkDown>;

#[derive(Debug)]
pub struct Overlay {
    this: PublicKey,
    net: Network,
    sender: Sender<(Option<PublicKey>, Bytes)>,
    parties: Vec<PublicKey>,
    buffer: Buffer,
    id: SeqId,
    retry: JoinHandle<Infallible>,
}

impl Drop for Overlay {
    fn drop(&mut self) {
        self.retry.abort()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeqId(u64);

#[derive(Debug, Clone)]
pub struct Data(BytesMut);

#[derive(Debug, Clone, Default)]
struct Buffer(Arc<Mutex<BTreeMap<SeqId, Message>>>);

#[derive(Debug)]
struct Message {
    data: Bytes,
    time: Instant,
    retries: usize,
    remaining: Vec<PublicKey>,
}

impl Overlay {
    pub fn new(net: Network) -> Self {
        let buffer = Buffer::default();
        let retry = spawn(retry(buffer.clone(), net.sender()));
        Self {
            this: net.public_key(),
            parties: net.parties().copied().collect(),
            sender: net.sender(),
            net,
            buffer,
            id: SeqId(0),
            retry,
        }
    }

    pub async fn broadcast(&mut self, data: Data) -> Result<SeqId> {
        self.send(None, data).await
    }

    pub async fn unicast(&mut self, to: PublicKey, data: Data) -> Result<SeqId> {
        self.send(Some(to), data).await
    }

    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
        loop {
            let (src, mut bytes) = self.net.receive().await.map_err(|_| NetworkDown(()))?;

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
                let ack = Bytes::copy_from_slice(&tail);
                self.sender
                    .send((Some(src), ack))
                    .await
                    .map_err(|_| NetworkDown(()))?;
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

    async fn send(&mut self, to: Option<PublicKey>, data: Data) -> Result<SeqId> {
        let id = self.next_id();

        let mut msg = data.0;

        msg.extend_from_slice(&id.0.to_be_bytes());
        let msg = msg.freeze();

        let now = Instant::now();

        let rem = if let Some(to) = to {
            self.sender
                .send((Some(to), msg.clone()))
                .await
                .map_err(|_| NetworkDown(()))?;
            vec![to]
        } else {
            self.sender
                .send((None, msg.clone()))
                .await
                .map_err(|_| NetworkDown(()))?;
            self.parties.clone()
        };

        self.buffer.0.lock().insert(
            id,
            Message {
                data: msg,
                time: now,
                retries: 0,
                remaining: rem,
            },
        );

        Ok(id)
    }

    fn next_id(&mut self) -> SeqId {
        let id = self.id;
        self.id = SeqId(self.id.0 + 1);
        id
    }
}

async fn retry(buf: Buffer, net: Sender<(Option<PublicKey>, Bytes)>) -> Infallible {
    const DELAYS: [u64; 4] = [1, 3, 5, 15];

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

#[derive(Debug, Error)]
#[error("network down")]
pub struct NetworkDown(());

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DataError {
    #[error("data size exceeds allowed maximum")]
    MaxSize,
}

impl TryFrom<BytesMut> for Data {
    type Error = DataError;

    fn try_from(val: BytesMut) -> std::result::Result<Self, Self::Error> {
        if val.len() > crate::net::MAX_TOTAL_SIZE {
            return Err(DataError::MaxSize);
        }
        Ok(Self(val))
    }
}

impl Deref for Data {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

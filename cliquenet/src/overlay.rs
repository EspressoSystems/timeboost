use std::collections::{BTreeMap, HashMap};
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

/// Max. bucket number.
pub const MAX_BUCKET: Bucket = Bucket(u64::MAX);

/// `Overlay` wraps a [`Network`] and returns acknowledgements to senders.
///
/// It also retries messages until either an acknowledgement has been received
/// or client code has indicated that the messages are no longer of interest
/// by invoking `Overlay::gc`.
///
/// Each message that is sent has a trailer appended that contains the bucket
/// number and ID of the message. Receivers will send this trailer back. The
/// sender then stops retrying the corresponding message.
///
/// Note that if malicious parties modify the trailer and have it point to a
/// different message, they can only remove themselves from the set of parties
/// the sender is expecting an acknowledgement from.
#[derive(Debug)]
pub struct Overlay {
    this: PublicKey,
    net: Network,
    sender: Sender<(Option<PublicKey>, Bytes)>,
    parties: Vec<PublicKey>,
    id: Id,
    buffer: Buffer,
    retry: JoinHandle<Infallible>,
}

impl Drop for Overlay {
    fn drop(&mut self) {
        self.retry.abort()
    }
}

/// Newtype wrapping some length-checked bytes.
///
/// This exists to allow clients to construct a message item that will
/// not be rejected by the network due to size violations (see the
/// `TryFrom<BytesMut>` impl for details).
#[derive(Debug, Clone)]
pub struct Data(BytesMut);

/// Buckets conceptionally contain messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bucket(u64);

/// A message ID uniquely identifies as message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(u64);

/// Messages are associated with IDs and put into buckets.
///
/// Bucket numbers are given to us by clients which also garbage collect
/// explicitly by specifying the bucket up to which to remove messages.
/// Buckets often correspond to rounds elsewhere.
#[derive(Debug, Clone, Default)]
struct Buffer(Arc<Mutex<BTreeMap<Bucket, HashMap<Id, Message>>>>);

#[derive(Debug)]
struct Message {
    /// The message bytes to (re-)send.
    data: Bytes,
    /// The time we started sending this message.
    time: Instant,
    /// The number of times we have sent this message.
    retries: usize,
    /// The remaining number of parties that have to acknowledge the message.
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
            id: Id(0),
            retry,
        }
    }

    pub async fn broadcast<B>(&mut self, b: B, data: Data) -> Result<Id>
    where
        B: Into<Bucket>,
    {
        self.send(b.into(), None, data).await
    }

    pub async fn unicast<B>(&mut self, to: PublicKey, b: B, data: Data) -> Result<Id>
    where
        B: Into<Bucket>,
    {
        self.send(b.into(), Some(to), data).await
    }

    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
        loop {
            let (src, mut bytes) = self.net.receive().await.map_err(|_| NetworkDown(()))?;

            if bytes.len() < 16 {
                warn!(node = %self.this, "received unexpected message");
                return Ok((src, bytes));
            }

            let trailer: [u8; 16] = bytes
                .split_off(bytes.len() - 16)
                .as_ref()
                .try_into()
                .expect("bytes len checked above");

            if !bytes.is_empty() {
                // Send the trailer back as acknowledgement:
                let ack = Bytes::copy_from_slice(&trailer);
                self.sender
                    .send((Some(src), ack))
                    .await
                    .map_err(|_| NetworkDown(()))?;
                return Ok((src, bytes));
            }

            let (b, i) = from_trailer(&trailer);

            let mut messages = self.buffer.0.lock();

            if let Some(buckets) = messages.get_mut(&b) {
                if let Some(m) = buckets.get_mut(&i) {
                    m.remaining.retain(|k| *k != src);
                    if m.remaining.is_empty() {
                        buckets.remove(&i);
                    }
                }
            }
        }
    }

    pub fn gc<B: Into<Bucket>>(&mut self, bucket: B) {
        let bucket = bucket.into();
        self.buffer.0.lock().retain(|b, _| *b >= bucket);
    }

    pub fn rm(&mut self, bucket: Bucket, id: Id) {
        if let Some(messages) = self.buffer.0.lock().get_mut(&bucket) {
            messages.remove(&id);
        }
    }

    async fn send(&mut self, b: Bucket, to: Option<PublicKey>, data: Data) -> Result<Id> {
        let i = self.next_id();

        let mut msg = data.0;

        msg.extend_from_slice(&to_trailer(b, i));
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

        self.buffer.0.lock().entry(b).or_default().insert(
            i,
            Message {
                data: msg,
                time: now,
                retries: 0,
                remaining: rem,
            },
        );

        Ok(i)
    }

    fn next_id(&mut self) -> Id {
        let id = self.id;
        self.id = Id(self.id.0 + 1);
        id
    }
}

/// Serialize a `Bucket` and `Id`.
fn to_trailer(b: Bucket, i: Id) -> [u8; 16] {
    let mut t = [0; 16];
    t[..8].copy_from_slice(&b.0.to_be_bytes());
    t[8..].copy_from_slice(&i.0.to_be_bytes());
    t
}

/// Deserialize into `Bucket` and `Id`.
fn from_trailer(t: &[u8; 16]) -> (Bucket, Id) {
    let b = u64::from_be_bytes(t[..8].try_into().expect("8 bytes"));
    let i = u64::from_be_bytes(t[8..].try_into().expect("8 bytes"));
    (Bucket(b), Id(i))
}

async fn retry(buf: Buffer, net: Sender<(Option<PublicKey>, Bytes)>) -> Infallible {
    const DELAYS: [u64; 4] = [1, 3, 5, 15];

    let mut i = time::interval(Duration::from_secs(1));
    i.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut buckets = Vec::new();
    let mut ids = Vec::new();

    loop {
        let now = i.tick().await;

        debug_assert!(buckets.is_empty());
        buckets.extend(buf.0.lock().keys().copied());

        for b in buckets.drain(..) {
            debug_assert!(ids.is_empty());
            ids.extend(
                buf.0
                    .lock()
                    .get(&b)
                    .into_iter()
                    .flat_map(|m| m.keys().copied()),
            );

            for id in ids.drain(..) {
                let message;
                let remaining;

                {
                    let mut buf = buf.0.lock();
                    let Some(m) = buf.get_mut(&b).and_then(|m| m.get_mut(&id)) else {
                        continue;
                    };

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
        if val.len() > crate::MAX_MESSAGE_SIZE {
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

impl From<u64> for Bucket {
    fn from(val: u64) -> Self {
        Bucket(val)
    }
}

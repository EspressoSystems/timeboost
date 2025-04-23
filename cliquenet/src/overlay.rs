use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::ops::Deref;
use std::sync::Arc;

use bincode::config::{Configuration, Limit, LittleEndian, Varint};
use bincode::{Decode, Encode};
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
/// the sender is expecting an acknowledgement from. However, if they change the
/// tag of a message, client code may classify the data incorrectly. The tag
/// can thus not be trusted and client code needs to be able to handle data that
/// does not match its tag. It is best used for data that the sender can anyway
/// easily produce.
#[derive(Debug)]
pub struct Overlay {
    this: PublicKey,
    net: Network,
    sender: Sender<(Option<PublicKey>, Bytes)>,
    parties: Vec<PublicKey>,
    id: Id,
    buffer: Buffer,
    encoded: [u8; Trailer::MAX_LEN],
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
pub struct Data {
    bytes: BytesMut,
    tag: Tag,
}

/// Buckets conceptionally contain messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Bucket(u64);

/// A message ID uniquely identifies as message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Id(u64);

/// A tag that can be attached to `Data` to allow classification.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Tag(u8);

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

/// Meta information appended at the end of a message.
#[derive(Debug, Encode, Decode)]
struct Trailer {
    /// The bucket number the message corresponds to.
    bucket: Bucket,
    /// The message ID.
    id: Id,
    /// The tag of a message.
    tag: Tag,
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
            encoded: [0; Trailer::MAX_LEN],
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

    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes, Tag)> {
        loop {
            let (src, mut bytes) = self.net.receive().await.map_err(|_| NetworkDown(()))?;

            let Some(trailer_bytes) = Trailer::split_off(&mut bytes) else {
                warn!(node = %self.this, "invalid trailer bytes");
                continue;
            };

            let trailer = match Trailer::decode(&trailer_bytes) {
                Ok(t) => t,
                Err(e) => {
                    warn!(node = %self.this, err = %e, "invalid trailer");
                    continue;
                }
            };

            if !bytes.is_empty() {
                // Send the trailer back as acknowledgement:
                self.sender
                    .send((Some(src), trailer_bytes))
                    .await
                    .map_err(|_| NetworkDown(()))?;
                return Ok((src, bytes, trailer.tag));
            }

            let mut messages = self.buffer.0.lock();

            if let Some(buckets) = messages.get_mut(&trailer.bucket) {
                if let Some(m) = buckets.get_mut(&trailer.id) {
                    m.remaining.retain(|k| *k != src);
                    if m.remaining.is_empty() {
                        buckets.remove(&trailer.id);
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
        let id = self.next_id();

        let trailer = Trailer {
            bucket: b,
            id,
            tag: data.tag,
        };

        let trailer_bytes = trailer.encode(&mut self.encoded);

        let mut msg = data.bytes;

        msg.extend_from_slice(trailer_bytes);
        msg.extend_from_slice(&[trailer_bytes.len().try_into().expect("|trailer| <= 32")]);
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

    fn next_id(&mut self) -> Id {
        let id = self.id;
        self.id = Id(self.id.0 + 1);
        id
    }
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
        Ok(Self {
            bytes: val,
            tag: Tag::default(),
        })
    }
}

impl Deref for Data {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes.as_ref()
    }
}

impl From<u64> for Bucket {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<u8> for Tag {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

impl Data {
    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub fn set_tag(&mut self, t: Tag) {
        self.tag = t
    }
}

impl Trailer {
    /// Max. byte length of a trailer.
    pub const MAX_LEN: usize = 32;

    const BINCONF: Configuration<LittleEndian, Varint, Limit<{ Self::MAX_LEN }>> =
        bincode::config::standard().with_limit::<{ Self::MAX_LEN }>();

    fn split_off(bytes: &mut Bytes) -> Option<Bytes> {
        let len = usize::from(*bytes.last()?);

        if bytes.len() < len + 1 {
            return None;
        }

        Some(bytes.split_off(bytes.len() - (len + 1)))
    }

    fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::error::DecodeError> {
        bincode::decode_from_slice(bytes, Self::BINCONF).map(|(t, _)| t)
    }

    fn encode<'a>(&self, buf: &'a mut [u8; Self::MAX_LEN]) -> &'a [u8] {
        let len = bincode::encode_into_slice(self, buf, Self::BINCONF)
            .expect("trailer encoding never fails");
        &buf[..len]
    }
}

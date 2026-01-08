use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fmt;
use std::ops::Deref;
use std::sync::Arc;

use bincode::config::{Configuration, Limit, LittleEndian, Varint};
use bincode::{Decode, Encode};
use bytes::{Bytes, BytesMut};
use multisig::{PublicKey, x25519};
use nohash_hasher::IntMap;
use parking_lot::Mutex;
#[cfg(feature = "metrics")]
use prometheus::{IntGauge, register_int_gauge};
use thiserror::Error;
use tokio::spawn;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinHandle;
use tokio::time::{self, Duration, Instant};
use tracing::warn;

use crate::net::Command;
use crate::{Address, Id, Network, Role};

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
    sender: Sender<Command>,
    id: Id,
    buffer: Buffer,
    encoded: [u8; Trailer::MAX_LEN],
    retry: JoinHandle<Infallible>,
    cutoff: Bucket,
}

impl Drop for Overlay {
    fn drop(&mut self) {
        self.retry.abort()
    }
}

/// Data wraps some length-checked, tagged bytes.
///
/// This exists to allow clients to construct a message item that will
/// not be rejected by the network due to size violations (see the
/// `TryFrom<(Tag, BytesMut)>` impl for details).
#[derive(Debug, Clone)]
pub struct Data {
    bytes: BytesMut,
}

/// Buckets conceptionally contain messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
pub struct Bucket(u64);

/// Messages are associated with IDs and put into buckets.
///
/// Bucket numbers are given to us by clients which also garbage collect
/// explicitly by specifying the bucket up to which to remove messages.
/// Buckets often correspond to rounds elsewhere.
#[derive(Debug, Clone, Default)]
#[allow(clippy::type_complexity)]
struct Buffer(Arc<Mutex<BTreeMap<Bucket, IntMap<Id, Message>>>>);

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
}

enum Target {
    Single(PublicKey),
    Multi(Vec<PublicKey>),
    All,
}

impl Overlay {
    pub fn new(net: Network) -> Self {
        let buffer = Buffer::default();
        #[cfg(feature = "metrics")]
        let m_gauge = register_int_gauge!(
            format!("{}_overlay_messages", net.name()),
            "in-flight messages"
        )
        .expect("valid metric definition");
        let retry = spawn(retry(
            buffer.clone(),
            net.sender(),
            #[cfg(feature = "metrics")]
            m_gauge,
        ));
        Self {
            this: net.public_key(),
            sender: net.sender(),
            net,
            buffer,
            encoded: [0; Trailer::MAX_LEN],
            id: Id::from(0),
            retry,
            cutoff: Bucket(0),
        }
    }

    pub fn parties(&self) -> impl Iterator<Item = (&PublicKey, &Role)> {
        self.net.parties()
    }

    pub async fn broadcast<B>(&mut self, b: B, data: Data) -> Result<Id>
    where
        B: Into<Bucket>,
    {
        self.send(b.into(), Target::All, data).await
    }

    pub async fn multicast<B>(&mut self, to: Vec<PublicKey>, b: B, data: Data) -> Result<Id>
    where
        B: Into<Bucket>,
    {
        self.send(b.into(), Target::Multi(to), data).await
    }

    pub async fn unicast<B>(&mut self, to: PublicKey, b: B, data: Data) -> Result<Id>
    where
        B: Into<Bucket>,
    {
        self.send(b.into(), Target::Single(to), data).await
    }

    pub async fn add(&mut self, peers: Vec<(PublicKey, x25519::PublicKey, Address)>) -> Result<()> {
        self.net.add(peers).await.map_err(|_| NetworkDown(()))
    }

    pub async fn remove(&mut self, peers: Vec<PublicKey>) -> Result<()> {
        self.net.remove(peers).await.map_err(|_| NetworkDown(()))
    }

    pub async fn assign(&mut self, r: Role, peers: Vec<PublicKey>) -> Result<()> {
        self.net.assign(r, peers).await.map_err(|_| NetworkDown(()))
    }

    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
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
                    .send(Command::Unicast(src, None, trailer_bytes))
                    .await
                    .map_err(|_| NetworkDown(()))?;
                if trailer.bucket < self.cutoff {
                    continue;
                }
                return Ok((src, bytes));
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
        self.cutoff = bucket;
        self.buffer.0.lock().retain(|b, _| *b >= bucket);
    }

    pub fn rm<B: Into<Bucket>>(&mut self, bucket: B, id: Id) {
        let bucket = bucket.into();
        if let Some(messages) = self.buffer.0.lock().get_mut(&bucket) {
            messages.remove(&id);
        }
    }

    async fn send(&mut self, b: Bucket, to: Target, data: Data) -> Result<Id> {
        let id = self.next_id();

        let trailer = Trailer { bucket: b, id };

        let trailer_bytes = trailer.encode(&mut self.encoded);

        let mut msg = data.bytes;

        msg.extend_from_slice(trailer_bytes);
        msg.extend_from_slice(&[trailer_bytes.len().try_into().expect("|trailer| <= 32")]);
        let msg = msg.freeze();

        let now = Instant::now();

        let rem = match to {
            Target::Single(to) => {
                self.sender
                    .send(Command::Unicast(to, Some(id), msg.clone()))
                    .await
                    .map_err(|_| NetworkDown(()))?;
                vec![to]
            }
            Target::Multi(peers) => {
                self.sender
                    .send(Command::Multicast(peers.clone(), Some(id), msg.clone()))
                    .await
                    .map_err(|_| NetworkDown(()))?;
                peers
            }
            Target::All => {
                self.sender
                    .send(Command::Broadcast(Some(id), msg.clone()))
                    .await
                    .map_err(|_| NetworkDown(()))?;
                self.net
                    .parties()
                    .filter(|(_, r)| r.is_active())
                    .map(|(p, _)| *p)
                    .collect()
            }
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
        self.id = (u64::from(self.id) + 1).into();
        id
    }
}

async fn retry(
    buf: Buffer,
    net: Sender<Command>,
    #[cfg(feature = "metrics")] msg_gauge: IntGauge,
) -> Infallible {
    const DELAYS: [u64; 4] = [1, 3, 5, 15];

    let mut i = time::interval(Duration::from_secs(1));
    i.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

    let mut buckets = Vec::new();
    let mut ids = Vec::new();

    loop {
        let now = i.tick().await;

        debug_assert!(buckets.is_empty());
        buckets.extend(buf.0.lock().keys().copied());

        #[cfg(feature = "metrics")]
        let mut ctr = 0;

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
                #[cfg(feature = "metrics")]
                {
                    ctr += 1;
                }

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

                let _ = net
                    .send(Command::Multicast(remaining, Some(id), message.clone()))
                    .await;
            }
        }

        #[cfg(feature = "metrics")]
        msg_gauge.set(ctr)
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
        Ok(Self { bytes: val })
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

impl From<Bucket> for u64 {
    fn from(val: Bucket) -> Self {
        val.0
    }
}

impl fmt::Display for Bucket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
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

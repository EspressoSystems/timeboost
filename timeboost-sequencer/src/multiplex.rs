use bytes::{BufMut, BytesMut};
use cliquenet::{
    Overlay, PEER_CAPACITY,
    overlay::{Bucket, Data, DataError},
};
use multisig::{Committee, PublicKey};
use sailfish::types::RoundNumber;
use serde::{Deserialize, Serialize};
use timeboost_types::{BlockInfo, BlockNumber, ShareInfo};
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};
use tracing::{debug, error, trace, warn};

use crate::MAX_SIZE;

type Result<T> = std::result::Result<T, MultiplexError>;
type DecryptReceiver = Receiver<(PublicKey, ShareInfo)>;
type BlockReceiver = Receiver<(PublicKey, BlockInfo)>;

struct BlockBucket(u64);

impl From<u64> for BlockBucket {
    fn from(value: u64) -> Self {
        let mut bucket = value;
        bucket ^= 1 << 63;
        Self(bucket)
    }
}

impl From<BlockBucket> for Bucket {
    fn from(bucket: BlockBucket) -> Self {
        bucket.0.into()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MultiplexMessage {
    Decrypt(ShareInfo),
    Block(BlockInfo),
}

#[derive(Debug)]
pub struct Multiplex {
    /// Label of the node.
    label: PublicKey,
    /// Sender to the multiplexer.
    tx: Sender<MultiplexMessage>,
    /// Sender to signal for gc.
    gc_tx: Sender<Bucket>,
    /// Join handle for worker.
    jh: JoinHandle<()>,
}

impl Multiplex {
    pub fn new(
        label: PublicKey,
        committee: Committee,
        net: Overlay,
    ) -> (DecryptReceiver, BlockReceiver, Self) {
        let capacity = committee.size().get() * PEER_CAPACITY;
        // Channel for multiplexed messages to/from the overlay network.
        let (tx, rx) = mpsc::channel(capacity);
        // Channel reserved for the decrypter
        let (dec_tx, dec_rx) = mpsc::channel(capacity);
        // Channel reserved for the block producer
        let (block_tx, block_rx) = mpsc::channel(capacity);
        // Channel reserved for garbage collection signal.
        let (gc_tx, gc_rx) = mpsc::channel(capacity);

        let worker = Worker::new(label, net, dec_tx, block_tx, rx, gc_rx);
        (
            dec_rx,
            block_rx,
            Self {
                label,
                tx,
                gc_tx,
                jh: tokio::spawn(worker.go()),
            },
        )
    }

    pub fn tx(&self) -> &Sender<MultiplexMessage> {
        &self.tx
    }

    pub async fn decrypt_gc(&mut self, round: RoundNumber) {
        let bucket = Bucket::from(*round);
        let gc_round: RoundNumber = round.saturating_sub(MAX_SIZE as u64).into();
        if RoundNumber::genesis() < gc_round {
            trace!(
                node      = %self.label,
                gc_round  = %gc_round,
                "decrypt-gc"
            );
            if let Err(e) = self.gc_tx.send(bucket).await {
                error!("failed to send gc signal: {}", e);
            }
        }
    }

    pub async fn block_gc(&mut self, block_num: BlockNumber) {
        let bucket = BlockBucket::from(*block_num);
        trace!(
            node   = %self.label,
            block  = %block_num,
            bucket = %bucket.0,
            "block-gc"
        );
        if let Err(e) = self.gc_tx.send(bucket.into()).await {
            error!("failed to send gc signal: {}", e);
        }
    }
}

impl Drop for Multiplex {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

struct Worker {
    /// Public key of the node.
    label: PublicKey,
    /// Overlay network.
    net: Overlay,
    /// Sender to decrypter.
    dec_tx: Sender<(PublicKey, ShareInfo)>,
    /// Sender to block producer.
    block_tx: Sender<(PublicKey, BlockInfo)>,
    /// Receiver for multiplexer.
    rx: Receiver<MultiplexMessage>,
    /// Receiver for gc signals.
    gc_rx: Receiver<Bucket>,
}

impl Worker {
    pub fn new(
        label: PublicKey,
        net: Overlay,
        dec_tx: Sender<(PublicKey, ShareInfo)>,
        block_tx: Sender<(PublicKey, BlockInfo)>,
        rx: Receiver<MultiplexMessage>,
        gc_rx: Receiver<Bucket>,
    ) -> Self {
        Self {
            label,
            net,
            dec_tx,
            block_tx,
            rx,
            gc_rx,
        }
    }
    pub async fn go(mut self) {
        loop {
            tokio::select! {
                Some(message) = self.rx.recv() => {
                    let data = match serialize(&message) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!(node = %self.label, "serialization error: {}", e);
                            continue;
                        }
                    };

                    let bucket = match &message {
                        MultiplexMessage::Decrypt(share_info) => {
                            Bucket::from(*share_info.round())
                        }
                        MultiplexMessage::Block(block_info) => {
                            BlockBucket::from(*block_info.number()).into()
                        }
                    };

                    if let Err(e) = self.net.broadcast(bucket, data).await {
                        error!(node = %self.label, "network broadcast error: {}", e);
                        return;
                    }
                }

                Ok((public_key, bytes)) = self.net.receive() => {
                    if public_key == self.label {
                        continue;
                    }
                    let msg = match deserialize(&bytes) {
                        Ok(message) => message,
                        Err(e) => {
                            warn!("failed to deserialize message: {}", e);
                            continue;
                        }
                    };

                    match msg {
                        MultiplexMessage::Decrypt(share_info) => {
                            if let Err(e) = self.dec_tx.send((public_key, share_info)).await {
                                error!("failed to send decrypt message: {}", e);
                                return;
                            }
                        }
                        MultiplexMessage::Block(envelope) => {
                            if let Err(e) = self.block_tx.send((public_key, envelope)).await {
                                error!("failed to send block message: {}", e);
                                return;
                            }
                        }
                    }
                }
                Some(bucket) = self.gc_rx.recv() => {
                    trace!(node = %self.label, "received gc signal for bucket: {:?}", bucket);
                    self.net.gc(bucket);
                }
                else => {
                    debug!(node = %self.label, "network shutdown detected");
                    return;
                }
            }
        }
    }
}

/// Serialize a given data type into `Bytes`
fn serialize<T: Serialize>(d: &T) -> Result<Data> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    Ok(b.into_inner().try_into()?)
}

/// Deserialize from `Bytes` into a given data type.
fn deserialize<T: for<'de> serde::Deserialize<'de>>(d: &bytes::Bytes) -> Result<T> {
    bincode::serde::decode_from_slice(d, bincode::config::standard())
        .map(|(msg, _)| msg)
        .map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultiplexError {
    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("data error: {0}")]
    DataError(#[from] DataError),
}

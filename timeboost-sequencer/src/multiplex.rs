use crate::MAX_SIZE;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::{
    Overlay, PEER_CAPACITY,
    overlay::{Bucket, DataError},
};
use multisig::{Committee, PublicKey};
use sailfish::types::RoundNumber;
use timeboost_types::BlockNumber;
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};
use tracing::{debug, error, trace, warn};

const DECRYPT_TAG: u8 = 0xDE;
const BLOCK_TAG: u8 = 0xB0;

type Result<T> = std::result::Result<T, MultiplexError>;

struct BlockBucket(u64);

impl From<u64> for BlockBucket {
    fn from(value: u64) -> Self {
        Self(value | (1 << 63))
    }
}

impl From<BlockBucket> for Bucket {
    fn from(bucket: BlockBucket) -> Self {
        bucket.0.into()
    }
}

pub enum TimeboostInbound {
    Decrypt(DecryptInbound),
    Block(BlockInbound),
}

pub struct DecryptOutbound {
    pub num: RoundNumber,
    pub data: Bytes,
}

impl DecryptOutbound {
    pub fn new(num: RoundNumber, data: Bytes) -> Self {
        Self { num, data }
    }
}

pub struct DecryptInbound {
    pub src: PublicKey,
    pub data: Bytes,
}

pub struct BlockOutbound {
    pub num: BlockNumber,
    pub data: Bytes,
}

impl BlockOutbound {
    pub fn new(num: BlockNumber, data: Bytes) -> Self {
        Self { num, data }
    }
}

pub struct BlockInbound {
    pub src: PublicKey,
    pub data: Bytes,
}

#[derive(Debug)]
pub struct Multiplex {
    /// Label of the node.
    label: PublicKey,
    /// Sender decryption data to the multiplexer.
    dec_tx: Sender<DecryptOutbound>,
    /// Sender block data to the multiplexer.
    block_tx: Sender<BlockOutbound>,
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
    ) -> (Receiver<DecryptInbound>, Receiver<BlockInbound>, Self) {
        let capacity = committee.size().get() * PEER_CAPACITY;
        // Channels reserved for the decrypter
        let (dec_itx, dec_irx) = mpsc::channel(capacity);
        let (dec_otx, dec_orx) = mpsc::channel(capacity);
        // Channels reserved for the block producer
        let (block_itx, block_irx) = mpsc::channel(capacity);
        let (block_otx, block_orx) = mpsc::channel(capacity);
        // Channel reserved for garbage collection signal.
        let (gc_tx, gc_rx) = mpsc::channel(capacity);

        let worker = Worker::new(label, net, dec_itx, dec_orx, block_itx, block_orx, gc_rx);
        (
            dec_irx,
            block_irx,
            Self {
                label,
                dec_tx: dec_otx,
                block_tx: block_otx,
                gc_tx,
                jh: tokio::spawn(worker.go()),
            },
        )
    }

    pub fn dec_tx(&self) -> &Sender<DecryptOutbound> {
        &self.dec_tx
    }

    pub fn block_tx(&self) -> &Sender<BlockOutbound> {
        &self.block_tx
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
    /// Send inbound messages to decrypter.
    dec_itx: Sender<DecryptInbound>,
    /// Receive obound messages from decrypter.
    dec_orx: Receiver<DecryptOutbound>,
    /// Send inbound messages to block producer.
    block_itx: Sender<BlockInbound>,
    /// Receive obound messages from block producer.
    block_orx: Receiver<BlockOutbound>,
    /// Receiver for gc signals.
    gc_rx: Receiver<Bucket>,
}

impl Worker {
    pub fn new(
        label: PublicKey,
        net: Overlay,
        dec_itx: Sender<DecryptInbound>,
        dec_orx: Receiver<DecryptOutbound>,
        block_itx: Sender<BlockInbound>,
        block_orx: Receiver<BlockOutbound>,
        gc_rx: Receiver<Bucket>,
    ) -> Self {
        Self {
            label,
            net,
            dec_itx,
            dec_orx,
            block_itx,
            block_orx,
            gc_rx,
        }
    }
    pub async fn go(mut self) {
        loop {
            tokio::select! {
                Some(DecryptOutbound { num, data }) = self.dec_orx.recv() => {
                    let mut tagged_data = BytesMut::with_capacity(data.len() + 1);
                    tagged_data.put_u8(DECRYPT_TAG);
                    tagged_data.extend_from_slice(&data);
                    match tagged_data.try_into() {
                        Ok(data) => {
                            if let Err(e) = self.net.broadcast(Bucket::from(*num), data).await {
                                error!(node = %self.label, "network broadcast error: {}", e);
                                return;
                            }
                        }
                        Err(e) => {
                            error!(node = %self.label, "failed to convert tagged data: {}", e);
                            return;
                        }
                    }
                }
                Some(BlockOutbound { num, data }) = self.block_orx.recv() => {
                    let mut tagged_data = BytesMut::with_capacity(data.len() + 1);
                    tagged_data.put_u8(BLOCK_TAG);
                    tagged_data.extend_from_slice(&data);
                    match tagged_data.try_into() {
                        Ok(data) => {
                            if let Err(e) = self.net.broadcast(Bucket::from(*num), data).await {
                                error!(node = %self.label, "network broadcast error: {}", e);
                                return;
                            }
                        }
                        Err(e) => {
                            error!(node = %self.label, "failed to convert tagged data: {}", e);
                            return;
                        }
                    }
                }

                Ok(msg) = self.net.receive() => {
                    if msg.0 == self.label {
                        continue;
                    }
                    match decode(msg) {
                        Ok(TimeboostInbound::Decrypt(message)) => {
                            if let Err(e) = self.dec_itx.send(message).await {
                                error!("failed to send decrypt message: {}", e);
                                return;
                            }
                        }
                        Ok(TimeboostInbound::Block(message)) => {
                            if let Err(e) = self.block_itx.send(message).await {
                                error!("failed to send block message: {}", e);
                                return;
                            }
                        }
                        Err(e) => {
                            warn!("failed to deserialize message: {}", e);
                            continue;
                        }
                    };
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

fn decode(inbound_msg: (PublicKey, bytes::Bytes)) -> Result<TimeboostInbound> {
    let (public_key, data) = inbound_msg;
    if data.is_empty() {
        return Err(MultiplexError::InvalidTag);
    }

    match data[0] {
        DECRYPT_TAG => Ok(TimeboostInbound::Decrypt(DecryptInbound {
            src: public_key,
            data: data.slice(1..),
        })),
        BLOCK_TAG => Ok(TimeboostInbound::Block(BlockInbound {
            src: public_key,
            data: data.slice(1..),
        })),
        _ => Err(MultiplexError::InvalidTag),
    }
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

    #[error("invalid tag error")]
    InvalidTag,
}

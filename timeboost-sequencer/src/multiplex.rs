use bytes::Bytes;
use cliquenet::{
    Overlay, PEER_CAPACITY,
    overlay::{Data, Tag},
};
use multisig::{Committee, PublicKey};
use sailfish::types::RoundNumber;
use timeboost_types::BlockNumber;
use tokio::{
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};
use tracing::{debug, error, trace, warn};

pub(crate) const DECRYPT_TAG: Tag = Tag::new(0xDE);
pub(crate) const BLOCK_TAG: Tag = Tag::new(0xB0);

pub struct DecryptOutbound {
    num: RoundNumber,
    data: Data,
}

impl DecryptOutbound {
    pub fn new(num: RoundNumber, data: Data) -> Self {
        Self { num, data }
    }
}

pub struct DecryptInbound {
    pub src: PublicKey,
    pub data: Bytes,
}

pub struct BlockOutbound {
    num: BlockNumber,
    data: Data,
}

impl BlockOutbound {
    pub fn new(num: BlockNumber, data: Data) -> Self {
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
    gc_tx: Sender<(Tag, u64)>,
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

    pub async fn gc<N: Into<u64>>(&mut self, t: Tag, n: N) {
        if let Err(err) = self.gc_tx.send((t, n.into())).await {
            error!(node = %self.label, %err, "failed to send gc signal");
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
    gc_rx: Receiver<(Tag, u64)>,
}

impl Worker {
    pub fn new(
        label: PublicKey,
        net: Overlay,
        dec_itx: Sender<DecryptInbound>,
        dec_orx: Receiver<DecryptOutbound>,
        block_itx: Sender<BlockInbound>,
        block_orx: Receiver<BlockOutbound>,
        gc_rx: Receiver<(Tag, u64)>,
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
                    if let Err(e) = self.net.broadcast(*num, data).await {
                        error!(node = %self.label, err = %e, "network broadcast error");
                        return;
                    }
                }
                Some(BlockOutbound { num, data }) = self.block_orx.recv() => {
                    if let Err(e) = self.net.broadcast(*num, data).await {
                        error!(node = %self.label, err = %e, "network broadcast error");
                        return;
                    }
                }

                Ok((src, data, tag)) = self.net.receive() => {
                    if src == self.label {
                        continue;
                    }
                    match tag {
                        DECRYPT_TAG => {
                            if let Err(err) = self.dec_itx.send(DecryptInbound { src, data }).await {
                                error!(node = %self.label, %err, "failed to send decrypt message");
                                return;
                            }
                        }
                        BLOCK_TAG => {
                            if let Err(err) = self.block_itx.send(BlockInbound { src, data }).await {
                                error!(node = %self.label, %err, "failed to send block message");
                                return;
                            }
                        }
                        _ => {
                            warn!(tag = u8::from(tag), "failed to classify message");
                            continue;
                        }
                    }
                }
                Some((t, n)) = self.gc_rx.recv() => {
                    trace!(node = %self.label, tag = %t, bucket = %n, "received gc signal");
                    self.net.gc(t, n);
                }
                else => {
                    debug!(node = %self.label, "network shutdown detected");
                    return;
                }
            }
        }
    }
}

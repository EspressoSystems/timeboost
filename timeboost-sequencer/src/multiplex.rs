use std::marker::PhantomData;
use std::sync::Arc;

use bytes::Bytes;
use cliquenet::{
    Overlay, PEER_CAPACITY,
    overlay::{Data, NetworkDown, Tag},
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

/// Marker type for decryption specific API parts.
#[derive(Debug, Clone)]
pub enum Decrypt {}

/// Marker type for block production specific API parts.
#[derive(Debug, Clone)]
pub enum Produce {}

/// Inbound decrypt message.
pub struct DecryptMessage {
    pub src: PublicKey,
    pub data: Bytes,
}

/// Inbound block produce message.
pub struct BlockMessage {
    pub src: PublicKey,
    pub data: Bytes,
}

#[derive(Debug, Clone)]
pub struct Multiplex<T>(Arc<Inner>, PhantomData<fn(T)>);

#[derive(Debug)]
struct Inner {
    /// Sender of commands to worker.
    cmd: Sender<Command>,
    /// Join handle for worker.
    jh: JoinHandle<()>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

enum Command {
    SendDecrypt { num: RoundNumber, data: Data },
    SendBlock { num: BlockNumber, data: Data },
    Gc { tag: Tag, bucket: u64 },
}

impl<T> Multiplex<T> {
    pub fn new(
        label: PublicKey,
        committee: Committee,
        net: Overlay,
    ) -> (Self, Receiver<DecryptMessage>, Receiver<BlockMessage>) {
        let capacity = committee.size().get() * PEER_CAPACITY;

        // Channel reserved for the decrypter
        let (dec_tx, dec_rx) = mpsc::channel(capacity);

        // Channel reserved for the block producer
        let (block_tx, block_rx) = mpsc::channel(capacity);

        // Command channel.
        let (cmd_tx, cmd_rx) = mpsc::channel(capacity);

        let worker = Worker::new(label, net, cmd_rx, dec_tx, block_tx);

        (
            Self(
                Arc::new(Inner {
                    cmd: cmd_tx,
                    jh: tokio::spawn(worker.go()),
                }),
                PhantomData,
            ),
            dec_rx,
            block_rx,
        )
    }

    pub async fn gc<N: Into<u64>>(&self, t: Tag, n: N) -> Result<(), MultiplexError> {
        self.0
            .cmd
            .send(Command::Gc {
                tag: t,
                bucket: n.into(),
            })
            .await
            .map_err(|_| MultiplexError::Closed)
    }
}

impl Multiplex<()> {
    pub fn cast<T>(self) -> Multiplex<T> {
        Multiplex(self.0, PhantomData)
    }
}

impl Multiplex<Decrypt> {
    pub async fn send(&self, r: RoundNumber, d: Data) -> Result<(), MultiplexError> {
        self.0
            .cmd
            .send(Command::SendDecrypt { num: r, data: d })
            .await
            .map_err(|_| MultiplexError::Closed)
    }
}

impl Multiplex<Produce> {
    pub async fn send(&self, b: BlockNumber, d: Data) -> Result<(), MultiplexError> {
        self.0
            .cmd
            .send(Command::SendBlock { num: b, data: d })
            .await
            .map_err(|_| MultiplexError::Closed)
    }
}

struct Worker {
    /// Public key of the node.
    label: PublicKey,
    /// Overlay network.
    net: Overlay,
    cmd: Receiver<Command>,
    /// Send inbound messages to decrypter.
    dec_tx: Sender<DecryptMessage>,
    /// Send inbound messages to block producer.
    block_tx: Sender<BlockMessage>,
}

impl Worker {
    pub fn new(
        label: PublicKey,
        net: Overlay,
        cmd: Receiver<Command>,
        dec_tx: Sender<DecryptMessage>,
        block_tx: Sender<BlockMessage>,
    ) -> Self {
        Self {
            label,
            net,
            cmd,
            dec_tx,
            block_tx,
        }
    }
    pub async fn go(mut self) {
        loop {
            tokio::select! {
                cmd = self.cmd.recv() => match cmd {
                    Some(Command::SendDecrypt { num, data }) => {
                        if let Err(e) = self.net.broadcast(*num, data).await {
                            error!(node = %self.label, err = %e, "network broadcast error");
                            return;
                        }
                    }
                    Some(Command::SendBlock { num, data }) => {
                        if let Err(e) = self.net.broadcast(*num, data).await {
                            error!(node = %self.label, err = %e, "network broadcast error");
                            return;
                        }
                    }
                    Some(Command::Gc { tag, bucket }) => {
                        trace!(node = %self.label, %tag, %bucket, "received gc signal");
                        self.net.gc(tag, bucket);
                    }
                    None => {
                        debug!(node = %self.label, "command channel closed");
                        return
                    }
                },
                data = self.net.receive() => match data {
                    Ok((src, data, tag)) => {
                        if src == self.label {
                            continue;
                        }
                        match tag {
                            DECRYPT_TAG => {
                                let msg = DecryptMessage { src, data };
                                if let Err(err) = self.dec_tx.send(msg).await {
                                    error!(node = %self.label, %err, "failed to send decrypt message");
                                    return;
                                }
                            }
                            BLOCK_TAG => {
                                let msg = BlockMessage { src, data };
                                if let Err(err) = self.block_tx.send(msg).await {
                                    error!(node = %self.label, %err, "failed to send block message");
                                    return;
                                }
                            }
                            _ => {
                                warn!(node = %self.label, %tag, "failed to classify message");
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        let _: NetworkDown = e;
                        debug!(node = %self.label, "network shutdown detected");
                        return
                    }
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MultiplexError {
    #[error("multiplexer closed")]
    Closed,
}

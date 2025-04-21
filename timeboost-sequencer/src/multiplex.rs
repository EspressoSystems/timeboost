use bytes::{BufMut, BytesMut};
use cliquenet::{
    Overlay, PEER_CAPACITY,
    overlay::{Data, DataError},
};
use multisig::{Committee, Envelope, PublicKey, Unchecked};
use serde::Serialize;
use timeboost_types::{BlockHash, MultiplexMessage, ShareInfo};
use tokio::sync::mpsc::{self, Receiver};
use tracing::{debug, error};

type Result<T> = std::result::Result<T, MultiplexError>;
type DecryptReceiver = Receiver<(PublicKey, ShareInfo)>;
type BlockReceiver = Receiver<(PublicKey, Envelope<BlockHash, Unchecked>)>;

#[derive(Debug)]
pub struct Multiplex {
    /// Public key of the node.
    label: PublicKey,
    /// Committee of the node.
    committee: Committee,
    /// Overlay network.
    net: Overlay,
    /// Sender for outbound messages to be multiplexed.
    tx: mpsc::Sender<MultiplexMessage>,
    /// Receiver for outbound messages to be multiplexed.
    rx: mpsc::Receiver<MultiplexMessage>,
}

impl Multiplex {
    pub fn new(label: PublicKey, committee: Committee, net: Overlay) -> Self {
        // Channel for multiplexed messages to/from the overlay network.
        let (obound_tx, obound_rx) = mpsc::channel(committee.size().get() * PEER_CAPACITY);
        Self {
            label,
            committee,
            net,
            tx: obound_tx,
            rx: obound_rx,
        }
    }
}

impl Multiplex {
    pub fn go(mut self) -> (DecryptReceiver, BlockReceiver) {
        let capacity = self.committee.size().get() * PEER_CAPACITY;
        // Channel reserved for the decrypter
        let (dec_tx, dec_rx) = mpsc::channel(capacity);
        // Channel reserved for the block producer
        let (block_tx, block_rx) = mpsc::channel(capacity);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(message) = self.rx.recv() => {
                        let data = match serialize(&message) {
                            Ok(data) => data,
                            Err(e) => {
                                debug!(node = %self.label, "serialization error: {}", e);
                                return;
                            }
                        };
                        match self.net.broadcast(data).await {
                            Ok(_seqid) => {
                                // TODO: store seqids for garbage collection.
                            }
                            Err(e) => {
                                debug!(node = %self.label, "network shutdown detected {}", e);
                                return;
                            }
                        }
                    }

                    Ok((public_key, bytes)) = self.net.receive() => {
                        if public_key == self.label {
                            continue;
                        }
                        let msg = match deserialize(&bytes) {
                            Ok(message) => message,
                            Err(e) => {
                                error!("failed to deserialize message: {}", e);
                                continue;
                            }
                        };

                        match msg {
                            MultiplexMessage::Decrypt(share_info) => {
                                if let Err(e) = dec_tx.send((public_key, share_info)).await {
                                    error!("failed to send decrypt message: {}", e);
                                }
                            }
                            MultiplexMessage::Block(envelope) => {
                                if let Err(e) = block_tx.send((public_key, envelope)).await {
                                    error!("failed to send block message: {}", e);
                                }
                            }
                        }
                    } else => {
                        debug!(node = %self.label, "network shutdown detected");
                        return;
                    }
                }
            }
        });
        (dec_rx, block_rx)
    }

    pub fn tx(&self) -> mpsc::Sender<MultiplexMessage> {
        self.tx.clone()
    }

    pub fn _gc(&mut self) {
        // TODO: garbage collect when interface stabilize.
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

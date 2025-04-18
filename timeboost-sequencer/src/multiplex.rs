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
    /// Sender for outbound messages to be multiplexed.
    pub tx: mpsc::Sender<MultiplexMessage>,
}

impl Multiplex {
    pub fn go(
        label: PublicKey,
        committee: Committee,
        mut net: Overlay,
    ) -> (DecryptReceiver, BlockReceiver, Self) {
        let channel_size = committee.size().get() * PEER_CAPACITY;
        // Channel for multiplexed messages to/from the overlay network.
        let (obound_tx, mut obound_rx) = mpsc::channel(channel_size);
        // Channel reserved for the decrypter
        let (dec_tx, dec_rx) = mpsc::channel(channel_size);
        // Channel reserved for the block producer
        let (block_tx, block_rx) = mpsc::channel(channel_size);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(message) = obound_rx.recv() => {
                        match serialize(&message) {
                            Ok(data) => {
                                if let Err(e) = net.broadcast(data).await {
                                    debug!(node = %label, "network shutdown detected {}", e);
                                    return;
                                }
                            }
                            Err(e) => {
                                error!("failed to serialize message: {}", e);
                            }
                        }
                    }

                    Ok((public_key, bytes)) = net.receive() => {
                        if public_key == label {
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
                        debug!(node = %label, "network shutdown detected");
                        return;
                    }
                }
            }
        });

        (dec_rx, block_rx, Self { tx: obound_tx })
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

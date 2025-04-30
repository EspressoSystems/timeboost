use bytes::{BufMut, BytesMut};
use cliquenet::MAX_MESSAGE_SIZE;
use cliquenet::overlay::{Data, DataError};
use multisig::{Certificate, Committee, Envelope, Keypair, Unchecked, Validated, VoteAccumulator};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use timeboost_types::{
    Block, BlockHash, BlockInfo, BlockNumber, CertifiedBlock, Timestamp, Transaction,
};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use crate::MAX_SIZE;
use crate::multiplex::{BLOCK_TAG, BlockInbound, BlockOutbound};

type Result<T> = std::result::Result<T, ProducerError>;

#[derive(Clone)]
enum Status {
    Uncertified(Block),
    Certified(Certificate<BlockHash>, Block),
}

struct WorkerRequest(BlockNumber, BlockHash);

struct WorkerResponse(BlockNumber, Certificate<BlockHash>);

pub struct BlockProducer {
    /// Keypair of the node.
    label: Keypair,
    /// Incoming transactions
    queue: VecDeque<(Timestamp, Transaction)>,
    /// Last block produced.
    parent: Option<(BlockNumber, BlockHash)>,
    /// Blocks subject to certification.
    blocks: BTreeMap<(BlockNumber, BlockHash), Status>,
    /// Sender for worker request.
    block_tx: Sender<WorkerRequest>,
    /// Receiver for worker response.
    cert_rx: Receiver<WorkerResponse>,
    /// Worker task handle.
    jh: JoinHandle<()>,
}

impl BlockProducer {
    pub fn new(
        label: Keypair,
        committee: Committee,
        rx: Receiver<BlockInbound>,
        tx: Sender<BlockOutbound>,
    ) -> Self {
        let (block_tx, block_rx) = channel(MAX_SIZE);
        let (cert_tx, cert_rx) = channel(MAX_SIZE);
        let worker = Worker::new(label.clone(), committee.clone());

        Self {
            label,
            queue: VecDeque::new(),
            parent: None,
            blocks: BTreeMap::new(),
            block_tx,
            cert_rx,
            jh: spawn(worker.go(block_rx, cert_tx, rx, tx)),
        }
    }

    pub async fn enqueue(&mut self, tx: (Timestamp, Transaction)) -> Result<()> {
        self.queue.push_back(tx);

        // TODO: produce blocks deterministically according to spec.
        // Useful links:
        // https://github.com/OffchainLabs/nitro/blob/66acaf2ce12de4c55290fad85083f31b14cec3cf/execution/gethexec/sequencer.go#L1001
        // https://github.com/OffchainLabs/nitro/blob/66acaf2ce12de4c55290fad85083f31b14cec3cf/arbos/block_processor.go#L164
        const BLOCK_SIZE: usize = 10;

        if self.queue.len() >= BLOCK_SIZE {
            let txs: Vec<_> = self.queue.drain(..BLOCK_SIZE).map(|(_, t)| t).collect();

            let (num, block) = match self.parent {
                Some((num, parent)) => {
                    let block = Block::new(parent, txs);
                    (num + 1, block)
                }
                None => {
                    let block = Block::new(BlockHash::default(), txs);
                    (BlockNumber::genesis(), block)
                }
            };

            let hash = BlockHash::from(*block.hash_slow());
            self.blocks
                .insert((num, hash), Status::Uncertified(block.clone()));
            self.block_tx
                .send(WorkerRequest(num, hash))
                .await
                .map_err(|_| ProducerError::Shutdown)?;
            self.parent = Some((num, hash));

            trace!(node = %self.label.public_key(), %num, block = ?hash, "certifying");
        }

        Ok(())
    }

    pub async fn next(&mut self) -> Result<CertifiedBlock> {
        while let Some(WorkerResponse(num, cert)) = self.cert_rx.recv().await {
            trace!(
                node = %self.label.public_key(),
                num  = %num,
                hash = ?cert.data(),
                "certified"
            );
            if let Some(status) = self.blocks.get_mut(&(num, *cert.data())) {
                if let Status::Uncertified(block) = status {
                    *status = Status::Certified(cert, block.to_owned());
                }
            };
            if let Some((block_info, status)) = self.blocks.pop_first() {
                if let Status::Certified(cert, block) = status {
                    return Ok(CertifiedBlock::new(num, cert, block));
                } else {
                    debug!(
                        node = %self.label.public_key(),
                        "received certified block {} but the next block is {}",
                        num,
                        block_info.0
                    );
                    self.blocks.insert(block_info, status);
                }
            }
        }
        Err(ProducerError::Shutdown)
    }
}

impl Drop for BlockProducer {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CertStatus {
    Unknown,
    Certified,
}

struct Tracker {
    votes: VoteAccumulator<BlockHash>,
    num: Option<BlockNumber>,
    status: CertStatus,
}

struct Worker {
    keypair: Keypair,
    committee: Committee,
    trackers: BTreeMap<BlockHash, Tracker>,
}

impl Worker {
    pub fn new(keypair: Keypair, committee: Committee) -> Self {
        Self {
            keypair,
            committee,
            trackers: BTreeMap::new(),
        }
    }

    pub async fn go(
        mut self,
        mut block_rx: Receiver<WorkerRequest>,
        cert_tx: Sender<WorkerResponse>,
        mut ibound: Receiver<BlockInbound>,
        obound: Sender<BlockOutbound>,
    ) {
        let label = self.keypair.public_key();
        let mut recv_block: (Option<BlockNumber>, Envelope<BlockHash, Validated>);
        loop {
            tokio::select! {
                val = ibound.recv() => match val {
                    Some(BlockInbound{src, data}) => {
                        let b = match deserialize::<BlockInfo<Unchecked>>(&data) {
                            Ok(block) => block,
                            Err(err) => {
                                warn!(node = %label, %err, "deserialization error");
                                continue;
                            }
                        };
                        let num = b.number();
                        let env = b.into_envelope();
                        trace!(
                            node   = %label,
                            num    = %num,
                            vote   = ?env.data(),
                            from   = %src,
                            "receive"
                        );
                        if let Some(e) = env.validated(&self.committee) {
                            recv_block = (None, e);
                        } else {
                            continue;
                        }
                    }
                    None => {
                        debug!(node = %label, "multiplexer shutdown detected");
                        return;
                    }
                },

                val = block_rx.recv() => match val {
                    Some(WorkerRequest(num, hash)) => {
                        trace!(node = %label, %num, hash = ?hash, "produced");
                        let env = Envelope::signed(hash, &self.keypair, false);
                        recv_block = (Some(num), env.clone());
                        let b = BlockInfo::new(num, env);
                        let data = match serialize(&b) {
                            Ok(data) => data,
                            Err(err) => {
                                warn!(node = %label, %err, %num, ?hash, "serialization error");
                                continue;
                            }
                        };
                        obound.send(BlockOutbound::new(num, data)).await.ok();
                    },
                    None => {
                        debug!(node = %label, "worker request channel closed");
                        return;
                    }
                },
            }

            let (block_num, block_hash) = recv_block;

            let tracker = self
                .trackers
                .entry(*block_hash.data())
                .or_insert_with(|| Tracker {
                    votes: VoteAccumulator::new(self.committee.clone()),
                    num: None,
                    status: CertStatus::Unknown,
                });

            if tracker.status == CertStatus::Certified {
                continue;
            }

            if let Some(num) = block_num {
                // Block number provided => block produced/signed by the local node.
                tracker.num = Some(num);
            }

            match tracker.votes.add(block_hash.into_signed()) {
                Ok(Some(cert)) => {
                    if let Some(num) = tracker.num {
                        if cert_tx
                            .send(WorkerResponse(num, cert.clone()))
                            .await
                            .is_err()
                        {
                            error!(node = %label, "failed to send certified block");
                            return;
                        }
                        tracker.status = CertStatus::Certified;
                    }
                }
                Err(_) => {
                    warn!(node = %label, "failed to add vote to tracker");
                }
                _ => {}
            }
        }
    }
}

fn serialize<T: Serialize>(d: &T) -> Result<Data> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    let bytes = b.into_inner();
    Ok(Data::try_from((BLOCK_TAG, bytes))?)
}

fn deserialize<T: for<'de> serde::Deserialize<'de>>(d: &bytes::Bytes) -> Result<T> {
    bincode::serde::decode_from_slice(
        d,
        bincode::config::standard().with_limit::<MAX_MESSAGE_SIZE>(),
    )
    .map(|(msg, _)| msg)
    .map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProducerError {
    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("data error: {0}")]
    DataError(#[from] DataError),

    #[error("an error occurred")]
    Shutdown,
}

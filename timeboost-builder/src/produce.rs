use bytes::{BufMut, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics};
use multisig::{Certificate, Committee, Envelope, Keypair, Unchecked, Validated, VoteAccumulator};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};
use timeboost_types::{Block, BlockHash, BlockInfo, BlockNumber, CertifiedBlock, Transaction};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use crate::BlockProducerConfig;

const MAX_BLOCKS: usize = 100;

#[derive(Clone)]
enum Status {
    Uncertified(Block),
    Certified(Certificate<BlockHash>, Block),
}

struct WorkerResponse(BlockNumber, Certificate<BlockHash>);

enum WorkerCommand {
    Send(BlockNumber, BlockHash),
    Gc(BlockNumber),
}

pub struct BlockProducer {
    /// Keypair of the node.
    label: Keypair,
    /// Incoming transactions
    queue: VecDeque<Transaction>,
    /// Last block produced.
    parent: Option<(BlockNumber, BlockHash)>,
    /// Blocks subject to certification.
    blocks: BTreeMap<(BlockNumber, BlockHash), Status>,
    /// Sender for worker request.
    block_tx: Sender<WorkerCommand>,
    /// Receiver for worker response.
    cert_rx: Receiver<WorkerResponse>,
    /// Worker task handle.
    jh: JoinHandle<()>,
    /// Timestamp of the last block produced
    last_block_timestamp: u64,
    /// Target block time in milliseconds
    target_block_time_ms: u64,
    /// Maximum transactions per block
    max_txs_per_block: usize,
    /// Maximum gas per block
    max_gas_per_block: u64,
}

impl BlockProducer {
    pub async fn new<M>(cfg: BlockProducerConfig, metrics: &M) -> Result<Self, ProducerError>
    where
        M: metrics::Metrics,
    {
        let (block_tx, block_rx) = channel(MAX_BLOCKS);
        let (cert_tx, cert_rx) = channel(MAX_BLOCKS);

        let net_metrics = NetworkMetrics::new("block", metrics, cfg.committee.parties().copied());

        let net = Network::create(
            "block",
            cfg.address.clone(),
            cfg.sign_keypair.clone(),
            cfg.dh_keypair.clone(),
            cfg.committee.entries(),
            net_metrics,
        )
        .await?;

        let worker = Worker::new(
            cfg.sign_keypair.clone(),
            Overlay::new(net),
            cfg.committee.committee().clone(),
        );

        // Default configuration for block production
        // These values can be adjusted based on network requirements
        let target_block_time_ms = 2000; // 2 seconds
        let max_txs_per_block = 100;     // Maximum transactions per block
        let max_gas_per_block = 8_000_000; // Similar to Ethereum's gas limit

        Ok(Self {
            label: cfg.sign_keypair,
            queue: VecDeque::new(),
            parent: None,
            blocks: BTreeMap::new(),
            block_tx,
            cert_rx,
            jh: spawn(worker.go(block_rx, cert_tx)),
            last_block_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            target_block_time_ms,
            max_txs_per_block,
            max_gas_per_block,
        })
    }

    pub async fn gc(&mut self, r: BlockNumber) -> Result<(), ProducerDown> {
        self.block_tx
            .send(WorkerCommand::Gc(r))
            .await
            .map_err(|_| ProducerDown(()))
    }

    pub async fn enqueue<I>(&mut self, txs: I) -> Result<(), ProducerDown>
    where
        I: IntoIterator<Item = Transaction>,
    {
        self.queue.extend(txs);

        // Deterministic block production according to spec
        // Inspired by Arbitrum's sequencer implementation
        
        // Get current timestamp
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        // Check if it's time to produce a new block based on:
        // 1. Time elapsed since last block is greater than target block time
        // 2. Queue has transactions
        let time_since_last_block = current_time.saturating_sub(self.last_block_timestamp);
        let should_produce_block = !self.queue.is_empty() && 
            (time_since_last_block >= self.target_block_time_ms);
            
        if should_produce_block {
            // Determine how many transactions to include in this block
            let tx_count = std::cmp::min(self.queue.len(), self.max_txs_per_block);
            
            // Calculate estimated gas for transactions (in a real implementation,
            // you would compute this based on transaction gas limits)
            let mut gas_used = 0u64;
            let mut tx_index = 0;
            
            // Select transactions up to gas limit or max tx count
            while tx_index < self.queue.len() && tx_index < self.max_txs_per_block {
                // In a real implementation, you would estimate gas for each transaction
                // For now, we'll use a simple approximation
                let tx_gas = 21_000; // Base gas for a simple transfer
                
                if gas_used + tx_gas > self.max_gas_per_block {
                    break;
                }
                
                gas_used += tx_gas;
                tx_index += 1;
            }
            
            // Take the selected transactions from the queue
            let txs: Vec<_> = self.queue.drain(..tx_index).collect();
            
            // Create the new block
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
                .send(WorkerCommand::Send(num, hash))
                .await
                .map_err(|_| ProducerDown(()))?;
            self.parent = Some((num, hash));
            
            // Update the timestamp of the last produced block
            self.last_block_timestamp = current_time;

            trace!(node = %self.label.public_key(), %num, block = ?hash, "certifying");
        }

        Ok(())
    }

    pub async fn next_block(&mut self) -> Result<CertifiedBlock, ProducerDown> {
        if let Some(cb) = self.first_certified() {
            return Ok(cb);
        }
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
            if let Some(cb) = self.first_certified() {
                return Ok(cb);
            } else {
                debug!(node = %self.label.public_key(), %num, "received future certified block");
            }
        }
        Err(ProducerDown(()))
    }

    /// Pop the first certified block.
    fn first_certified(&mut self) -> Option<CertifiedBlock> {
        let entry = self.blocks.first_entry()?;
        if matches!(entry.get(), Status::Certified(..)) {
            let ((num, _hash), status) = entry.remove_entry();
            let Status::Certified(cert, block) = status else {
                unreachable!("`Status::Certified` has been checked above.");
            };
            Some(CertifiedBlock::new(num, cert, block))
        } else {
            None
        }
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
    net: Overlay,
    committee: Committee,
    trackers: BTreeMap<BlockHash, Tracker>,
}

impl Worker {
    pub fn new(keypair: Keypair, net: Overlay, committee: Committee) -> Self {
        Self {
            keypair,
            net,
            committee,
            trackers: BTreeMap::new(),
        }
    }

    pub async fn go(
        mut self,
        mut block_rx: Receiver<WorkerCommand>,
        cert_tx: Sender<WorkerResponse>,
    ) {
        let label = self.keypair.public_key();
        let mut recv_block: (Option<BlockNumber>, Envelope<BlockHash, Validated>);
        loop {
            tokio::select! {
                val = self.net.receive() => match val {
                    Ok((src, data)) => {
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
                            node = %label,
                            num  = %num,
                            vote = ?env.data(),
                            from = %src,
                            "receive"
                        );
                        if let Some(e) = env.validated(&self.committee) {
                            recv_block = (None, e);
                        } else {
                            warn!(node = %label, %num, "invalid block info received");
                            continue;
                        }
                    }
                    Err(e) => {
                        let _: NetworkDown = e;
                        debug!(node = %label, "network down");
                        return;
                    }
                },

                val = block_rx.recv() => match val {
                    Some(WorkerCommand::Send(num, hash)) => {
                        trace!(node = %label, %num, hash = ?hash, "produced");
                        let env = Envelope::signed(hash, &self.keypair);
                        recv_block = (Some(num), env.clone());
                        let b = BlockInfo::new(num, env);
                        let data = match serialize(&b) {
                            Ok(data) => data,
                            Err(err) => {
                                warn!(node = %label, %err, %num, ?hash, "serialization error");
                                continue;
                            }
                        };
                        self.net.broadcast(*num, data).await.ok();
                    },
                    Some(WorkerCommand::Gc(num)) => {
                        let num = num.saturating_sub(MAX_BLOCKS as u64);
                        if num > 0 {
                            self.net.gc(num)
                        }
                        continue;
                    }
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
                Err(err) => {
                    warn!(node = %label, %err, "failed to add vote to tracker");
                }
                _ => {}
            }
        }
    }
}

fn serialize<T: Serialize>(d: &T) -> Result<Data, ProducerError> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    let bytes = b.into_inner();
    Ok(Data::try_from(bytes)?)
}

fn deserialize<T: for<'de> serde::Deserialize<'de>>(d: &bytes::Bytes) -> Result<T, ProducerError> {
    bincode::serde::decode_from_slice(
        d,
        bincode::config::standard().with_limit::<MAX_MESSAGE_SIZE>(),
    )
    .map(|(msg, _)| msg)
    .map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
#[error("producer down")]
pub struct ProducerDown(());

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProducerError {
    #[error("network error: {0}")]
    Net(#[from] NetworkError),

    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("data error: {0}")]
    DataError(#[from] DataError),
}

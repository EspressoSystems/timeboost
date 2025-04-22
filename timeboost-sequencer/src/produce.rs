use multisig::{
    Certificate, Committee, Envelope, Keypair, PublicKey, Unchecked, Validated, VoteAccumulator,
};
use std::collections::{BTreeMap, VecDeque};
use timeboost_types::{Block, BlockHash, BlockNumber, MultiplexMessage, Timestamp, Transaction};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace};

use crate::MAX_SIZE;

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
    /// block lists.
    blocks: BTreeMap<(BlockNumber, BlockHash), Status>,
    /// Send worker request.
    block_tx: Sender<WorkerRequest>,
    /// Receive worker response
    cert_rx: Receiver<WorkerResponse>,
    /// Worker task handle.
    jh: JoinHandle<()>,
}

impl BlockProducer {
    pub fn new(
        label: Keypair,
        committee: Committee,
        rx: Receiver<(PublicKey, Envelope<BlockHash, Unchecked>)>,
        tx: Sender<MultiplexMessage>,
    ) -> Self {
        let (block_tx, block_rx) = channel(MAX_SIZE);
        let (cert_tx, cert_rx) = channel(MAX_SIZE);
        let certifier = Worker::new(label.clone(), committee.clone());

        Self {
            label,
            queue: VecDeque::new(),
            parent: None,
            blocks: BTreeMap::new(),
            block_tx,
            cert_rx,
            jh: spawn(certifier.go(block_rx, cert_tx, rx, tx)),
        }
    }

    pub async fn enqueue(&mut self, tx: (Timestamp, Transaction)) -> Result<()> {
        self.queue.push_back(tx);

        // TODO: produce blocks deterministically according to spec.
        // Useful links:
        // https://github.com/OffchainLabs/nitro/blob/66acaf2ce12de4c55290fad85083f31b14cec3cf/execution/gethexec/sequencer.go#L1001
        // https://github.com/OffchainLabs/nitro/blob/66acaf2ce12de4c55290fad85083f31b14cec3cf/arbos/block_processor.go#L164
        if self.queue.len() >= 10 {
            let mut txs = Vec::new();
            for _ in 0..10 {
                if let Some(transaction) = self.queue.pop_front() {
                    txs.push(transaction);
                }
            }
            let (num, block) = if let Some((num, parent)) = self.parent {
                let block = Block::new(parent, txs.into_iter().map(|(_, t)| t).collect());
                (num + 1, block)
            } else {
                let block = Block::new(
                    BlockHash::default(),
                    txs.into_iter().map(|(_, t)| t).collect(),
                );
                (BlockNumber::genesis(), block)
            };
            let hash = BlockHash::from(*(block.hash_slow()));
            self.blocks
                .insert((num, hash), Status::Uncertified(block.clone()));
            self.block_tx
                .send(WorkerRequest(num, hash))
                .await
                .map_err(|_| ProducerError::General)?;
            self.parent = Some((num, hash));

            trace!(
                node  = %self.label.public_key(),
                num   = %num,
                block = ?hash,
                "certifying"
            );
        }

        Ok(())
    }

    pub async fn next(&mut self) -> Result<(Certificate<BlockHash>, Block)> {
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

            if let Some(entry) = self.blocks.first_entry() {
                match entry.get() {
                    Status::Certified(_, _) => {
                        let (cert, block) = match entry.remove() {
                            Status::Certified(cert, block) => (cert, block),
                            _ => unreachable!(),
                        };
                        return Ok((cert, block));
                    }
                    Status::Uncertified(_) => {
                        debug!(
                            node = %self.label.public_key(),
                            "received certified block {} but the next block num is {}",
                            num,
                            entry.key().0
                        );
                    }
                }
            }
        }
        Err(ProducerError::General)
    }
}

impl Drop for BlockProducer {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProducerError {
    #[error("an error occurred")]
    General,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CertStatus {
    Unknown,
    Signed,
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
        mut ibound: Receiver<(PublicKey, Envelope<BlockHash, Unchecked>)>,
        obound: Sender<MultiplexMessage>,
    ) {
        let label = self.keypair.public_key();
        let mut recv_block: (Option<BlockNumber>, Envelope<BlockHash, Validated>);
        loop {
            tokio::select! {
                val = ibound.recv() => match val {
                    Some((remote, e)) => {
                        trace!(
                            node   = %label,
                            vote   = ?e.data(),
                            from   = %remote,
                            "receive"
                        );
                        if let Some(e) = e.validated(&self.committee) {
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
                        trace!(
                            node = %label,
                            hash = ?hash,
                            "produced"
                        );
                        let env = Envelope::signed(hash, &self.keypair, false);
                        recv_block = (Some(num), env.clone());
                        obound.send(MultiplexMessage::Block(env.into())).await.ok();
                    },
                    None => {
                        debug!(node = %label, "block request channel closed");
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
            if let Some(num) = block_num {
                tracker.num = Some(num);
                tracker.status = CertStatus::Signed;
            }

            if tracker.status != CertStatus::Signed {
                continue;
            }

            if let Ok(cert) = tracker.votes.add(block_hash.into_signed()) {
                if let Some(cert) = cert {
                    if let Some(num) = tracker.num {
                        cert_tx.send(WorkerResponse(num, cert.clone())).await.ok();
                        tracker.status = CertStatus::Certified;
                    }
                }
            } else {
                tracing::warn!(
                    node = %label,
                    "failed to add vote to tracker"
                );
            }
        }
    }
}

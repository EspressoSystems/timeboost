use multisig::{
    Certificate, Committee, Envelope, Keypair, PublicKey, Signed, Unchecked, VoteAccumulator,
};
use std::collections::VecDeque;
use timeboost_types::{Block, BlockHash, MultiplexMessage, Timestamp, Transaction};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::error;

type Result<T> = std::result::Result<T, ProducerError>;

struct WorkerRequest(usize, BlockHash);

struct WorkerResponse(Certificate<BlockHash>);

pub struct BlockProducer {
    /// Keypair of the node.
    label: Keypair,
    /// Incoming transactions
    committee: Committee,
    queue: VecDeque<(Timestamp, Transaction)>,
    /// Block count
    count: usize,
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
        let (block_tx, block_rx) = channel(100);
        let (cert_tx, cert_rx) = channel(100);
        let certifier = Worker::new(label.clone(), committee.clone());

        Self {
            label,
            count: 0,
            committee,
            queue: VecDeque::new(),
            block_tx,
            cert_rx,
            jh: spawn(certifier.go(block_rx, cert_tx, rx, tx)),
        }
    }

    pub async fn enqueue(&mut self, tx: (Timestamp, Transaction)) -> Result<()> {
        self.queue.push_back(tx);

        if self.queue.len() >= 10 {
            let mut block_transactions = Vec::new();
            for _ in 0..10 {
                if let Some(transaction) = self.queue.pop_front() {
                    block_transactions.push(transaction);
                }
            }

            // TODO: use the real transactions and wrap them in a block
            let block = Block::default();
            let block_header = block.header.clone();
            let block_hash = *block_header.hash_slow();
            self.count += 1;
            self.block_tx
                .send(WorkerRequest(self.count, block_hash.into()))
                .await
                .map_err(|_| ProducerError::General)?;
        }

        Ok(())
    }

    pub async fn next(&mut self) -> Result<(Certificate<BlockHash>, Block)> {
        // TODO: cheating certificate for now
        let mut acc = VoteAccumulator::new(Committee::new(
            self.committee
                .entries()
                .filter(|(_, public_key)| **public_key == self.label.public_key())
                .map(|(key_id, public_key)| (key_id, *public_key))
                .collect::<Vec<_>>(),
        ));
        let block = Block::default();
        let block_header = block.header.clone();
        let block_hash = BlockHash::from(*block_header.hash_slow());
        let signed = Signed::new(block_hash, &self.label, true);
        match acc.add(signed) {
            Ok(Some(cert)) => Ok((cert.clone(), block)),
            Ok(None) => Err(ProducerError::General),
            Err(_) => Err(ProducerError::General),
        }
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

struct Worker {
    keypair: Keypair,
    committee: Committee,
}

impl Worker {
    pub fn new(keypair: Keypair, committee: Committee) -> Self {
        Self { keypair, committee }
    }

    pub async fn go(
        self,
        _block_rx: Receiver<WorkerRequest>,
        _cert_tx: Sender<WorkerResponse>,
        _ibound: Receiver<(PublicKey, Envelope<BlockHash, Unchecked>)>,
        _obound: Sender<MultiplexMessage>,
    ) {
        todo!()
    }
}

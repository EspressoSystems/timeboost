use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;
use std::result::Result as StdResult;

use bon::Builder;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{
    Certificate, Committee, Envelope, KeyId, Keypair, PublicKey, Unchecked, VoteAccumulator,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use timeboost_types::{Block, BlockInfo, BlockNumber, CertifiedBlock};
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::BlockProducerConfig;

type Result<T> = StdResult<T, ProducerError>;

pub struct BlockProducer {
    /// Log label of the node.
    label: PublicKey,
    /// Sender for blocks to certify.
    block_tx: Sender<(BlockNumber, Block)>,
    /// Receiver certified blocks.
    block_rx: Receiver<CertifiedBlock>,
    /// Worker task handle.
    worker: JoinHandle<EndOfPlay>,
    /// Block number counter.
    counter: BlockNumber,
}

impl BlockProducer {
    pub async fn new<M>(cfg: BlockProducerConfig, metrics: &M) -> Result<Self>
    where
        M: metrics::Metrics,
    {
        let (block_tx, block_rx) = channel(cfg.retain);
        let (cert_tx, cert_rx) = channel(cfg.retain);

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

        let worker = Worker::builder()
            .label(cfg.sign_keypair.public_key())
            .committee(cfg.committee.committee().clone())
            .keypair(cfg.sign_keypair.clone())
            .net(Overlay::new(net))
            .tx(cert_tx)
            .rx(block_rx)
            .trackers(Default::default())
            .retain(cfg.retain)
            .build();

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            block_tx,
            block_rx: cert_rx,
            worker: spawn(worker.go()),
            counter: BlockNumber::genesis(),
        })
    }

    pub async fn enqueue(&mut self, b: Block) -> StdResult<(), ProducerDown> {
        debug!(
            node  = %self.label,
            round = %b.round(),
            num   = %self.counter,
            hash  = ?b.hash(),
            "enqueuing block"
        );
        self.block_tx
            .send((self.counter, b))
            .await
            .map_err(|_| ProducerDown(()))?;
        self.counter = self.counter + 1;
        Ok(())
    }

    /// Get the next certified block.
    ///
    /// # Panics
    ///
    /// Once a `ProducerDown` error is returned, calling `next_block` again panics.
    pub async fn next_block(&mut self) -> StdResult<CertifiedBlock, ProducerDown> {
        select! {
            end = &mut self.worker => match end {
                Ok(end) => {
                    let end: EndOfPlay = end;
                    error!(node = %self.label, %end, "worker terminated");
                }
                Err(err) => {
                    error!(node = %self.label, %err, "worker panic");
                }
            },
            blk = self.block_rx.recv() => {
                if let Some(b) = blk {
                    info!(
                        node  = %self.label,
                        round = %b.data().round(),
                        hash  = ?b.data().hash(),
                        "certified block"
                    );
                    return Ok(b)
                }
                error!(node = %self.label, "worker terminated");
            }
        }
        Err(ProducerDown(()))
    }
}

impl Drop for BlockProducer {
    fn drop(&mut self) {
        self.worker.abort()
    }
}

#[derive(Builder)]
struct Worker {
    /// Our signing keypair.
    keypair: Keypair,

    /// Log label.
    label: PublicKey,

    /// Network handle.
    net: Overlay,

    /// The committee of block signers.
    committee: Committee,

    /// Blocks to certify.
    rx: Receiver<(BlockNumber, Block)>,

    /// Sender to return certified blocks back to the application.
    tx: Sender<CertifiedBlock>,

    /// Track votes for block signatures.
    trackers: BTreeMap<BlockNumber, BTreeMap<BlockInfo, Tracker>>,

    /// Keep the given number of blocks around when garbage collecting.
    retain: usize,

    /// Blocks to certify that wait for `Evidence` of previous rounds.
    #[builder(default)]
    pending: HashMap<BlockNumber, Block>,

    /// The next expected block to deliver.
    #[builder(default = BlockNumber::genesis())]
    next: BlockNumber,
}

struct Tracker {
    /// The block to certify.
    ///
    /// `None` in case we receive votes before the block itself is produced.
    block: Option<Block>,
    /// The vote accumulator for the block info.
    votes: VoteAccumulator<BlockInfo>,
    /// We remember the voters and only allow one vote per party and block.
    voters: SmallVec<[KeyId; 16]>,
}

impl Worker {
    pub async fn go(mut self) -> EndOfPlay {
        loop {
            select! {
                msg = self.net.receive() => match msg {
                    Ok((src, data)) =>
                        match self.on_message(src, data).await {
                            Ok(()) => {}
                            Err(ProducerError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, %src, "error on message")
                        }
                    Err(err) => {
                        let _: NetworkDown = err;
                        debug!(node = %self.label, "network down");
                        return EndOfPlay::NetworkDown
                    }
                },
                req = self.rx.recv() => match req {
                    Some((num, blk)) =>
                        match self.on_certify_request(num, blk).await {
                            Ok(()) => {}
                            Err(ProducerError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on certify request")
                        }
                    None => {
                        debug!(node = %self.label, "parent down");
                        return EndOfPlay::ProducerDown
                    }
                }
            }
            match self.deliver().await {
                Ok(()) => {}
                Err(ProducerError::End(end)) => return end,
                Err(err) => warn!(node = %self.label, %err, "delivery error"),
            }
        }
    }

    /// The application asked to certify the given block.
    async fn on_certify_request(&mut self, num: BlockNumber, block: Block) -> Result<()> {
        debug!(
            node  = %self.label,
            round = %block.round(),
            num   = %num,
            hash  = ?block.hash(),
            "certify request"
        );

        let info = BlockInfo::new(num, *block.hash(), self.committee.id());

        let Some(evi) = self.evidence(num) else {
            debug!(
                node  = %self.label,
                round = %block.round(),
                num   = %num,
                hash  = ?block.hash(),
                "stashing block until evidence is available"
            );
            self.pending.insert(info.num(), block);
            return Ok(());
        };

        self.send(block, info, evi).await
    }

    /// Broadcast the certification message to everyone.
    async fn send(&mut self, block: Block, info: BlockInfo, evi: Evidence) -> Result<()> {
        debug!(
            node  = %self.label,
            round = %block.round(),
            num   = %info.num(),
            hash  = ?block.hash(),
            "propose block hash"
        );

        let tracker = self
            .trackers
            .entry(info.num())
            .or_default()
            .entry(info.clone())
            .or_insert_with(|| Tracker {
                block: Some(block.clone()),
                votes: VoteAccumulator::new(self.committee.clone())
                    .with_threshold(self.committee.one_honest_threshold()),
                voters: SmallVec::new(),
            });

        if tracker.block.is_none() {
            tracker.block = Some(block.clone())
        }

        let msg = Message {
            info: Envelope::signed(info.clone(), &self.keypair),
            evidence: evi,
        };

        let data = serialize(&msg)?;
        self.net
            .broadcast(*info.num(), data)
            .await
            .map_err(|e| ProducerError::End(e.into()))?;

        Ok(())
    }

    /// A message from another block signer has been received.
    async fn on_message(&mut self, src: PublicKey, data: Bytes) -> Result<()> {
        debug!(node = %self.label, %src, "incoming message");

        let msg: Message<Unchecked> = deserialize(&data)?;

        let Some(info) = msg.info.validated(&self.committee) else {
            warn!(node = %self.label, %src, "invalid envelope signature");
            return Ok(());
        };

        if !msg.evidence.is_valid(
            info.data().num(),
            &self.committee,
            self.committee.one_honest_threshold(),
        ) {
            warn!(
                node = %self.label,
                src  = %src,
                num  = %info.data().num(),
                evi  = %msg.evidence.num(),
                "invalid message evidence"
            );
            return Ok(());
        }

        if self.has_voted(info.data().num(), &src) {
            debug!(node = %self.label, %src, num = %info.data().num(), "vote already counted");
            return Ok(());
        }

        let tracker = self
            .trackers
            .entry(info.data().num())
            .or_default()
            .entry(info.data().clone())
            .or_insert_with(|| Tracker {
                block: None,
                votes: VoteAccumulator::new(self.committee.clone())
                    .with_threshold(self.committee.one_honest_threshold()),
                voters: SmallVec::new(),
            });

        let num = info.data().num();

        match tracker.votes.add(info.into_signed()) {
            Ok(Some(cert)) => {
                // Check if a waiting block can be broadcasted, now that new evidence exists.
                if let Some(b) = self.pending.remove(&(num + 1)) {
                    let i = BlockInfo::new(num + 1, *b.hash(), self.committee.id());
                    let e = Evidence::Previous(cert.clone());
                    self.send(b, i, e).await?
                }
            }
            Ok(None) => {}
            Err(err) => {
                warn!(node = %self.label, %err, %src, %num, "failed to add block info vote");
            }
        }

        Ok(())
    }

    /// Go over trackers and deliver the next certified block, if any.
    async fn deliver(&mut self) -> Result<()> {
        let n = self.next;
        for t in self
            .trackers
            .get(&self.next)
            .into_iter()
            .flat_map(|tt| tt.values())
        {
            if let Some(cert) = t.votes.certificate() {
                if let Some(block) = &t.block {
                    let cb = CertifiedBlock::new(cert.clone(), block.clone());
                    self.tx
                        .send(cb)
                        .await
                        .map_err(|_| EndOfPlay::ProducerDown)?;
                    self.next = self.next + 1;
                    break;
                }
            }
        }
        if n != self.next {
            self.gc(self.next);
        } else {
            debug!(node = %self.label, num = %self.next, "still awaiting block");
        }
        Ok(())
    }

    fn gc(&mut self, num: BlockNumber) {
        let num: BlockNumber = num.saturating_sub(self.retain as u64).into();
        if *num > 0 {
            self.net.gc(*num)
        }
        self.trackers.retain(|n, _| *n >= num);
    }

    fn evidence(&self, num: BlockNumber) -> Option<Evidence> {
        if num.is_genesis() {
            return Some(Evidence::Genesis);
        }
        let trackers = self.trackers.get(&(num - 1))?;
        for t in trackers.values() {
            if let Some(cert) = t.votes.certificate() {
                return Some(Evidence::Previous(cert.clone()));
            }
        }
        None
    }

    fn has_voted(&self, num: BlockNumber, src: &PublicKey) -> bool {
        let Some(kid) = self.committee.get_index(src) else {
            error!(node = %self.label, %src, "unknown committee member");
            return false;
        };
        for (_, t) in self.trackers.get(&num).into_iter().flatten() {
            if t.voters.contains(&kid) {
                return true;
            }
        }
        false
    }
}

fn serialize<T: Serialize>(d: &T) -> Result<Data> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    let bytes = b.into_inner();
    Ok(Data::try_from(bytes)?)
}

fn deserialize<T>(d: &bytes::Bytes) -> Result<T>
where
    T: for<'de> serde::Deserialize<'de>,
{
    let cfg = bincode::config::standard().with_limit::<MAX_MESSAGE_SIZE>();
    bincode::serde::decode_from_slice(d, cfg)
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

    #[error("terminal error: {0}")]
    End(#[from] EndOfPlay),

    #[error("bincode encode error: {0}")]
    Encode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    Decode(#[from] bincode::error::DecodeError),

    #[error("data error: {0}")]
    DataError(#[from] DataError),
}

/// Fatal errors.
#[derive(Debug, thiserror::Error)]
pub enum EndOfPlay {
    #[error("network down")]
    NetworkDown,
    #[error("producer down")]
    ProducerDown,
}

impl From<NetworkDown> for EndOfPlay {
    fn from(_: NetworkDown) -> Self {
        Self::NetworkDown
    }
}

/// Evidence to include in certify messages.
#[derive(Serialize, Deserialize)]
enum Evidence {
    /// For block number 0.
    Genesis,
    /// For any block number > 0, the certificate of the previous block.
    Previous(Certificate<BlockInfo>),
}

impl Evidence {
    fn num(&self) -> BlockNumber {
        match self {
            Self::Genesis => BlockNumber::genesis(),
            Self::Previous(crt) => crt.data().num(),
        }
    }

    fn is_valid(&self, n: BlockNumber, c: &Committee, t: NonZeroUsize) -> bool {
        match self {
            Self::Genesis => n.is_genesis(),
            Self::Previous(cert) => {
                cert.data().num() + 1 == n && cert.is_valid_with_threshold_par(c, t)
            }
        }
    }
}

/// The certify message broadcasted to every block signer.
#[derive(Serialize, Deserialize)]
struct Message<S> {
    info: Envelope<BlockInfo, S>,
    evidence: Evidence,
}

impl Committable for Evidence {
    fn commit(&self) -> Commitment<Self> {
        match self {
            Self::Genesis => RawCommitmentBuilder::new("ProducerEvidence::Genesis").finalize(),
            Self::Previous(crt) => RawCommitmentBuilder::new("ProducerEvidence::Previous")
                .field("cert", crt.commit())
                .finalize(),
        }
    }
}

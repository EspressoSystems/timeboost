use std::collections::{BTreeMap, HashMap};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bon::Builder;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{
    AddressableCommittee, MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics, Role,
};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{
    Certificate, CommitteeId, Envelope, KeyId, Keypair, PublicKey, Unchecked, VoteAccumulator,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use timeboost_types::sailfish::{CommitteeVec, NodeInfo, Round, RoundNumber};
use timeboost_types::{Block, BlockInfo, BlockNumber, CertifiedBlock};
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::BlockProducerConfig;

type Result<T> = StdResult<T, ProducerError>;

const CAPACITY: usize = 128;

pub struct BlockProducer {
    /// Log label of the node.
    label: PublicKey,
    /// Command channel to worker.
    worker_tx: Sender<Command>,
    /// Receiver of certified blocks from worker.
    worker_rx: Receiver<CertifiedBlock>,
    /// Worker task handle.
    worker: JoinHandle<EndOfPlay>,
    /// Block number counter.
    counter: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct Handle {
    label: PublicKey,
    worker_tx: Sender<Command>,
    counter: Arc<AtomicU64>,
}

/// Worker commands.
enum Command {
    /// Certify the given block.
    Certify(BlockNumber, Block),
    /// Prepare for the next committee.
    NextCommittee(AddressableCommittee),
    /// Use a committee starting at the given round.
    UseCommittee(Round),
}

impl BlockProducer {
    pub async fn new<M>(cfg: BlockProducerConfig, metrics: &M) -> Result<Self>
    where
        M: metrics::Metrics,
    {
        let (cmd_tx, cmd_rx) = channel(CAPACITY);
        let (crt_tx, crt_rx) = channel(CAPACITY);

        let net_metrics = NetworkMetrics::new("block", metrics, cfg.committee.parties().copied());

        let net = Network::create(
            "block",
            cfg.address.clone(),
            cfg.sign_keypair.public_key(),
            cfg.dh_keypair.clone(),
            cfg.committee.entries(),
            net_metrics,
        )
        .await?;

        let worker = Worker::builder()
            .label(cfg.sign_keypair.public_key())
            .committees(CommitteeVec::new(cfg.committee.committee().clone()))
            .current(cfg.committee.committee().id())
            .keypair(cfg.sign_keypair.clone())
            .net(Overlay::new(net))
            .tx(crt_tx)
            .rx(cmd_rx)
            .tracking(Default::default())
            .maybe_next_block((!cfg.recover).then(BlockNumber::genesis))
            .info(NodeInfo::new(cfg.committee.committee()))
            .history(cfg.committee.committee().quorum_size().get() as u64)
            .build();

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            worker_tx: cmd_tx,
            worker_rx: crt_rx,
            worker: spawn(worker.go()),
            counter: Arc::new(AtomicU64::new(BlockNumber::genesis().into())),
        })
    }

    pub fn handle(&self) -> Handle {
        Handle {
            label: self.label,
            worker_tx: self.worker_tx.clone(),
            counter: self.counter.clone(),
        }
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
            blk = self.worker_rx.recv() => {
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

    /// Prepare for the next committee.
    pub async fn next_committee(&mut self, c: AddressableCommittee) -> StdResult<(), ProducerDown> {
        debug!(node = %self.label, committee = %c.committee().id(), "next committee");
        self.worker_tx
            .send(Command::NextCommittee(c))
            .await
            .map_err(|_| ProducerDown(()))?;
        Ok(())
    }

    /// Use a committee starting at the given round.
    pub async fn use_committee(&mut self, r: Round) -> StdResult<(), ProducerDown> {
        debug!(node = %self.label, round = %r, "use committee");
        self.worker_tx
            .send(Command::UseCommittee(r))
            .await
            .map_err(|_| ProducerDown(()))?;
        Ok(())
    }
}

impl Drop for BlockProducer {
    fn drop(&mut self) {
        self.worker.abort()
    }
}

impl Handle {
    /// Enqueue the given block for certification.
    pub async fn enqueue(&self, b: Block) -> StdResult<(), ProducerDown> {
        debug!(node = %self.label, round = %b.round(), hash = ?b.hash(), "enqueuing block");
        let num = self.counter.fetch_add(1, Ordering::Relaxed);
        self.worker_tx
            .send(Command::Certify(num.into(), b))
            .await
            .map_err(|_| ProducerDown(()))?;
        Ok(())
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

    /// The committees of block signers.
    committees: CommitteeVec<2>,

    /// Current committee ID.
    current: CommitteeId,

    /// The next committee ID and its round number (if any).
    next_committee: Option<Round>,

    /// Command channel receiver.
    rx: Receiver<Command>,

    /// Sender to return certified blocks back to the application.
    tx: Sender<CertifiedBlock>,

    /// Track votes for block signatures.
    tracking: BTreeMap<BlockNumber, Tracking>,

    /// Blocks to certify that wait for `Evidence` of previous rounds.
    #[builder(default)]
    pending: HashMap<BlockNumber, (Block, BlockInfo)>,

    /// The next expected block to deliver.
    next_block: Option<BlockNumber>,

    /// The local clock, driven by round number.
    #[builder(default = RoundNumber::genesis())]
    clock: RoundNumber,

    /// Quorum of block numbers to use with garbage collection.
    info: NodeInfo<BlockNumber>,

    /// How many extra blocks to keep before GC.
    history: u64,
}

#[derive(Default)]
struct Tracking {
    trackers: HashMap<BlockInfo, Tracker>,
    voters: SmallVec<[KeyId; 16]>,
}

struct Tracker {
    /// The block to certify.
    ///
    /// `None` in case we receive votes before the block itself is produced.
    block: Option<Block>,
    /// The vote accumulator for the block info.
    votes: VoteAccumulator<BlockInfo>,
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
                cmd = self.rx.recv() => match cmd {
                    Some(Command::Certify(n, b)) =>
                        match self.on_certify_request(n, b).await {
                            Ok(()) => {}
                            Err(ProducerError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on certify request")
                        }
                    Some(Command::NextCommittee(c)) =>
                        match self.on_next_committee(c).await {
                            Ok(()) => {}
                            Err(ProducerError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on use committee")
                        }
                    Some(Command::UseCommittee(r)) =>
                        match self.on_use_committee(r).await {
                            Ok(()) => {}
                            Err(ProducerError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on use committee")
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
        debug!(node = %self.label, round = %block.round(), %num, hash = ?block.hash(), "certify request");

        debug_assert!(self.clock.is_genesis() || self.clock < block.round());
        self.clock = block.round();
        self.maybe_switch_committee().await?;

        let round = Round::new(block.round(), self.current);
        let info = BlockInfo::new(num, round, *block.hash());

        let Some(evi) = self.evidence(num) else {
            debug!(
                node  = %self.label,
                round = %round,
                num   = %num,
                hash  = ?block.hash(),
                "stashing block until evidence is available"
            );
            self.pending.insert(info.num(), (block, info));
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

        let Some(committee) = self.committees.get(info.round().committee()).cloned() else {
            error!(node = %self.label, committee = %info.round().committee(), "no committee");
            return Err(ProducerError::NoCommittee(info.round().committee()));
        };

        let tracker = self
            .tracking
            .entry(info.num())
            .or_default()
            .trackers
            .entry(info.clone())
            .or_insert_with(|| Tracker {
                block: Some(block.clone()),
                votes: {
                    let t = committee.one_honest_threshold();
                    VoteAccumulator::new(committee.clone()).with_threshold(t)
                },
            });

        let msg = Message {
            info: Envelope::signed(info.clone(), &self.keypair),
            evidence: evi,
            next: self.next_block.unwrap_or_default(),
        };

        if tracker.block.is_none() {
            tracker.block = Some(block)
        }

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

        let Some(committee) = self
            .committees
            .get(msg.info.data().round().committee())
            .cloned()
        else {
            return Err(ProducerError::NoCommittee(
                msg.info.data().round().committee(),
            ));
        };

        let Some(info) = msg.info.validated(&committee) else {
            warn!(node = %self.label, %src, "invalid envelope signature");
            return Ok(());
        };

        if !msg.evidence.is_valid(info.data(), &self.committees) {
            warn!(
                node = %self.label,
                src  = %src,
                num  = %info.data().num(),
                evi  = %msg.evidence.num(),
                "invalid message evidence"
            );
            return Ok(());
        }

        self.info.record(&src, msg.next);

        let tracking = self.tracking.entry(info.data().num()).or_default();

        let kid = committee
            .get_index(&src)
            .expect("valid signing key => member of committee");

        if tracking.voters.contains(&kid) {
            debug!(node = %self.label, %src, num = %info.data().num(), "vote already counted");
            return Ok(());
        }

        let tracker = tracking
            .trackers
            .entry(info.data().clone())
            .or_insert_with(|| Tracker {
                block: None,
                votes: {
                    let t = committee.one_honest_threshold();
                    VoteAccumulator::new(committee).with_threshold(t)
                },
            });

        let num = info.data().num();

        match tracker.votes.add(info.into_signed()) {
            Ok(Some(cert)) => {
                tracking.voters.push(kid);
                // Check if a waiting block can be broadcasted, now that new evidence exists.
                if let Some((b, i)) = self.pending.remove(&(num + 1)) {
                    let e = Evidence::Previous(cert.clone());
                    self.send(b, i, e).await?
                }
            }
            Ok(None) => {
                tracking.voters.push(kid);
            }
            Err(err) => {
                warn!(node = %self.label, %err, %src, %num, "failed to add block info vote");
            }
        }

        Ok(())
    }

    /// Go over trackers and deliver the next certified block, if any.
    async fn deliver(&mut self) -> Result<()> {
        let lower_bound: BlockNumber = self.info.quorum().saturating_sub(self.history).into();

        // Check if we need to catch up to the others.
        if self
            .next_block
            .map(|n| n + self.history < lower_bound)
            .unwrap_or(false)
        {
            debug!(node = %self.label, next = ?self.next_block, %lower_bound, "catching up");
            // To catch up we first discard everything too old.
            self.next_block = Some(lower_bound);
            self.gc(lower_bound);
            // Now we look for the first block number which has a certificate
            // available and continue from there.
            for (i, t) in self.tracking.values().flat_map(|t| t.trackers.iter()) {
                if t.deliver(&self.tx).await? {
                    self.next_block = Some(i.num() + 1);
                    break;
                }
            }
        }

        let start = self.next_block;

        'main: loop {
            if let Some(next) = self.next_block {
                for t in self
                    .tracking
                    .get(&next)
                    .into_iter()
                    .flat_map(|t| t.trackers.values())
                {
                    if t.deliver(&self.tx).await? {
                        self.next_block = Some(next + 1);
                        continue 'main;
                    }
                }
                break;
            } else {
                // If next_block is not available yet we look for the first block
                // we can deliver and start from there.
                for (i, t) in self.tracking.values().flat_map(|t| t.trackers.iter()) {
                    if t.deliver(&self.tx).await? {
                        self.next_block = Some(i.num() + 1);
                        continue 'main;
                    }
                }
                break;
            }
        }

        if start != self.next_block {
            self.gc(lower_bound);
        }

        Ok(())
    }

    fn gc(&mut self, lower_bound: BlockNumber) {
        if !lower_bound.is_genesis() {
            self.net.gc(*lower_bound);
            self.tracking.retain(|n, _| *n >= lower_bound);
        }
    }

    fn evidence(&self, num: BlockNumber) -> Option<Evidence> {
        if num.is_genesis() {
            return Some(Evidence::Genesis);
        }
        let t = self.tracking.get(&(num - 1))?;
        for t in t.trackers.values() {
            if let Some(cert) = t.votes.certificate().cloned() {
                return Some(Evidence::Previous(cert));
            }
        }
        None
    }

    async fn on_next_committee(&mut self, c: AddressableCommittee) -> Result<()> {
        info!(node = %self.label, committee = %c.committee().id(), "add next committee");
        if self.committees.contains(c.committee().id()) {
            warn!(node = %self.label, committee = %c.committee().id(), "committee already added");
            return Ok(());
        }
        let Some(committee) = self.committees.get(self.current) else {
            error!(node = %self.label, committee = %self.current, "current committee not found");
            return Err(ProducerError::NoCommittee(self.current));
        };
        let mut additional = Vec::new();
        for (k, x, a) in c.entries().filter(|(k, ..)| !committee.contains_key(k)) {
            additional.push((k, x, a))
        }
        self.net
            .add(additional)
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.committees.add(c.committee().clone());
        Ok(())
    }

    async fn on_use_committee(&mut self, round: Round) -> Result<()> {
        info!(node = %self.label, %round, "use committee");
        if self.committees.get(round.committee()).is_none() {
            error!(node = %self.label, committee = %round.committee(), "committee to use does not exist");
            return Err(ProducerError::NoCommittee(round.committee()));
        };
        self.next_committee = Some(round);
        Ok(())
    }

    async fn maybe_switch_committee(&mut self) -> Result<()> {
        let Some(start) = self.next_committee else {
            return Ok(());
        };
        if self.clock < start.num() {
            return Ok(());
        }
        let Some(committee) = self.committees.get(self.current) else {
            error!(node = %self.label, committee = %self.current, "current committee not found");
            return Err(ProducerError::NoCommittee(self.current));
        };
        let old = self
            .net
            .parties()
            .map(|(p, _)| p)
            .filter(|p| !committee.contains_key(p))
            .copied();
        self.net
            .remove(old.collect())
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.net
            .assign(Role::Active, committee.parties().copied().collect())
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.current = start.committee();
        self.history = committee.quorum_size().get() as u64;
        Ok(())
    }
}

impl Tracker {
    async fn deliver(&self, tx: &Sender<CertifiedBlock>) -> Result<bool> {
        if let Some(cert) = self.votes.certificate() {
            if let Some(block) = &self.block {
                let cb = CertifiedBlock::new(cert.clone(), block.clone());
                tx.send(cb).await.map_err(|_| EndOfPlay::ProducerDown)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The certify message broadcasted to every block signer.
#[derive(Serialize, Deserialize)]
struct Message<S> {
    info: Envelope<BlockInfo, S>,
    evidence: Evidence,
    next: BlockNumber,
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

    #[error("unknown committee: {0}")]
    NoCommittee(CommitteeId),
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

    fn is_valid(&self, i: &BlockInfo, v: &CommitteeVec<2>) -> bool {
        match self {
            Self::Genesis => i.num().is_genesis(),
            Self::Previous(cert) => {
                let Some(c) = v.get(i.round().committee()) else {
                    return false;
                };
                let t = c.one_honest_threshold();
                cert.data().num() + 1 == i.num() && cert.is_valid_with_threshold_par(c, t)
            }
        }
    }
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

use std::collections::{BTreeMap, HashMap};
use std::result::Result as StdResult;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arrayvec::ArrayVec;
use bon::Builder;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{
    AddressableCommittee, MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics, Role,
};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{
    Certificate, Committee, CommitteeId, Envelope, KeyId, Keypair, PublicKey, Unchecked,
    VoteAccumulator,
};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use timeboost_types::sailfish::{Round, RoundNumber};
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
        let (cmd_tx, cmd_rx) = channel(cfg.retain);
        let (crt_tx, crt_rx) = channel(cfg.retain);

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
            .committees({
                let mut v = ArrayVec::new();
                v.push((RoundNumber::genesis(), cfg.committee.committee().clone()));
                v
            })
            .keypair(cfg.sign_keypair.clone())
            .net(Overlay::new(net))
            .tx(crt_tx)
            .rx(cmd_rx)
            .trackers(Default::default())
            .next_committee(NextCommittee::None)
            .retain(cfg.retain)
            .maybe_next_block((!cfg.recover).then(BlockNumber::genesis))
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

/// Max. supported number of committees.
const MAX_COMMITTEES: usize = 2;

#[derive(Builder)]
struct Worker {
    /// Our signing keypair.
    keypair: Keypair,

    /// Log label.
    label: PublicKey,

    /// Network handle.
    net: Overlay,

    /// The committees of block signers.
    ///
    /// The round number denotes the start of the epoch where a
    /// committee is active.
    committees: ArrayVec<(RoundNumber, Committee), MAX_COMMITTEES>,

    /// The next committee to use, if any.
    next_committee: NextCommittee,

    /// Command channel receiver.
    rx: Receiver<Command>,

    /// Sender to return certified blocks back to the application.
    tx: Sender<CertifiedBlock>,

    /// Track votes for block signatures.
    trackers: BTreeMap<BlockNumber, Tracker>,

    /// Blocks to certify that wait for `Evidence` of previous rounds.
    #[builder(default)]
    pending: HashMap<BlockNumber, Block>,

    /// The next expected block to deliver.
    next_block: Option<BlockNumber>,

    /// The local clock, driven by round number.
    #[builder(default = RoundNumber::genesis())]
    clock: RoundNumber,

    /// Keep the given number of blocks around when garbage collecting.
    retain: usize,
}

struct Tracker {
    /// The block to certify.
    ///
    /// `None` in case we receive votes before the block itself is produced.
    block: Option<Block>,
    /// The vote accumulator for the block info.
    votes: VoteAccumulator<BlockInfo>,
    /// We remember the voters and only allow one vote per party and block number.
    voters: SmallVec<[KeyId; 16]>,
}

/// Information about the next committee.
enum NextCommittee {
    /// None expected
    None,
    /// A new committee is known, but we have no round number yet.
    Next(Committee),
    /// We wait for the given round before we activate the next committee.
    ActivateIn(RoundNumber),
}

impl NextCommittee {
    fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
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
                        if let Err(err) = self.on_next_committee(c).await {
                            let _: NetworkDown = err;
                            debug!(node = %self.label, "network down");
                            return EndOfPlay::NetworkDown
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

        let info = BlockInfo::new(num, block.round(), *block.hash());

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

        let Some(committee) = self.committee_of(block.round()).cloned() else {
            error!(node = %self.label, round = %block.round(), "no committee for round");
            return Err(ProducerError::NoCommitteeForRound(block.round()));
        };

        let tracker = self.trackers.entry(info.num()).or_insert_with(|| Tracker {
            block: Some(block.clone()),
            votes: {
                let t = committee.one_honest_threshold();
                VoteAccumulator::new(committee.clone()).with_threshold(t)
            },
            voters: SmallVec::new(),
        });

        let msg = Message {
            info: Envelope::signed(info.clone(), &self.keypair),
            evidence: evi,
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

        let Some(committee) = self.committee_of(msg.info.data().round()).cloned() else {
            return Err(ProducerError::NoCommitteeForRound(msg.info.data().round()));
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

        let kid = committee
            .get_index(&src)
            .expect("valid signing key => member of committee");

        let tracker = self
            .trackers
            .entry(info.data().num())
            .or_insert_with(|| Tracker {
                block: None,
                votes: {
                    let t = committee.one_honest_threshold();
                    VoteAccumulator::new(committee).with_threshold(t)
                },
                voters: SmallVec::new(),
            });

        if tracker.voters.contains(&kid) {
            debug!(node = %self.label, %src, num = %info.data().num(), "vote already counted");
            return Ok(());
        }

        let num = info.data().num();

        match tracker.votes.add(info.into_signed()) {
            Ok(Some(cert)) => {
                tracker.voters.push(kid);
                // Check if a waiting block can be broadcasted, now that new evidence exists.
                if let Some(b) = self.pending.remove(&(num + 1)) {
                    let e = Evidence::Previous(cert.clone());
                    let i = BlockInfo::new(num + 1, b.round(), *b.hash());
                    self.send(b, i, e).await?
                }
            }
            Ok(None) => {
                tracker.voters.push(kid);
            }
            Err(err) => {
                warn!(node = %self.label, %err, %src, %num, "failed to add block info vote");
            }
        }

        Ok(())
    }

    /// Go over trackers and deliver the next certified block, if any.
    async fn deliver(&mut self) -> Result<()> {
        let start = self.next_block;

        'main: loop {
            if let Some(next) = self.next_block {
                if let Some(t) = self.trackers.get(&next) {
                    if t.deliver(&self.tx).await? {
                        self.next_block = Some(next + 1);
                        continue 'main;
                    }
                }
                break;
            } else {
                // If next_block is not available yet we look for the first block
                // we can deliver and start from there.
                for (i, t) in &self.trackers {
                    if t.deliver(&self.tx).await? {
                        self.next_block = Some(*i + 1);
                        continue 'main;
                    }
                }
                break;
            }
        }

        if start != self.next_block {
            self.gc();
        }

        Ok(())
    }

    fn gc(&mut self) {
        let Some(next) = self.next_block else { return };
        let num: BlockNumber = next.saturating_sub(self.retain as u64).into();
        if *num > 0 {
            self.net.gc(*num)
        }
        self.trackers.retain(|n, _| *n >= num);
    }

    fn evidence(&self, num: BlockNumber) -> Option<Evidence> {
        if num.is_genesis() {
            return Some(Evidence::Genesis);
        }
        let t = self.trackers.get(&(num - 1))?;
        t.votes.certificate().cloned().map(Evidence::Previous)
    }

    fn committee_of(&self, r: RoundNumber) -> Option<&Committee> {
        self.committees
            .iter()
            .find_map(|(n, c)| (r >= *n).then_some(c))
    }

    /// Add the next committee.
    ///
    /// This adds any new parties to the network and stores the committee as
    /// the next one to use.
    async fn on_next_committee(&mut self, c: AddressableCommittee) -> StdResult<(), NetworkDown> {
        info!(node = %self.label, committee = %c.committee().id(), "add next committee");
        if !self.next_committee.is_none() {
            error!(node = %self.label, id = %c.committee().id(), "next committee already pending");
            return Ok(());
        }
        if let Some(current) = self.committee_of(self.clock) {
            let mut additional = Vec::new();
            for (k, x, a) in c.entries().filter(|(k, ..)| !current.contains_key(k)) {
                additional.push((k, x, a))
            }
            self.net.add(additional).await?;
        }
        self.next_committee = NextCommittee::Next(c.committee().clone());
        Ok(())
    }

    /// Use a committee starting at the given round.
    ///
    /// Assuming the committee ID corresponds to the next committee we move it
    /// into our committee collection with the round number as its epoch start.
    async fn on_use_committee(&mut self, round: Round) -> Result<()> {
        info!(node = %self.label, %round, "use committee");
        let NextCommittee::Next(committee) = &self.next_committee else {
            error!(node = %self.label, %round, "committee to use does not exist");
            return Err(ProducerError::NoCommittee(round.committee()));
        };
        if committee.id() != round.committee() {
            error!(node = %self.label, next = %committee.id(), %round, "unexpected committee to use");
            return Err(ProducerError::NoCommittee(round.committee()));
        }
        self.committees.truncate(MAX_COMMITTEES - 1);
        self.committees.insert(0, (round.num(), committee.clone()));
        self.next_committee = NextCommittee::ActivateIn(round.num());
        Ok(())
    }

    /// Activate a committee at the correct round number.
    async fn maybe_switch_committee(&mut self) -> Result<()> {
        let NextCommittee::ActivateIn(start) = self.next_committee else {
            return Ok(());
        };
        if self.clock < start {
            return Ok(());
        }
        let Some(committee) = self.committee_of(start).cloned() else {
            error!(node = %self.label, "committee to activate does not exist");
            return Err(ProducerError::NoCommitteeForRound(start));
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
        self.next_committee = NextCommittee::None;
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

    #[error("no committee for round: {0}")]
    NoCommitteeForRound(RoundNumber),
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

    fn is_valid<const N: usize>(
        &self,
        i: &BlockInfo,
        v: &ArrayVec<(RoundNumber, Committee), N>,
    ) -> bool {
        match self {
            Self::Genesis => i.num().is_genesis(),
            Self::Previous(cert) => {
                let Some(c) = v
                    .iter()
                    .find_map(|(r, c)| (cert.data().round() >= *r).then_some(c))
                else {
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

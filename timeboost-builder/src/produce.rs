use std::collections::{BTreeMap, HashMap};
use std::result::Result as StdResult;

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
    counter: BlockNumber,
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
            .epoch(RoundNumber::genesis())
            .keypair(cfg.sign_keypair.clone())
            .net(Overlay::new(net))
            .tx(crt_tx)
            .rx(cmd_rx)
            .tracking(Default::default())
            .retain(cfg.retain)
            .build();

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            worker_tx: cmd_tx,
            worker_rx: crt_rx,
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
        self.worker_tx
            .send(Command::Certify(self.counter, b))
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

    /// Begin of current committee epoch.
    epoch: RoundNumber,

    /// The next committee to use, if any.
    next_committee: Option<Committee>,

    /// Command channel receiver.
    rx: Receiver<Command>,

    /// Sender to return certified blocks back to the application.
    tx: Sender<CertifiedBlock>,

    /// Track votes for block signatures.
    tracking: BTreeMap<BlockNumber, Tracking>,

    /// Keep the given number of blocks around when garbage collecting.
    retain: usize,

    /// Blocks to certify that wait for `Evidence` of previous rounds.
    #[builder(default)]
    pending: HashMap<BlockNumber, Block>,

    /// The next expected block to deliver.
    #[builder(default = BlockNumber::genesis())]
    next: BlockNumber,
}

#[derive(Default)]
struct Tracking {
    /// We keep one tracker per block info.
    ///
    /// The reason for that is that a `VoteAccumulator` corresponds to one
    /// committee and the block info contains a committee ID that is used
    /// to select the committee. The committee can therefore not be subject
    /// to voting.
    trackers: BTreeMap<BlockInfo, Tracker>,
    /// We remember the voters and only allow one vote per party and block number.
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
                    Some(Command::Certify(num, blk)) =>
                        match self.on_certify_request(num, blk).await {
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

    /// Add the next committee.
    async fn on_next_committee(&mut self, c: AddressableCommittee) -> StdResult<(), NetworkDown> {
        info!(node = %self.label, committee = %c.committee().id(), "next committee");
        if let Some(next) = &self.next_committee {
            error!(
                node = %self.label,
                next = %next.id(),
                arg  = %c.committee().id(),
                "next committee already exists"
            );
            return Ok(());
        }
        let mut additional = Vec::new();
        for (k, x, a) in c
            .entries()
            .filter(|(k, ..)| !self.current_committee().contains_key(k))
        {
            additional.push((k, x, a))
        }
        self.net.add(additional).await?;
        self.next_committee = Some(c.committee().clone());
        Ok(())
    }

    /// Use a committee starting at the given round.
    async fn on_use_committee(&mut self, round: Round) -> Result<()> {
        info!(node = %self.label, %round, "use committee");
        let Some(committee) = self.next_committee.take() else {
            error!(node = %self.label, %round, "committee to use does not exist");
            return Err(ProducerError::NoCommittee(round.committee()));
        };
        if committee.id() != round.committee() {
            error!(node = %self.label, next = %committee.id(), %round, "unexpected committee to use");
            self.next_committee = Some(committee);
            return Err(ProducerError::NoCommittee(round.committee()));
        }
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
        self.committees.truncate(MAX_COMMITTEES - 1);
        self.committees.insert(0, (round.num(), committee));
        self.epoch = round.num();
        Ok(())
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

        let Some(committee) = self.committee_of_round(block.round()) else {
            error!(node = %self.label, round = %block.round(), "no committee for round");
            return Err(ProducerError::NoCommitteeForRound(block.round()));
        };

        let info = BlockInfo::new(num, *block.hash(), committee.id());

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

        let Some(committee) = self.committee_of_round(block.round()).cloned() else {
            error!(node = %self.label, round = %block.round(), "no committee for round");
            return Err(ProducerError::NoCommitteeForRound(block.round()));
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
                    VoteAccumulator::new(committee).with_threshold(t)
                },
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

        let Some(committee) = self.committee(msg.info.data().committee()).cloned() else {
            return Err(ProducerError::NoCommittee(msg.info.data().committee()));
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
                if let Some(b) = self.pending.remove(&(num + 1)) {
                    let e = Evidence::Previous(cert.clone());
                    let Some(c) = self.committee_of_round(b.round()) else {
                        error!(node = %self.label, round = %b.round(), "no committee for round");
                        return Err(ProducerError::NoCommitteeForRound(b.round()));
                    };
                    let i = BlockInfo::new(num + 1, *b.hash(), c.id());
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
        let n = self.next;
        for t in self
            .tracking
            .get(&self.next)
            .into_iter()
            .flat_map(|t| t.trackers.values())
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
        self.tracking.retain(|n, _| *n >= num);
    }

    fn evidence(&self, num: BlockNumber) -> Option<Evidence> {
        if num.is_genesis() {
            return Some(Evidence::Genesis);
        }
        for t in self.tracking.get(&(num - 1))?.trackers.values() {
            if let Some(cert) = t.votes.certificate() {
                return Some(Evidence::Previous(cert.clone()));
            }
        }
        None
    }

    fn current_committee(&self) -> &Committee {
        self.committees
            .iter()
            .find_map(|(r, c)| (r == &self.epoch).then_some(c))
            .expect("`use_committee` ensures that committee of epoch exists")
    }

    fn committee(&self, i: CommitteeId) -> Option<&Committee> {
        self.committees
            .iter()
            .find_map(|(_, c)| (c.id() == i).then_some(c))
    }

    fn committee_of_round(&self, r: RoundNumber) -> Option<&Committee> {
        self.committees
            .iter()
            .find_map(|(n, c)| (r >= *n).then_some(c))
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
                    .find_map(|(_, c)| (c.id() == i.committee()).then_some(c))
                else {
                    return false;
                };
                let t = c.one_honest_threshold();
                cert.data().num() + 1 == i.num() && cert.is_valid_with_threshold_par(c, t)
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::Infallible;
use std::result::Result as StdResult;

use adapters::bytes::BytesWriter;
use bon::Builder;
use bytes::{Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{AddressableCommittee, Network, NetworkError, NetworkMetrics, Role};
use committable::{Commitment, Committable, RawCommitmentBuilder};
use minicbor::{Decode, Encode};
use multisig::{
    Certificate, CommitteeId, Envelope, KeyId, Keypair, PublicKey, Unchecked, Validated,
    VoteAccumulator,
};
use smallvec::SmallVec;
use timeboost_types::sailfish::{CommitteeVec, NodeInfo, Round, RoundNumber};
use timeboost_types::{Block, BlockInfo, BlockNumber, CertifiedBlock};
use tokio::select;
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::CertifierConfig;

type Result<T> = StdResult<T, CertifierError>;

const CAPACITY: usize = 128;

pub struct Certifier {
    /// Log label of the node.
    label: PublicKey,
    /// Command channel to worker.
    worker_tx: Sender<Command>,
    /// Receiver of certified blocks from worker.
    worker_rx: Receiver<CertifiedBlock<Validated>>,
    /// Worker task handle.
    worker: JoinHandle<EndOfPlay>,
}

#[derive(Clone)]
pub struct Handle {
    label: PublicKey,
    worker_tx: Sender<Command>,
}

/// Worker commands.
enum Command {
    /// Certify the given block.
    Certify(Block),
    /// Prepare for the next committee.
    NextCommittee(AddressableCommittee),
    /// Use a committee starting at the given round.
    UseCommittee(Round),
}

impl Certifier {
    pub async fn new<M>(cfg: CertifierConfig, metrics: &M) -> Result<Self>
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
            .info({
                let c = cfg.committee.committee();
                NodeInfo::new(c, c.one_honest_threshold())
            })
            .history(cfg.committee.committee().quorum_size().get() as u64)
            .recover(cfg.recover)
            .build();

        Ok(Self {
            label: cfg.sign_keypair.public_key(),
            worker_tx: cmd_tx,
            worker_rx: crt_rx,
            worker: spawn(worker.go()),
        })
    }

    pub fn handle(&self) -> Handle {
        Handle {
            label: self.label,
            worker_tx: self.worker_tx.clone(),
        }
    }

    /// Get the next certified block.
    ///
    /// # Panics
    ///
    /// Once a `CertifierDown` error is returned, calling `next_block` again panics.
    pub async fn next_block(&mut self) -> StdResult<CertifiedBlock<Validated>, CertifierDown> {
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
                        num   = %b.data().num(),
                        round = %b.data().round(),
                        hash  = %b.data().hash(),
                        "certified block"
                    );
                    return Ok(b)
                }
                error!(node = %self.label, "worker terminated");
            }
        }
        Err(CertifierDown(()))
    }

    /// Prepare for the next committee.
    pub async fn set_next_committee(
        &mut self,
        c: AddressableCommittee,
    ) -> StdResult<(), CertifierDown> {
        debug!(node = %self.label, committee = %c.committee().id(), "next committee");
        // map to Certifier network
        let c = translate_addr(c);
        self.worker_tx
            .send(Command::NextCommittee(c))
            .await
            .map_err(|_| CertifierDown(()))?;
        Ok(())
    }

    /// Use a committee starting at the given round.
    pub async fn use_committee(&mut self, r: Round) -> StdResult<(), CertifierDown> {
        debug!(node = %self.label, round = %r, "use committee");
        self.worker_tx
            .send(Command::UseCommittee(r))
            .await
            .map_err(|_| CertifierDown(()))?;
        Ok(())
    }
}

fn translate_addr(c: AddressableCommittee) -> AddressableCommittee {
    let committee = c.committee().clone();
    let shifted_entries = c
        .entries()
        .map(|(pk, dh, addr)| {
            let dec_port = addr.port().saturating_add(2000);
            let new_addr = addr.with_port(dec_port);
            (pk, dh, new_addr)
        })
        .collect::<Vec<_>>();
    AddressableCommittee::new(committee, shifted_entries)
}

impl Drop for Certifier {
    fn drop(&mut self) {
        self.worker.abort()
    }
}

impl Handle {
    /// Enqueue the given block for certification.
    pub async fn enqueue(&self, b: Block) -> StdResult<(), CertifierDown> {
        debug!(
            node  = %self.label,
            num   = %b.num(),
            round = %b.round(),
            hash  = %b.hash(),
            "enqueuing block"
        );
        self.worker_tx
            .send(Command::Certify(b))
            .await
            .map_err(|_| CertifierDown(()))?;
        Ok(())
    }
}

/// Next committee state.
#[derive(Default)]
enum NextCommittee {
    /// No next committee is scheduled.
    #[default]
    None,
    /// The next committee should become effective at the given round.
    Use(Round),
    /// The old committee should be removed when the given round is garbage collected.
    Del(Round),
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
    #[builder(default)]
    next_committee: NextCommittee,

    /// Command channel receiver.
    rx: Receiver<Command>,

    /// Sender to return certified blocks back to the application.
    tx: Sender<CertifiedBlock<Validated>>,

    /// Track votes for block signatures.
    #[builder(default)]
    tracking: BTreeMap<BlockNumber, Tracking>,

    /// Blocks to certify that wait for `Evidence` of a previous block.
    #[builder(default)]
    pending: HashMap<BlockNumber, (Block, BlockInfo)>,

    /// Here we record every party when we receive its first message.
    ///
    /// Unknown parties are allowed to send one message without evidence.
    #[builder(default)]
    known: HashSet<PublicKey>,

    /// The next expected block to deliver.
    next_block: Option<BlockNumber>,

    /// The local clock, driven by round number.
    #[builder(default = RoundNumber::genesis())]
    clock: RoundNumber,

    /// Are we recovering from a crash?
    recover: bool,

    /// Quorum of block numbers to use with garbage collection.
    info: NodeInfo<BlockNumber>,

    /// How many extra blocks to keep before GC.
    history: u64,
}

#[derive(Default)]
struct Tracking {
    /// We keep one tracker per block info.
    ///
    /// The reason for that is that a `VoteAccumulator` corresponds to one
    /// committee and the block info contains a committee ID that is used
    /// to select the committee. The committee can therefore not be subject
    /// to voting.
    trackers: HashMap<BlockInfo, Tracker>,
    /// We remember the voters and only allow one vote per party and block hash.
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
                            Err(CertifierError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, %src, "error on message")
                        }
                    Err(err) => {
                        let _: NetworkDown = err;
                        debug!(node = %self.label, "network down");
                        return EndOfPlay::NetworkDown
                    }
                },
                cmd = self.rx.recv() => match cmd {
                    Some(Command::Certify(b)) =>
                        match self.on_certify_request(b).await {
                            Ok(()) => {}
                            Err(CertifierError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on certify request")
                        }
                    Some(Command::NextCommittee(c)) =>
                        match self.on_next_committee(c).await {
                            Ok(()) => {}
                            Err(CertifierError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on use committee")
                        }
                    Some(Command::UseCommittee(r)) =>
                        match self.on_use_committee(r).await {
                            Ok(()) => {}
                            Err(CertifierError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on use committee")
                        }
                    None => {
                        debug!(node = %self.label, "parent down");
                        return EndOfPlay::CertifierDown
                    }
                }
            }
            match self.deliver().await {
                Ok(()) => {}
                Err(CertifierError::End(end)) => return end,
                Err(err) => warn!(node = %self.label, %err, "delivery error"),
            }
        }
    }

    /// The application asked to certify the given block.
    async fn on_certify_request(&mut self, block: Block) -> Result<()> {
        debug!(
            node  = %self.label,
            round = %block.round(),
            num   = %block.num(),
            hash  = %block.hash(),
            "certify request"
        );

        debug_assert!(self.clock.is_genesis() || self.clock < block.round());
        self.clock = block.round();
        self.maybe_switch_committee().await?;

        let round = Round::new(block.round(), self.current);
        let info = BlockInfo::new(block.num(), round, block.hash());
        let evidence = self.evidence(block.num());

        if self.next_block.is_none() {
            self.next_block = Some(block.num());
            if self.recover {
                debug!(
                    node  = %self.label,
                    round = %block.round(),
                    num   = %block.num(),
                    hash  = %block.hash(),
                    "recovering: stashing block until evidence is available"
                );
                self.pending.insert(block.num(), (block, info));
                return Ok(());
            }
        } else if evidence.is_none() {
            debug!(
                node  = %self.label,
                round = %block.round(),
                num   = %block.num(),
                hash  = %block.hash(),
                "stashing block until evidence is available"
            );
            self.pending.insert(block.num(), (block, info));
            return Ok(());
        }

        self.send(block, info, evidence).await
    }

    /// Broadcast the certification message to everyone.
    async fn send(&mut self, block: Block, info: BlockInfo, evi: Option<Evidence>) -> Result<()> {
        debug!(
            node  = %self.label,
            round = %block.round(),
            num   = %info.num(),
            hash  = %block.hash(),
            "propose block hash"
        );

        let Some(committee) = self.committees.get(info.round().committee()).cloned() else {
            error!(node = %self.label, committee = %info.round().committee(), "no committee");
            return Err(CertifierError::NoCommittee(info.round().committee()));
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

        let data = {
            let mut w = BytesWriter::default();
            minicbor::encode(&msg, &mut w)?;
            Data::try_from(BytesMut::from(w))?
        };

        self.net
            .broadcast(*info.num(), data)
            .await
            .map_err(|e| CertifierError::End(e.into()))?;

        Ok(())
    }

    /// A message from another block signer has been received.
    async fn on_message(&mut self, src: PublicKey, data: Bytes) -> Result<()> {
        trace!(node = %self.label, %src, "incoming message");

        let msg: Message<Unchecked> = minicbor::decode(&data)?;

        let Some(committee) = self
            .committees
            .get(msg.info.data().round().committee())
            .cloned()
        else {
            return Err(CertifierError::NoCommittee(
                msg.info.data().round().committee(),
            ));
        };

        let Some(info) = msg.info.validated(&committee) else {
            warn!(node = %self.label, %src, "invalid envelope signature");
            return Ok(());
        };

        if let Some(evi) = msg.evidence {
            if !evi.is_valid(info.data(), &self.committees) {
                warn!(
                    node = %self.label,
                    src  = %src,
                    num  = %info.data().num(),
                    evi  = %evi.num(),
                    "invalid message evidence"
                );
                return Ok(());
            }
        } else if self.known.contains(&src) {
            warn!(
                node = %self.label,
                src  = %src,
                num  = %info.data().num(),
                "missing message evidence"
            );
            return Ok(());
        } else {
            self.known.insert(src);
        }

        debug!(
            node  = %self.label,
            src   = %src,
            num   = %info.data().num(),
            round = %info.data().round(),
            hash  = %info.data().hash(),
            "message received"
        );

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
                    let e = Evidence(cert.clone());
                    self.send(b, i, Some(e)).await?
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
        if self.next_block.unwrap_or_default() < lower_bound {
            debug!(node = %self.label, next = ?self.next_block, %lower_bound, "catching up");
            // To catch up we first discard everything too old.
            self.next_block = Some(lower_bound);
            self.gc(lower_bound).await?;
            // Now we look for the first block number which has a certificate
            // available and continue from there.
            for (i, t) in self.tracking.values().flat_map(|t| t.trackers.iter()) {
                if t.deliver(self.is_leader(i), &self.tx).await? {
                    self.next_block = Some(i.num() + 1);
                    break;
                }
            }
        }

        let start = self.next_block;

        'main: loop {
            if let Some(next) = self.next_block {
                for (i, t) in self
                    .tracking
                    .get(&next)
                    .into_iter()
                    .flat_map(|t| &t.trackers)
                {
                    if t.deliver(self.is_leader(i), &self.tx).await? {
                        self.next_block = Some(next + 1);
                        continue 'main;
                    }
                }
                break;
            } else {
                // If next_block is not available yet we look for the first block
                // we can deliver and start from there.
                for (i, t) in self.tracking.values().flat_map(|t| t.trackers.iter()) {
                    if t.deliver(self.is_leader(i), &self.tx).await? {
                        self.next_block = Some(i.num() + 1);
                        continue 'main;
                    }
                }
                break;
            }
        }

        if start != self.next_block {
            self.gc(lower_bound).await?;
        }

        Ok(())
    }

    async fn gc(&mut self, lower_bound: BlockNumber) -> Result<()> {
        self.net.gc(*lower_bound);
        self.tracking.retain(|n, _| *n >= lower_bound);
        self.remove_old_committee().await
    }

    fn evidence(&self, num: BlockNumber) -> Option<Evidence> {
        let t = self.tracking.get(&num.saturating_sub(1).into())?;
        for t in t.trackers.values() {
            if let Some(cert) = t.votes.certificate().cloned() {
                return Some(Evidence(cert));
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
            return Err(CertifierError::NoCommittee(self.current));
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
            return Err(CertifierError::NoCommittee(round.committee()));
        };
        self.next_committee = NextCommittee::Use(round);
        Ok(())
    }

    async fn maybe_switch_committee(&mut self) -> Result<()> {
        let NextCommittee::Use(start) = self.next_committee else {
            return Ok(());
        };
        if self.clock < start.num() {
            return Ok(());
        }
        let Some(committee) = self.committees.get(start.committee()) else {
            error!(node = %self.label, committee = %self.current, "current committee not found");
            return Err(CertifierError::NoCommittee(start.committee()));
        };
        let old = self
            .net
            .parties()
            .map(|(p, _)| p)
            .filter(|p| !committee.contains_key(p))
            .copied()
            .collect::<Vec<_>>();
        self.net
            .assign(Role::Passive, old)
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.net
            .assign(Role::Active, committee.parties().copied().collect())
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.current = start.committee();
        self.history = committee.quorum_size().get() as u64;
        self.next_committee = NextCommittee::Del(start);
        Ok(())
    }

    async fn remove_old_committee(&mut self) -> Result<()> {
        let NextCommittee::Del(round) = self.next_committee else {
            return Ok(());
        };
        let Some(block) = self.oldest_block() else {
            return Ok(());
        };
        if block.round() <= round.num() {
            return Ok(());
        }
        let Some(committee) = self.committees.get(self.current) else {
            error!(node = %self.label, committee = %self.current, "current committee not found");
            return Err(CertifierError::NoCommittee(self.current));
        };
        let old = self
            .net
            .parties()
            .map(|(p, _)| p)
            .filter(|p| !committee.contains_key(p))
            .copied()
            .collect::<Vec<_>>();
        for party in &old {
            self.known.remove(party);
        }
        self.net
            .remove(old)
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.next_committee = NextCommittee::None;
        Ok(())
    }

    /// Check if this node is leader of the given block.
    fn is_leader(&self, i: &BlockInfo) -> bool {
        let Some(c) = self.committees.get(i.round().committee()) else {
            error!(node = %self.label, round = %i.round(), "can not determine leader");
            return false;
        };
        self.label == c.leader(*i.num() as usize)
    }

    fn oldest_block(&self) -> Option<&Block> {
        self.tracking
            .first_key_value()?
            .1
            .trackers
            .values()
            .find_map(|t| t.block.as_ref())
    }
}

impl Tracker {
    async fn deliver(&self, leader: bool, tx: &Sender<CertifiedBlock<Validated>>) -> Result<bool> {
        if let Some(cert) = self.votes.certificate() {
            if let Some(block) = &self.block {
                let cb = CertifiedBlock::v1(cert.clone(), block.clone(), leader);
                tx.send(cb).await.map_err(|_| EndOfPlay::CertifierDown)?;
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// The certify message broadcasted to every block signer.
#[derive(Encode, Decode)]
struct Message<S> {
    #[cbor(n(0))]
    info: Envelope<BlockInfo, S>,

    #[cbor(n(1))]
    next: BlockNumber,

    #[cbor(n(2))]
    evidence: Option<Evidence>,
}

#[derive(Debug, thiserror::Error)]
#[error("block certifier down")]
pub struct CertifierDown(());

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CertifierError {
    #[error("network error: {0}")]
    Net(#[from] NetworkError),

    #[error("terminal error: {0}")]
    End(#[from] EndOfPlay),

    #[error("encode error: {0}")]
    Encode(#[from] minicbor::encode::Error<Infallible>),

    #[error("decode error: {0}")]
    Decode(#[from] minicbor::decode::Error),

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
    #[error("block certifier down")]
    CertifierDown,
}

impl From<NetworkDown> for EndOfPlay {
    fn from(_: NetworkDown) -> Self {
        Self::NetworkDown
    }
}

/// Evidence to include in certify messages.
#[derive(Encode, Decode)]
struct Evidence(#[n(0)] Certificate<BlockInfo>);

impl Evidence {
    fn num(&self) -> BlockNumber {
        self.0.data().num()
    }

    fn is_valid(&self, i: &BlockInfo, v: &CommitteeVec<2>) -> bool {
        let Some(c) = v.get(i.round().committee()) else {
            return false;
        };
        let t = c.one_honest_threshold();
        self.0.data().num() + 1 == i.num() && self.0.is_valid_with_threshold_par(c, t)
    }
}

impl Committable for Evidence {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("CertifierEvidence")
            .field("cert", self.0.commit())
            .finalize()
    }
}

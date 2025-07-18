mod config;
mod decrypt;
mod include;
mod metrics;
mod queue;
mod sort;

use std::collections::VecDeque;
use std::sync::Arc;

use cliquenet::MAX_MESSAGE_SIZE;
use cliquenet::{AddressableCommittee, Network, NetworkError, NetworkMetrics, Overlay};
use metrics::SequencerMetrics;
use multisig::{Keypair, PublicKey};
use sailfish::consensus::{Consensus, ConsensusMetrics};
use sailfish::rbc::{Rbc, RbcError, RbcMetrics};
use sailfish::types::{Action, ConsensusTime, Evidence, Round, RoundNumber};
use sailfish::{Coordinator, Event};
use timeboost_types::{BundleVariant, Timestamp, Transaction};
use timeboost_types::{CandidateList, CandidateListBytes, InclusionList};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{JoinHandle, spawn};
use tracing::{error, info, warn};

use decrypt::{Decrypter, DecrypterError};
use include::Includer;
use queue::BundleQueue;
use sort::Sorter;

pub use config::{SequencerConfig, SequencerConfigBuilder};

type Result<T> = std::result::Result<T, TimeboostError>;
type Candidates = VecDeque<(RoundNumber, Evidence, Vec<CandidateList>)>;

#[derive(Debug)]
pub enum Output {
    Transactions {
        round: RoundNumber,
        timestamp: Timestamp,
        transactions: Vec<Transaction>,
    },
    UseCommittee(Round),
}

pub struct Sequencer {
    label: PublicKey,
    task: JoinHandle<Result<()>>,
    bundles: BundleQueue,
    commands: Sender<Command>,
    output: Receiver<Output>,
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.task.abort()
    }
}

struct Task {
    kpair: Keypair,
    label: PublicKey,
    bundles: BundleQueue,
    sailfish: Coordinator<CandidateListBytes, Rbc<CandidateListBytes>>,
    includer: Includer,
    decrypter: Decrypter,
    sorter: Sorter,
    commands: Receiver<Command>,
    output: Sender<Output>,
    mode: Mode,
}

enum Command {
    NextCommittee(ConsensusTime, AddressableCommittee, BundleQueue),
}

/// Mode of operation.
#[derive(Debug, Copy, Clone)]
enum Mode {
    /// The sequencer will not produce transactions.
    Passive,
    /// The sequencer will produce transactions.
    Active,
}

impl Mode {
    fn is_passive(self) -> bool {
        matches!(self, Self::Passive)
    }
}

impl Sequencer {
    pub async fn new<M>(cfg: SequencerConfig, metrics: &M) -> Result<Self>
    where
        M: ::metrics::Metrics,
    {
        let cons_metrics = ConsensusMetrics::new(metrics);
        let rbc_metrics = RbcMetrics::new(metrics);
        let seq_metrics = Arc::new(SequencerMetrics::new(metrics));

        let public_key = cfg.sign_keypair.public_key();

        let queue = BundleQueue::new(
            cfg.priority_addr,
            cfg.delayed_inbox_index,
            seq_metrics.clone(),
        );

        // Limit max. size of candidate list. Leave margin of 128 KiB for overhead.
        queue.set_max_data_len(cliquenet::MAX_MESSAGE_SIZE - 128 * 1024);

        let sailfish = {
            let met = NetworkMetrics::new(
                "sailfish",
                metrics,
                cfg.sailfish_committee.parties().copied(),
            );

            let mut net = Network::create(
                "sailfish",
                cfg.sailfish_addr.clone(),
                cfg.sign_keypair.public_key(),
                cfg.dh_keypair.clone(),
                cfg.sailfish_committee.entries(),
                met,
            )
            .await?;

            if let Some(prev) = &cfg.previous_sailfish_committee {
                // Add peers from the previous committee which are not members of
                // the current one for a proper handover.
                let old = prev.diff(&cfg.sailfish_committee);
                net.add(old.collect()).await?
            }

            let rbc = Rbc::new(
                5 * cfg.sailfish_committee.committee().size().get(),
                Overlay::new(net),
                cfg.rbc_config().with_metrics(rbc_metrics),
            );

            let mut cons = Consensus::new(
                cfg.sign_keypair.clone(),
                cfg.sailfish_committee.committee().clone(),
                queue.clone(),
            )
            .with_metrics(cons_metrics);

            if let Some(prev) = &cfg.previous_sailfish_committee {
                // Inform consensus about the previous committee.
                cons.set_handover_committee(prev.committee().clone())
            }

            Coordinator::new(rbc, cons, cfg.previous_sailfish_committee.is_some())
        };

        let decrypter = Decrypter::new(cfg.decrypter_config(), metrics).await?;

        let (tx, rx) = mpsc::channel(1024);
        let (cx, cr) = mpsc::channel(4);

        let task = Task {
            kpair: cfg.sign_keypair,
            label: public_key,
            bundles: queue.clone(),
            sailfish,
            includer: Includer::new(
                cfg.sailfish_committee.committee().clone(),
                cfg.delayed_inbox_index,
            ),
            decrypter,
            sorter: Sorter::new(public_key),
            output: tx,
            commands: cr,
            mode: Mode::Passive,
        };

        Ok(Self {
            label: public_key,
            task: spawn(task.go()),
            bundles: queue,
            output: rx,
            commands: cx,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.label
    }

    pub fn add_bundles<I>(&mut self, it: I)
    where
        I: IntoIterator<Item = BundleVariant>,
    {
        self.bundles.add_bundles(it)
    }

    pub async fn next(&mut self) -> Result<Output> {
        select! {
            txs = self.output.recv() => txs.ok_or(TimeboostError::ChannelClosed),
            res = &mut self.task => match res {
                Ok(Ok(())) => {
                    error!(node = %self.label, "unexpected task termination");
                    Err(TimeboostError::TaskTerminated)
                }
                Ok(Err(err)) => {
                    error!(node = %self.label, %err, "task error");
                    Err(err)
                }
                Err(err) => {
                    error!(node = %self.label, %err, "task panic");
                    Err(TimeboostError::TaskTerminated)
                }
            }
        }
    }

    pub async fn set_next_committee(
        &mut self,
        t: ConsensusTime,
        a: AddressableCommittee,
    ) -> Result<()> {
        self.commands
            .send(Command::NextCommittee(t, a, self.bundles.clone()))
            .await
            .map_err(|_| TimeboostError::ChannelClosed)
    }
}

impl Task {
    /// Run sequencing logic.
    // Processing takes place as follows:
    //
    // 1. Sailfish actions are executed and outputs collected in round-indexed sequences of
    //    candidate lists.
    // 2. Candidates are handed to the inclusion phase and produce the next inclusion list.
    // 3. If the decrypter has capacity the inclusion list is passed on and processing continues
    //    with the next candidates.
    // 4. Otherwise we buffer the inclusion list and pause Sailfish execution.
    // 5. When the decrypter produces outputs we hand it to the ordering phase and if it then has
    //    capacity we resume with the buffered inclusion list from (4) and process the remaining
    //    candidates.
    // 6. The logic continues at step (1).
    //
    // NB that if Sailfish does not produce outputs (i.e. candidate lists)
    // processing its actions continues unhindered.
    async fn go(mut self) -> Result<()> {
        let mut pending = None;
        let mut candidates = Candidates::new();

        if !self.sailfish.is_init() {
            let actions = self.sailfish.init();
            candidates = self.execute(actions).await?;
        }

        loop {
            if pending.is_none() {
                while let Some(ilist) = self.next_inclusion(&mut candidates) {
                    if !self.decrypter.has_capacity() {
                        pending = Some(ilist);
                        break;
                    }
                    if let Err(err) = self.decrypter.enqueue(ilist).await {
                        error!(node = %self.label, %err, "decrypt enqueue error");
                    }
                }
            }
            select! {
                result = self.sailfish.next(), if pending.is_none() => match result {
                    Ok(actions) => {
                        debug_assert!(candidates.is_empty());
                        candidates = self.execute(actions).await?
                    },
                    Err(err) => {
                        error!(node = %self.label, %err, "coordinator error");
                    },
                },
                result = self.decrypter.next() => match result {
                    Ok(incl) => {
                        let round = incl.round();
                        let timestamp = incl.timestamp();
                        let transactions = self.sorter.sort(incl);
                        if !transactions.is_empty() {
                            let out = Output::Transactions { round, timestamp, transactions };
                            self.output.send(out).await.map_err(|_| TimeboostError::ChannelClosed)?;
                        }
                        if self.decrypter.has_capacity() {
                            let Some(ilist) = pending.take() else {
                                continue
                            };
                            if let Err(err) = self.decrypter.enqueue(ilist).await {
                                error!(node = %self.label, %err, "decrypt enqueue error");
                            }
                        }
                    }
                    Err(err) => {
                        error!(node = %self.label, %err);
                    }
                },
                cmd = self.commands.recv(), if pending.is_none() => match cmd {
                    Some(Command::NextCommittee(t, a, b)) => {
                        self.sailfish.set_next_committee(t, a.committee().clone(), a.clone()).await?;
                        if a.committee().contains_key(&self.kpair.public_key()) {
                            let cons = Consensus::new(self.kpair.clone(), a.committee().clone(), b);
                            let acts = self.sailfish.set_next_consensus(cons);
                            candidates = self.execute(acts).await?
                        }
                        if let Err(err) = self.decrypter.next_committee(a).await {
                            error!(node = %self.label, %err, "decrypt next committee error");
                        }
                    }
                    None => {
                        return Err(TimeboostError::ChannelClosed)
                    }
                }
            }
        }
    }

    /// Execute Sailfish actions and collect candidate lists.
    async fn execute(&mut self, actions: Vec<Action<CandidateListBytes>>) -> Result<Candidates> {
        let mut actions = VecDeque::from(actions);
        let mut candidates = Vec::new();
        while !actions.is_empty() {
            let mut round = RoundNumber::genesis();
            let mut evidence = Evidence::Genesis;
            let mut lists = Vec::new();
            while let Some(action) = actions.pop_front() {
                if let Action::Deliver(payload) = action {
                    match payload.data().decode::<MAX_MESSAGE_SIZE>() {
                        Ok(data) => {
                            round = payload.round().num();
                            evidence = payload.into_evidence();
                            lists.push(data)
                        }
                        Err(err) => {
                            warn!(
                                node = %self.label,
                                err  = %err,
                                src  = %payload.source(),
                                "failed to deserialize candidate list"
                            );
                        }
                    }
                } else {
                    actions.push_front(action);
                    break;
                }
            }
            if !lists.is_empty() {
                candidates.push((round, evidence, lists))
            }
            while let Some(action) = actions.pop_front() {
                if action.is_deliver() {
                    actions.push_front(action);
                    break;
                }
                match self.sailfish.execute(action).await {
                    Ok(Some(Event::Gc(r))) => {
                        if let Err(err) = self.decrypter.gc(r.num()).await {
                            warn!(node = %self.label, %err, "decrypt gc error");
                        }
                    }
                    Ok(Some(Event::Catchup(_))) => {
                        self.includer.clear_cache();
                    }
                    Ok(Some(Event::UseCommittee(r))) => {
                        if let Some(cons) = self.sailfish.consensus(r.committee()) {
                            let c = cons.committee().clone();
                            self.includer.set_next_committee(r.num(), c);
                            if let Err(err) = self.decrypter.use_committee(r).await {
                                error!(node = %self.label, %err, "decrypt use committee error");
                            }
                            self.output
                                .send(Output::UseCommittee(r))
                                .await
                                .map_err(|_| TimeboostError::ChannelClosed)?;
                        } else {
                            warn!(node = %self.label, id = %r.committee(), "committee not found");
                        }
                    }
                    Ok(Some(Event::Deliver(_)) | None) => {}
                    Err(err) => {
                        error!(node = %self.label, %err, "coordinator error");
                        return Err(err.into());
                    }
                }
            }
        }
        Ok(candidates.into())
    }

    /// Handle candidate lists and return the next inclusion list.
    fn next_inclusion(&mut self, candidates: &mut Candidates) -> Option<InclusionList> {
        while let Some((round, evidence, lists)) = candidates.pop_front() {
            let outcome = self.includer.inclusion_list(round, evidence, lists);
            self.bundles.update_bundles(&outcome.ilist, outcome.retry);
            if !outcome.is_valid {
                self.mode = Mode::Passive;
                self.bundles.set_mode(self.mode);
                info!(node = %self.label, %round, "passive mode");
                continue;
            }
            if self.mode.is_passive() {
                info!(node = %self.label, %round, "entering active mode");
                self.mode = Mode::Active;
                self.bundles.set_mode(self.mode);
            }
            return Some(outcome.ilist);
        }
        None
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TimeboostError {
    #[error("network error: {0}")]
    Net(#[from] NetworkError),

    #[error("rbc error: {0}")]
    Rbc(#[from] RbcError),

    #[error("channel closed")]
    ChannelClosed,

    #[error("task terminated")]
    TaskTerminated,

    #[error("decrypt error: {0}")]
    Decrypt(#[from] DecrypterError),
}

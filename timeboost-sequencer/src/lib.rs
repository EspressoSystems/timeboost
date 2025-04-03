mod decrypt;
mod include;
mod metrics;
mod queue;
mod sort;

use std::collections::VecDeque;
use std::sync::Arc;

use cliquenet as net;
use cliquenet::{Network, NetworkError, NetworkMetrics};
use metrics::SequencerMetrics;
use multisig::{Committee, Keypair, PublicKey};
use sailfish::Coordinator;
use sailfish::consensus::{Consensus, ConsensusMetrics};
use sailfish::rbc::{Rbc, RbcConfig, RbcError, RbcMetrics};
use sailfish::types::{Action, RoundNumber};
use timeboost_crypto::Keyset;
use timeboost_types::{Address, BundleVariant, DecryptionKey, Transaction};
use timeboost_types::{CandidateList, DelayedInboxIndex};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{JoinHandle, spawn};
use tracing::{debug, error, info};

use decrypt::{DecryptError, Decrypter};
use include::Includer;
use queue::BundleQueue;
use sort::Sorter;

type Result<T> = std::result::Result<T, TimeboostError>;

#[derive(Debug)]
pub struct SequencerConfig {
    priority_addr: Address,
    keypair: Keypair,
    peers: Vec<(PublicKey, net::Address)>,
    bind: net::Address,
    index: DelayedInboxIndex,
    dec_sk: DecryptionKey,
}

impl SequencerConfig {
    pub fn new<A>(keyp: Keypair, dec_sk: DecryptionKey, bind: A) -> Self
    where
        A: Into<net::Address>,
    {
        Self {
            priority_addr: Address::default(),
            keypair: keyp,
            peers: Vec::new(),
            bind: bind.into(),
            index: DelayedInboxIndex::default(),
            dec_sk,
        }
    }

    pub fn with_priority_addr(mut self, a: Address) -> Self {
        self.priority_addr = a;
        self
    }

    pub fn with_peers<I, A>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (PublicKey, A)>,
        A: Into<net::Address>,
    {
        self.peers = it.into_iter().map(|(k, a)| (k, a.into())).collect();
        self
    }

    pub fn with_delayed_inbox_index(mut self, i: DelayedInboxIndex) -> Self {
        self.index = i;
        self
    }
}

pub struct Sequencer {
    label: PublicKey,
    task: JoinHandle<Result<()>>,
    bundles: BundleQueue,
    output: Receiver<Transaction>,
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.task.abort()
    }
}

struct Task {
    label: PublicKey,
    bundles: BundleQueue,
    sailfish: Coordinator<CandidateList, Rbc<CandidateList>>,
    includer: Includer,
    decrypter: Decrypter,
    sorter: Sorter,
    output: Sender<Transaction>,
    mode: Mode,
    round: RoundNumber,
    actions: VecDeque<Action<CandidateList>>,
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
    fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

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
        let net_metrics = NetworkMetrics::new(metrics, cfg.peers.iter().map(|(k, _)| *k));
        let seq_metrics = Arc::new(SequencerMetrics::new(metrics));

        let committee = Committee::new(
            cfg.peers
                .iter()
                .map(|(k, _)| *k)
                .enumerate()
                .map(|(i, key)| (i as u8, key)),
        );

        let network = Network::create(
            cfg.bind.clone(),
            cfg.keypair.clone(),
            cfg.peers.clone(),
            net_metrics,
        )
        .await?;

        let rcf = RbcConfig::new(cfg.keypair.clone(), committee.clone());
        let rbc = Rbc::new(network, rcf.with_metrics(rbc_metrics));

        let label = cfg.keypair.public_key();

        let queue = BundleQueue::new(cfg.priority_addr, cfg.index, seq_metrics.clone());
        let consensus = Consensus::new(cfg.keypair.clone(), committee.clone(), queue.clone())
            .with_metrics(cons_metrics);

        let keyset = Keyset::new(1, committee.size());

        let peers: Vec<_> = cfg
            .peers
            .iter()
            .map(|(k, a)| (*k, a.clone().with_port(a.port() + 250)))
            .collect();

        let addr = {
            let p = cfg.bind.port() + 250;
            cfg.bind.with_port(p)
        };

        let network = Network::create(
            addr,
            cfg.keypair.clone(), // same auth
            peers,
            NetworkMetrics::default(),
        )
        .await?;

        let (tx, rx) = mpsc::channel(1024);

        let task = Task {
            label,
            bundles: queue.clone(),
            sailfish: Coordinator::new(rbc, consensus),
            includer: Includer::new(committee, cfg.index),
            decrypter: Decrypter::new(cfg.keypair.public_key(), network, keyset, cfg.dec_sk),
            sorter: Sorter::new(),
            output: tx,
            round: RoundNumber::genesis(),
            mode: Mode::Passive,
            actions: VecDeque::new(),
        };

        Ok(Self {
            label,
            task: spawn(task.go()),
            bundles: queue,
            output: rx,
        })
    }

    pub fn add_bundles<I>(&mut self, it: I)
    where
        I: IntoIterator<Item = BundleVariant>,
    {
        self.bundles.add_bundles(it)
    }

    pub async fn next_transaction(&mut self) -> Result<Transaction> {
        select! {
            trx = self.output.recv() => trx.ok_or(TimeboostError::ChannelClosed),
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
}

impl Task {
    async fn go(mut self) -> Result<()> {
        self.actions = self.sailfish.init().into();
        self.execute().await?;

        loop {
            select! {
                result = self.sailfish.next(), if self.actions.is_empty() => {
                    match result {
                        Ok(a) => {
                            self.actions = a.into();
                            self.execute().await?;
                        },
                        Err(err) => {
                            error!(node = %self.label, %err, "coordinator error");
                        }
                    }
                },
                result = self.decrypter.next() => match result {
                    Ok(incl) => {
                        self.round = incl.round();
                        for t in self.sorter.sort(incl) {
                            self.output.send(t).await.map_err(|_| TimeboostError::ChannelClosed)?
                        }
                        self.execute().await?
                    }
                    Err(err) => {
                        error!(node = %self.label, %err, "decrypt error");
                    }
                }
            }
        }
    }

    async fn execute(&mut self) -> Result<()> {
        let mut lists = Vec::new();

        'outer: while !self.actions.is_empty() {
            // Collect all consecutive deliveries:
            let mut round = RoundNumber::genesis();
            let mut candidates = Vec::new();
            while let Some(action) = self.actions.pop_front() {
                if let Action::Deliver(payload) = action {
                    round = payload.round();
                    candidates.push(payload.into_data())
                } else {
                    self.actions.push_front(action);
                    break;
                }
            }

            // At this point no more deliveries are expected.
            debug_assert!(!matches!(self.actions.front(), Some(&Action::Deliver(_))));

            // Associate the candidate lists delivered with their highest round
            // number. (There may be multiple round numbers in a consecutive
            // delivery sequence because late arrivals may be delivered in front
            // of the next DAG frontier)
            if !candidates.is_empty() {
                lists.push((round, candidates))
            }

            // Execute all actions up to the next delivery sequence.
            while let Some(action) = self.actions.pop_front() {
                match action {
                    // Next delivery sequence starts => stop execution
                    Action::Deliver(_) => {
                        self.actions.push_front(action);
                        break;
                    }
                    // Unless we passively observe, stop execution if
                    // garbage collection goes past our latest processed round.
                    Action::Gc(r) if self.mode.is_active() && self.round < r => {
                        self.actions.push_front(action);
                        debug!(node = %self.label, round = %r, "gc cutoff reached");
                        break 'outer;
                    }
                    _ => {
                        if let Err(err) = self.sailfish.execute(action).await {
                            error!(node = %self.label, %err, "coordinator error");
                            return Err(err.into());
                        }
                    }
                }
            }
        }

        // Submit the collected candidate lists to the next phases.
        for (round, candidates) in lists {
            let outcome = self.includer.inclusion_list(round, candidates);
            self.bundles.update_bundles(&outcome.ilist, outcome.retry);
            if !outcome.is_valid {
                self.mode = Mode::Passive;
                info!(node = %self.label, %round, "passive mode");
                continue;
            } else {
                if self.mode.is_passive() {
                    info!(node = %self.label, %round, "entering active mode");
                }
                self.mode = Mode::Active;
            }
            if let Err(err) = self.decrypter.enqueue(outcome.ilist).await {
                error!(node = %self.label, %err, "decrypt enqueue error");
            }
        }

        Ok(())
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
    Decrypt(#[from] DecryptError),
}

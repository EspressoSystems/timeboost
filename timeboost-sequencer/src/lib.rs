mod decrypt;
mod include;
mod queue;
mod sort;

use std::collections::{BTreeMap, VecDeque};

use cliquenet as net;
use cliquenet::{Network, NetworkError, NetworkMetrics};
use metrics::Metrics;
use multisig::{Committee, Keypair, PublicKey};
use sailfish::consensus::{Consensus, ConsensusMetrics};
use sailfish::rbc::{Rbc, RbcConfig, RbcError, RbcMetrics};
use sailfish::types::{Action, RoundNumber};
use sailfish::Coordinator;
use timeboost_types::{Address, Transaction};
use timeboost_types::{CandidateList, DelayedInboxIndex};
use tokio::select;
use tracing::{error, trace, Level};

use decrypt::Decrypter;
use include::Includer;
use queue::TransactionQueue;
use sort::Sorter;

type Result<T> = std::result::Result<T, TimeboostError>;

#[derive(Debug)]
pub struct SequencerConfig {
    priority_addr: Address,
    keypair: Keypair,
    peers: Vec<(PublicKey, net::Address)>,
    bind: net::Address,
    index: DelayedInboxIndex,
}

impl SequencerConfig {
    pub fn new<A>(keyp: Keypair, bind: A) -> Self
    where
        A: Into<net::Address>,
    {
        Self {
            priority_addr: Address::zero(),
            keypair: keyp,
            peers: Vec::new(),
            bind: bind.into(),
            index: DelayedInboxIndex::default(),
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
    transactions: TransactionQueue,
    sailfish: Coordinator<CandidateList, Rbc<CandidateList>>,
    includer: Includer,
    decrypter: Decrypter,
    sorter: Sorter,
    output: VecDeque<Transaction>,
}

impl Sequencer {
    pub async fn new<M: Metrics>(cfg: SequencerConfig, metrics: &M) -> Result<Self> {
        let cons_metrics = ConsensusMetrics::new(metrics);
        let rbc_metrics = RbcMetrics::new(metrics);
        let net_metrics = NetworkMetrics::new(metrics, cfg.peers.iter().map(|(k, _)| *k));

        let committee = Committee::new(
            cfg.peers
                .iter()
                .map(|(k, _)| *k)
                .enumerate()
                .map(|(i, key)| (i as u8, key)),
        );

        let network =
            Network::create(cfg.bind, cfg.keypair.clone(), cfg.peers, net_metrics).await?;

        let rcf = RbcConfig::new(cfg.keypair.clone(), committee.clone());
        let rbc = Rbc::new(network, rcf.with_metrics(rbc_metrics));

        let label = cfg.keypair.public_key();

        let queue = TransactionQueue::new(cfg.priority_addr, cfg.index);
        let consensus = Consensus::new(cfg.keypair, committee.clone(), queue.clone())
            .with_metrics(cons_metrics);
        let coordinator = Coordinator::new(rbc, consensus);

        let includer = Includer::new(committee, cfg.index);
        let decrypter = Decrypter::new();
        let sorter = Sorter::new();

        Ok(Self {
            label,
            transactions: queue,
            sailfish: coordinator,
            includer,
            decrypter,
            sorter,
            output: VecDeque::new(),
        })
    }

    pub fn add_transactions<I>(&mut self, it: I)
    where
        I: IntoIterator<Item = Transaction>,
    {
        if tracing::enabled!(Level::TRACE) {
            let (b, t) = self.transactions.len();
            trace!(
                node = %self.label,
                bundles = %b,
                transactions = %t,
                "adding transactions to queue"
            );
        }

        self.transactions.add_transactions(it)
    }

    pub async fn next_transaction(&mut self) -> Result<Transaction> {
        if !self.sailfish.is_init() {
            for a in self.sailfish.init() {
                debug_assert!(!matches!(a, Action::Deliver(_)));
                self.sailfish.execute(a).await?
            }
        }
        loop {
            if let Some(t) = self.output.pop_front() {
                trace!(node = %self.label, transaction = %t.digest());
                return Ok(t);
            }
            select! {
                result = self.sailfish.next() => match result {
                    Ok(actions) => {
                        let mut payloads: BTreeMap<RoundNumber, Vec<CandidateList>> = BTreeMap::new();
                        for a in actions {
                            if let Action::Deliver(data) = a {
                                payloads.entry(data.round()).or_default().push(data.into_data());
                            } else if let Err(e) = self.sailfish.execute(a).await {
                                error!(node = %self.label, "coordinator error: {}", e);
                                return Err(e.into())
                            }
                        }
                        let mut inclusions = Vec::new();
                        for (round, lists) in payloads {
                            let (i, r) = self.includer.inclusion_list(round, lists);
                            self.transactions.update_transactions(&i, r);
                            inclusions.push(i)
                        }
                        self.decrypter.enqueue(inclusions)
                    },
                    Err(e) => {
                        error!(node = %self.label, "coordinator error: {}", e);
                    },
                },
                result = self.decrypter.next() => match result {
                    Ok(incl) => {
                        for t in self.sorter.sort(incl) {
                            self.output.push_back(t)
                        }
                    }
                    Err(e) => {
                        error!(node = %self.label, "decrypter error: {}", e);
                    }
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TimeboostError {
    #[error("network error: {0}")]
    Net(#[from] NetworkError),

    #[error("network error: {0}")]
    Rbc(#[from] RbcError),
}

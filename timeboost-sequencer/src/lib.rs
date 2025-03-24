mod decrypt;
mod include;
mod queue;
mod sort;

use std::collections::BTreeMap;

use cliquenet as net;
use cliquenet::{Network, NetworkError, NetworkMetrics};
use metrics::Metrics;
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
use tracing::{Level, error, trace};

use decrypt::{DecryptError, Decrypter};
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
    dec_sk: DecryptionKey,
}

impl SequencerConfig {
    pub fn new<A>(keyp: Keypair, dec_sk: DecryptionKey, bind: A) -> Self
    where
        A: Into<net::Address>,
    {
        Self {
            priority_addr: Address::zero(),
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
    transactions: TransactionQueue,
    output: Receiver<Transaction>,
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.task.abort()
    }
}

struct Task {
    label: PublicKey,
    transactions: TransactionQueue,
    sailfish: Coordinator<CandidateList, Rbc<CandidateList>>,
    includer: Includer,
    decrypter: Decrypter,
    sorter: Sorter,
    output: Sender<Transaction>,
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

        let queue = TransactionQueue::new(cfg.priority_addr, cfg.index);
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
            transactions: queue.clone(),
            sailfish: Coordinator::new(rbc, consensus),
            includer: Includer::new(committee, cfg.index),
            decrypter: Decrypter::new(cfg.keypair.public_key(), network, keyset, cfg.dec_sk),
            sorter: Sorter::new(),
            output: tx,
        };

        Ok(Self {
            label,
            task: spawn(task.go()),
            transactions: queue,
            output: rx,
        })
    }

    pub fn add_transactions<I>(&mut self, it: I)
    where
        I: IntoIterator<Item = BundleVariant>,
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

        self.transactions.add_bundles(it)
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
        if !self.sailfish.is_init() {
            for a in self.sailfish.init() {
                debug_assert!(!matches!(a, Action::Deliver(_)));
                self.sailfish.execute(a).await?
            }
        }
        loop {
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
                        if let Err(e) = self.decrypter.enqueue(inclusions).await {
                            error!("decrypt enqueue error: {}", e);
                        }
                    },
                    Err(e) => {
                        error!(node = %self.label, "coordinator error: {}", e);
                    },
                },
                result = self.decrypter.next() => match result {
                    Ok(incl) => {
                        for t in self.sorter.sort(incl) {
                            self.output.send(t).await.map_err(|_| TimeboostError::ChannelClosed)?
                        }
                    }
                    Err(err) => {
                        error!(node = %self.label, %err);
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

    #[error("rbc error: {0}")]
    Rbc(#[from] RbcError),

    #[error("channel closed")]
    ChannelClosed,

    #[error("task terminated")]
    TaskTerminated,

    #[error("decrypt error: {0}")]
    Decrypt(#[from] DecryptError),
}

mod decrypt;
mod include;
mod queue;
mod sort;

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use cliquenet as net;
use cliquenet::{Network, NetworkError, NetworkMetrics};
use multisig::{Committee, Keypair, PublicKey};
use sailfish::consensus::{Consensus, ConsensusMetrics};
use sailfish::rbc::{Rbc, RbcConfig, RbcError, RbcMetrics};
use sailfish::types::{Action, RoundNumber};
use sailfish::Coordinator;
use timeboost_types::{Address, Epoch, Transaction};
use timeboost_types::{CandidateList, DelayedInboxIndex};
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::select;
use tracing::error;

use decrypt::Decrypter;
use include::Includer;
use queue::TransactionsQueue;
use sort::Sorter;

type Result<T> = std::result::Result<T, TimeboostError>;

#[derive(Debug)]
pub struct SequencerConfig {
    priority_addr: Address,
    keypair: Keypair,
    peers: Vec<(PublicKey, net::Address)>,
    bind: SocketAddr,
    index: DelayedInboxIndex,
}

pub struct Sequencer {
    epoch: Epoch,
    transactions: TransactionsQueue,
    sailfish: Coordinator<CandidateList, Rbc<CandidateList>>,
    includer: Includer,
    decrypter: Decrypter,
    sorter: Sorter,
    output: VecDeque<Transaction>,
}

impl Sequencer {
    pub async fn new(cfg: SequencerConfig) -> Result<Self> {
        let prom = Arc::new(PrometheusMetrics::default());
        let cons_metrics = ConsensusMetrics::new(prom.as_ref());
        let rbc_metrics = RbcMetrics::new(prom.as_ref());
        let net_metrics = NetworkMetrics::new(prom.as_ref(), cfg.peers.iter().map(|(k, _)| *k));

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

        let queue = TransactionsQueue::new(cfg.priority_addr, Epoch::default(), cfg.index);
        let consensus = Consensus::new(cfg.keypair, committee.clone(), queue.clone())
            .with_metrics(cons_metrics);
        let coordinator = Coordinator::new(rbc, consensus);

        let includer = Includer::new(committee, cfg.index);
        let decrypter = Decrypter::new();
        let sorter = Sorter::new();

        Ok(Self {
            epoch: Epoch::default(),
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
                                error!("coordinator error: {}", e);
                                return Err(e.into())
                            }
                        }
                        let mut inclusions = Vec::new();
                        for (round, lists) in payloads {
                            let i = self.includer.inclusion_list(round, lists);
                            inclusions.push(i)
                        }
                        let index = self.includer.delayed_inbox_index();
                        self.transactions.set_delayed_inbox_index(index);
                        let epoch = self.includer.epoch();
                        if self.epoch != epoch {
                            self.epoch = epoch;
                            self.transactions.advance_to_epoch(epoch)
                        }
                        self.decrypter.enqueue(inclusions)
                    },
                    Err(e) => {
                        error!("coordinator error: {}", e);
                    },
                },
                result = self.decrypter.next() => match result {
                    Ok(incl) => {
                        for t in self.sorter.sort(incl) {
                            self.output.push_back(t)
                        }
                    }
                    Err(e) => {
                        error!("decrypter error: {}", e);
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

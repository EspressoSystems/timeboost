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
use timeboost_types::{Address, CandidateList, DelayedInboxIndex};
use timeboost_types::{DecryptionKey, Transaction};
use timeboost_utils::dec_addr;
use timeboost_utils::types::prometheus::PrometheusMetrics;
use tokio::select;
use tracing::error;

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
    bind: SocketAddr,
    index: DelayedInboxIndex,
    dec_sk: DecryptionKey,
}

pub struct Sequencer {
    transactions: TransactionQueue,
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

        let cons_keyset = Committee::new(
            cfg.peers
                .iter()
                .map(|(k, _)| *k)
                .enumerate()
                .map(|(i, key)| (i as u8, key)),
        );

        let cons_net = Network::create(
            cfg.bind,
            cfg.keypair.clone(),
            cfg.peers.clone(),
            net_metrics,
        )
        .await?;

        let rcf = RbcConfig::new(cfg.keypair.clone(), cons_keyset.clone());
        let rbc = Rbc::new(cons_net, rcf.with_metrics(rbc_metrics));

        let queue = TransactionQueue::new(cfg.priority_addr, cfg.index);
        let consensus = Consensus::new(cfg.keypair.clone(), cons_keyset.clone(), queue.clone())
            .with_metrics(cons_metrics);
        let coordinator = Coordinator::new(rbc, consensus);

        let dec_keyset = timeboost_crypto::Keyset::new(1, cons_keyset.size().get() as u16);
        let dec_peers: Vec<_> = cfg.peers.iter().map(|(k, a)| (*k, dec_addr(a))).collect();
        let dec_addr = dec_addr(&net::Address::from(cfg.bind));
        let dec_net = Network::create(
            dec_addr,
            cfg.keypair, // same auth
            dec_peers,
            NetworkMetrics::default(),
        )
        .await?;

        let includer = Includer::new(cons_keyset.clone(), cfg.index);
        let decrypter = Decrypter::new(dec_net, dec_keyset, cfg.dec_sk);
        let sorter = Sorter::new();

        Ok(Self {
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
                            let (i, r) = self.includer.inclusion_list(round, lists);
                            self.transactions.update_transactions(&i, r);
                            inclusions.push(i)
                        }
                        self.decrypter.enqueue(inclusions).await;
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

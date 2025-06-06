mod decrypt;
mod include;
mod metrics;
mod queue;
mod sort;

use std::collections::VecDeque;
use std::sync::Arc;

use cliquenet::{self as net, MAX_MESSAGE_SIZE};
use cliquenet::{Network, NetworkError, NetworkMetrics, Overlay};
use metrics::SequencerMetrics;
use multisig::{Committee, Keypair, PublicKey, x25519};
use sailfish::Coordinator;
use sailfish::consensus::{Consensus, ConsensusMetrics};
use sailfish::rbc::{Rbc, RbcConfig, RbcError, RbcMetrics};
use sailfish::types::{Action, Evidence, RoundNumber};
use timeboost_crypto::Keyset;
use timeboost_types::{Address, BundleVariant, DecryptionKey, Transaction};
use timeboost_types::{CandidateList, CandidateListBytes, DelayedInboxIndex, InclusionList};
use tokio::select;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{JoinHandle, spawn};
use tracing::{error, info, warn};

use decrypt::{DecryptError, Decrypter};
use include::Includer;
use queue::BundleQueue;
use sort::Sorter;

type Result<T> = std::result::Result<T, TimeboostError>;
type Candidates = VecDeque<(RoundNumber, Evidence, Vec<CandidateList>)>;

#[derive(Debug)]
pub struct SequencerConfig {
    priority_addr: Address,
    sign_keypair: Keypair,
    dh_keypair: x25519::Keypair,
    sailfish_peers: Vec<(PublicKey, x25519::PublicKey, net::Address)>,
    sailfish_bind: net::Address,
    decrypt_bind: net::Address,
    decrypt_peers: Vec<(PublicKey, x25519::PublicKey, net::Address)>,
    index: DelayedInboxIndex,
    dec_sk: DecryptionKey,
    recover: bool,
}

impl SequencerConfig {
    pub fn new<A>(
        kp: Keypair,
        xp: x25519::Keypair,
        dec_sk: DecryptionKey,
        sf_bind: A,
        dec_bind: A,
    ) -> Self
    where
        A: Into<net::Address>,
    {
        Self {
            priority_addr: Address::default(),
            sign_keypair: kp,
            dh_keypair: xp,
            sailfish_peers: Vec::new(),
            decrypt_peers: Vec::new(),
            sailfish_bind: sf_bind.into(),
            decrypt_bind: dec_bind.into(),
            index: DelayedInboxIndex::default(),
            dec_sk,
            recover: true,
        }
    }

    pub fn with_priority_addr(mut self, a: Address) -> Self {
        self.priority_addr = a;
        self
    }

    pub fn with_sailfish_peers<I, A>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (PublicKey, x25519::PublicKey, A)>,
        A: Into<net::Address>,
    {
        self.sailfish_peers = it.into_iter().map(|(k, x, a)| (k, x, a.into())).collect();
        self
    }

    pub fn with_decrypt_peers<I, A>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (PublicKey, x25519::PublicKey, A)>,
        A: Into<net::Address>,
    {
        self.decrypt_peers = it.into_iter().map(|(k, x, a)| (k, x, a.into())).collect();
        self
    }

    pub fn with_delayed_inbox_index(mut self, i: DelayedInboxIndex) -> Self {
        self.index = i;
        self
    }

    pub fn recover(mut self, val: bool) -> Self {
        self.recover = val;
        self
    }

    pub fn is_recover(&self) -> bool {
        self.recover
    }
}

pub struct Sequencer {
    label: PublicKey,
    task: JoinHandle<Result<()>>,
    bundles: BundleQueue,
    output: Receiver<Vec<Transaction>>,
}

impl Drop for Sequencer {
    fn drop(&mut self) {
        self.task.abort()
    }
}

struct Task {
    label: PublicKey,
    bundles: BundleQueue,
    sailfish: Coordinator<CandidateListBytes, Rbc<CandidateListBytes>>,
    includer: Includer,
    decrypter: Decrypter,
    sorter: Sorter,
    output: Sender<Vec<Transaction>>,
    mode: Mode,
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

        let committee = Committee::new(
            cfg.sailfish_peers
                .iter()
                .map(|(k, ..)| *k)
                .enumerate()
                .map(|(i, key)| (i as u8, key)),
        );

        let public_key = cfg.sign_keypair.public_key();

        let queue = BundleQueue::new(cfg.priority_addr, cfg.index, seq_metrics.clone());

        // Limit max. size of candidate list. Leave margin of 128 KiB for overhead.
        queue.set_max_data_len(cliquenet::MAX_MESSAGE_SIZE - 128 * 1024);

        let sailfish = {
            let met = NetworkMetrics::new(
                "sailfish",
                metrics,
                cfg.sailfish_peers.iter().map(|(k, ..)| *k),
            );

            let net = Network::create(
                "sailfish",
                cfg.sailfish_bind,
                cfg.sign_keypair.clone(),
                cfg.dh_keypair.clone(),
                cfg.sailfish_peers,
                met,
            )
            .await?;

            let rcf =
                RbcConfig::new(cfg.sign_keypair.clone(), committee.clone()).recover(cfg.recover);
            let rbc = Rbc::new(Overlay::new(net), rcf.with_metrics(rbc_metrics));

            let cons = Consensus::new(cfg.sign_keypair.clone(), committee.clone(), queue.clone())
                .with_metrics(cons_metrics);

            Coordinator::new(rbc, cons)
        };

        let decrypter = {
            let keyset = Keyset::new(1, committee.size());

            let met = NetworkMetrics::new(
                "decrypt",
                metrics,
                cfg.decrypt_peers.iter().map(|(k, ..)| *k),
            );

            let net = Network::create(
                "decrypt",
                cfg.decrypt_bind,
                cfg.sign_keypair.clone(), // same auth
                cfg.dh_keypair.clone(),   // same auth
                cfg.decrypt_peers,
                met,
            )
            .await?;

            Decrypter::new(
                public_key,
                Overlay::new(net),
                committee.clone(),
                keyset,
                cfg.dec_sk,
            )
        };

        let (tx, rx) = mpsc::channel(1024);

        let task = Task {
            label: public_key,
            bundles: queue.clone(),
            sailfish,
            includer: Includer::new(committee, cfg.index),
            decrypter,
            sorter: Sorter::new(public_key),
            output: tx,
            mode: Mode::Passive,
        };

        Ok(Self {
            label: public_key,
            task: spawn(task.go()),
            bundles: queue,
            output: rx,
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

    pub async fn next_transactions(&mut self) -> Result<Vec<Transaction>> {
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
                        let txs = self.sorter.sort(incl);
                        if !txs.is_empty() {
                            self.output.send(txs).await.map_err(|_| TimeboostError::ChannelClosed)?;
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
                match action {
                    Action::Deliver(payload) => match payload.data().decode::<MAX_MESSAGE_SIZE>() {
                        Ok(data) => {
                            round = payload.round();
                            if payload.evidence().round() > evidence.round() {
                                evidence = payload.into_evidence()
                            }
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
                    },
                    Action::Gc(r) => {
                        self.decrypter.gc(r).await?;
                        actions.push_front(action);
                        break;
                    }
                    Action::Catchup(_) => {
                        self.includer.clear_cache();
                    }
                    _ => {
                        actions.push_front(action);
                        break;
                    }
                }
            }
            if !lists.is_empty() {
                candidates.push((round, evidence, lists))
            }
            while let Some(action) = actions.pop_front() {
                match action {
                    Action::Deliver(_) => {
                        actions.push_front(action);
                        break;
                    }
                    Action::Gc(r) => {
                        self.decrypter.gc(r).await?;
                    }
                    Action::Catchup(_) => {
                        self.includer.clear_cache();
                    }
                    _ => {}
                }
                if let Err(err) = self.sailfish.execute(action).await {
                    error!(node = %self.label, %err, "coordinator error");
                    return Err(err.into());
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
    Decrypt(#[from] DecryptError),
}

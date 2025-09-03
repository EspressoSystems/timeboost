use ark_std::{UniformRand, rand::thread_rng};
use bon::Builder;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{
    AddressableCommittee, MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics, Role,
};
use multisig::{CommitteeId, PublicKey};
use parking_lot::RwLock;
use sailfish::types::{Evidence, Round, RoundNumber};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::result::Result as StdResult;
use std::sync::Arc;
use timeboost_crypto::prelude::{LabeledDkgDecKey, Vess, Vss};
use timeboost_crypto::traits::dkg::VerifiableSecretSharing;
use timeboost_crypto::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};
use timeboost_crypto::{DecryptionScheme, Plaintext};
use timeboost_types::{
    AccumulatorMode, DecryptionKey, DecryptionKeyCell, DkgAccumulator, DkgBundle, DkgSubset,
    InclusionList, KeyStore, KeyStoreVec,
};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

use crate::config::DecrypterConfig;
use crate::metrics::SequencerMetrics;

const DKG_AAD: &[u8] = b"dkg";
const THRES_AAD: &[u8] = b"threshold";

type Result<T> = StdResult<T, DecrypterError>;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;
type DecShareCache = BTreeMap<RoundNumber, HashMap<Round, Vec<Vec<Option<DecShare>>>>>;

/// The message types exchanged during decryption phase.
#[derive(Debug, Serialize, Deserialize)]
enum Protocol {
    /// Broadcast a request to retrieve a subset identified by the committee id.
    DkgRequest(CommitteeId),

    /// Direct reply to a get request.
    DkgResponse(SubsetResponse),

    /// Multicast (to new members) a message with agreed-upon subset of DkgBundle for resharing.
    Resharing(ReshareMessage),

    /// Broadcast a batch of decryption shares for a given round.
    Batch(DecShareBatch),
}

/// Command sent to Decrypter's background Worker
enum Command {
    /// Inform the Worker of a DKG bundle.
    Dkg(DkgBundle),
    /// Decrypt all encrypted transactions in the inclusion list.
    Decrypt((InclusionList, bool)),
    /// Prepare for the next committee.
    NextCommittee(AddressableCommittee, KeyStore),
    /// Use a committee starting at the given round.
    UseCommittee(Round),
    /// Garbage collect state related to a round (and previous rounds).
    Gc(RoundNumber),
}

/// A decrypter, indentified by its signing/consensus public key, connects to other decrypters to
/// collectively threshold-decrypt encrypted transactions in the inclusion list during the 2nd phase
/// ("Decryption phase") of timeboost.
///
/// The Decrypter also extracts DKG shares from inclusion lists and combines these to obtain keys.
///
/// In timeboost protocol, a decrypter does both the share "decryption" (using its decryption key
/// share), and combiner's "hatching" (using the combiner key).
///
/// Functionality wise, the core logic of decrypt and combine, and the caching of yet-hatched
/// decryption shares are all managed by a dedicated `Worker` thread. Upon request, the worker
/// receive an inclusion list (potentially w/ some encrypted tx), decypt and broadcast decryption
/// shares to other decrypter's workers, until hatching them to plaintext tx, and finally returns to
/// the Decrypter the decrypted inclusion list, with order perserved. The actual `Decrypter` only
/// acts as a proxy to `enqueue` or be pulled by other timeboost components.
pub struct Decrypter {
    /// Public key of the node.
    label: PublicKey,
    /// Buffer of increasing round numbers representing inclusion lists.
    ///
    /// The boolean flag (if true) indicates that the inclusion list contains
    /// encrypted transactions.
    incls: VecDeque<(RoundNumber, bool)>,
    /// Sender end of the worker commands
    worker_tx: Sender<Command>,
    /// Receiver end of the Worker response
    worker_rx: Receiver<InclusionList>,
    /// Worker task handle.
    worker: JoinHandle<EndOfPlay>,
    /// Pending threshold encryption key material
    dec_key: DecryptionKeyCell,
    /// Key stores (shared with Worker)
    key_stores: Arc<RwLock<KeyStoreVec<2>>>,
    /// Current committee.
    current: CommitteeId,
    /// Metrics to keep track of decrypter status
    metrics: Arc<SequencerMetrics>,
}

impl Decrypter {
    pub async fn new<M>(
        cfg: DecrypterConfig,
        metrics: &M,
        seq_metrics: Arc<SequencerMetrics>,
    ) -> Result<Self>
    where
        M: metrics::Metrics,
    {
        let (cmd_tx, cmd_rx) = channel(cfg.retain * 2); // incl and gc
        let (dec_tx, dec_rx) = channel(cfg.retain);
        let (addr_comm, key_store) = cfg.committee;
        let net_metrics = NetworkMetrics::new("decrypt", metrics, addr_comm.parties().copied());

        let mut net = Network::create(
            "decrypt",
            cfg.address,
            cfg.label,
            cfg.dh_keypair,
            addr_comm.entries(),
            net_metrics,
        )
        .await
        .map_err(DecrypterError::Net)?;

        let committee = key_store.committee();
        let current = committee.id();
        let labeled_sk = cfg.dkg_key.label(
            committee
                .get_index(&cfg.label)
                .ok_or_else(|| DecrypterError::UnknownKey(cfg.label))?
                .into(),
        );

        let (key_stores, state) = match cfg.prev_committee {
            Some((prev_addr_comm, prev_key_store)) => {
                let kv = KeyStoreVec::new(prev_key_store).with(key_store);
                // add peers from the previous committee not present in the current committee.
                let new_peers = prev_addr_comm.diff(&addr_comm);
                net.add(new_peers.collect()).await?;
                (
                    Arc::new(RwLock::new(kv)),
                    WorkerState::HandoverPending(HashMap::new()),
                )
            }
            None => {
                let kv = KeyStoreVec::new(key_store);
                (
                    Arc::new(RwLock::new(kv)),
                    WorkerState::DkgPending(HashMap::new()),
                )
            }
        };

        let worker = Worker::builder()
            .label(cfg.label)
            .dkg_sk(labeled_sk)
            .key_stores(key_stores.clone())
            .current(current)
            .net(Overlay::new(net))
            .state(state)
            .tx(dec_tx)
            .rx(cmd_rx)
            .dec_key(cfg.threshold_dec_key.clone())
            .retain(cfg.retain)
            .build();

        Ok(Self {
            label: cfg.label,
            incls: VecDeque::new(),
            worker_tx: cmd_tx,
            worker_rx: dec_rx,
            worker: spawn(worker.go()),
            dec_key: cfg.threshold_dec_key,
            key_stores: key_stores.clone(),
            current,
            metrics: seq_metrics,
        })
    }

    /// Check if the channels between Decrypter and its Worker have capacity.
    pub fn has_capacity(&mut self) -> bool {
        self.worker_tx.capacity() > 0 && self.worker_rx.capacity() > 0
    }

    /// Garbage collect cached state of `r` and prior rounds.
    pub async fn gc(&mut self, r: RoundNumber) -> StdResult<(), DecrypterDown> {
        if self.dec_key.get_ref().is_some() {
            self.worker_tx
                .send(Command::Gc(r))
                .await
                .map_err(|_| DecrypterDown(()))?
        }
        Ok(())
    }

    /// Send the inclusion list to the Worker for decryption.
    pub async fn enqueue(&mut self, incl: InclusionList) -> StdResult<(), DecrypterDown> {
        let round = incl.round();
        let is_encrypted = incl.is_encrypted();
        if is_encrypted {
            self.metrics.queued_encrypted.update(1);
        }
        debug!(node = %self.label, %round, %is_encrypted, "enqueuing inclusion list");

        self.worker_tx
            .send(Command::Decrypt((incl, is_encrypted)))
            .await
            .map_err(|_| DecrypterDown(()))?;
        self.incls.push_back((round, is_encrypted));

        Ok(())
    }

    /// Send the received DKG bundle to worker
    pub async fn enqueue_dkg(&self, dkg: DkgBundle) -> StdResult<(), DecrypterDown> {
        self.worker_tx
            .send(Command::Dkg(dkg))
            .await
            .map_err(|_| DecrypterDown(()))?;
        debug!(node = %self.label, "enqueued one dkg bundle");
        Ok(())
    }

    /// Generates and returns a DKG bundle for the current committee, if not already submitted.
    ///
    /// # Returns
    /// - `Some(DkgBundle)` if a new dealing was successfully created for the current committee.
    /// - `None` if already submitted or if encryption key is missing.
    pub fn gen_dkg_bundle(&mut self) -> Option<DkgBundle> {
        let guard = self.key_stores.read();
        let Some(store) = guard.get(self.current) else {
            warn!(node = %self.label, committee = %self.current, "missing current key store");
            return None;
        };
        let Some(node_idx) = store.committee().get_index(&self.label) else {
            warn!(node = %self.label, committee = %self.current, "local key not in store for dkg");
            return None;
        };

        let vess = Vess::new_fast();
        let mut rng = thread_rng();
        let secret = <Vss as VerifiableSecretSharing>::Secret::rand(&mut rng);
        let (ct, cm) = vess
            .encrypt_shares(store.committee(), store.sorted_keys(), secret, DKG_AAD)
            .ok()?;
        Some(DkgBundle::new((node_idx, self.label), self.current, ct, cm))
    }

    /// Generates a resharing bundle for the given key store, if not already submitted.
    ///
    /// # Returns
    /// - `Some(DkgBundle)` if a Resharing dealing was successfully created.
    /// - `None` if already submitted or if encryption key is missing.
    pub fn gen_resharing_bundle(&mut self, next_store: KeyStore) -> Option<DkgBundle> {
        let committee_id = next_store.committee().id();
        let guard = self.key_stores.read();
        let Some(current_store) = guard.get(self.current) else {
            warn!(node = %self.label, committee = %self.current, "missing current key store");
            return None;
        };

        let Some(node_idx) = current_store.committee().get_index(&self.label) else {
            warn!(node = %self.label, committee = %self.current, "local key not in store for resharing");
            return None;
        };

        let Some(dec_key) = self.dec_key.get() else {
            warn!(node = %self.label, committee = %committee_id, "no existing key to reshare");
            return None;
        };
        let vess = Vess::new_fast();
        let (ct, cm) = vess
            .encrypt_reshares(
                next_store.committee(),
                next_store.sorted_keys(),
                *dec_key.privkey().share(),
                DKG_AAD,
            )
            .ok()?;
        Some(DkgBundle::new((node_idx, self.label), committee_id, ct, cm))
    }

    /// Produces decrypted inclusion lists received from the Worker.
    pub async fn next(&mut self) -> StdResult<InclusionList, DecrypterDown> {
        loop {
            // wait for next message
            let dec_incl = self.worker_rx.recv().await.ok_or(DecrypterDown(()))?;
            let round = dec_incl.round();

            // get the expected round from the front of the queue
            if let Some((expected_round, is_encrypted)) = self.incls.pop_front() {
                if round != expected_round {
                    warn!(
                        node = %self.label,
                        %round,
                        %expected_round,
                        "inclusion list does not match next round"
                    );
                    self.incls.push_front((expected_round, is_encrypted));
                    continue;
                }

                debug!(
                    node = %self.label,
                    round = %round,
                    epoch = %dec_incl.epoch(),
                    "received inclusion list from Worker"
                );

                if is_encrypted {
                    debug_assert!(
                        !dec_incl.is_encrypted(),
                        "decrypter Worker returned non-decrypted inclusion list"
                    );
                    self.metrics.output_decrypted.update(1);
                }

                return Ok(dec_incl);
            } else {
                error!(
                    node = %self.label,
                    %round,
                    "received unexpected inclusion list"
                );
                return Err(DecrypterDown(()));
            }
        }
    }

    /// Prepare for the next committee.
    pub async fn next_committee(
        &mut self,
        c: AddressableCommittee,
        k: KeyStore,
    ) -> StdResult<(), DecrypterDown> {
        debug!(node = %self.label, committee = %c.committee().id(), "next committee");
        self.worker_tx
            .send(Command::NextCommittee(c, k))
            .await
            .map_err(|_| DecrypterDown(()))?;
        Ok(())
    }

    /// Use a committee starting at the given round.
    pub async fn use_committee(&mut self, r: Round) -> StdResult<(), DecrypterDown> {
        debug!(node = %self.label, round = %r, "use committee");
        self.worker_tx
            .send(Command::UseCommittee(r))
            .await
            .map_err(|_| DecrypterDown(()))?;
        Ok(())
    }
}

impl Drop for Decrypter {
    fn drop(&mut self) {
        self.worker.abort()
    }
}

/// The operational state of the Worker.
///
/// # State Machine Flow: (epoch e1 is special, e2 onwards are the same)
///
/// note: ShuttingDown and ResharingComplete will trigger send_handover_msg,
/// Running is triggered by maybe_switch_committee except in epoch 1
///
/// #1: "e1 -> e2, in C1, but not C2"
/// DkgPending -> Running -> ShuttingDown
///
/// #2: "e1 -> e2, in C1 and C2"
/// DkgPending -> Running -> ResharingComplete -> Running (in e2)
///
/// #3: "ex -> ex+1, in Cx, but not Cx+1"
/// HandoverPending -> HandoverComplete -> Running (in ex) -> ShuttingDown
///
/// #4: "ex -> ex+1, in Cx and Cx+1"
/// HandoverPending -> HandoverComplete -> Running (in ex) -> ResharingComplete -> Running (in ex+1)
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum WorkerState {
    /// Awaiting resharing subsets from previous committee (current committee, if catching up).
    HandoverPending(HashMap<PublicKey, DkgSubset>),
    /// Received enough resharing messages to complete the handover, but not yet actively running.
    HandoverComplete,
    /// Expects to obtain the initial DKG key through DKG bundles.
    ///
    /// Upon startup the Worker requests DKG messages from remote nodes
    /// such that, if the local node is behind, it will catchup immediately.
    DkgPending(HashMap<PublicKey, DkgSubset>),
    /// Active mode with decryption key ready.
    Running,
    /// Obtained decryption key for the next committee also as a member (see case #2 and #4)
    ResharingComplete(DecryptionKey),
    /// Completed resharing and handover but is not a member of next committee.
    ShuttingDown,
}

/// Worker is responsible for "hatching" ciphertexts.
///
/// When ciphertexts in a round have received t+1 decryption shares
/// the shares can be combined to decrypt the ciphertext (hatching).
#[derive(Builder)]
struct Worker {
    /// Labeling of the node (consensus signing key).
    label: PublicKey,

    /// Overlay network to connect to other decrypter Workers.
    net: Overlay,

    /// Current committee.
    current: CommitteeId,

    /// The next committee to use, if any.
    next_committee: Option<Round>,

    /// Channel for sending inclusion lists back to parent.
    tx: Sender<InclusionList>,

    /// Channel for receiving commands from the parent.
    rx: Receiver<Command>,

    /// Pending decryption key that will be updated after DKG/resharing is done.
    dec_key: DecryptionKeyCell,

    /// First round where an inclusion list was received (ignore shares for earlier rounds).
    first_requested_round: Option<RoundNumber>,

    /// Decryption key used for communication between nodes for DKG and resharing.
    dkg_sk: LabeledDkgDecKey,

    /// Key material for committee members (shared with Decrypter)
    key_stores: Arc<RwLock<KeyStoreVec<2>>>,

    /// State of the node holding generated threshold decryption keys.
    state: WorkerState,

    /// Number of rounds to retain.
    retain: usize,

    /// Tracker for DKG bundles received from other nodes.
    #[builder(default)]
    tracker: BTreeMap<CommitteeId, DkgAccumulator>,

    /// Cache of decryption shares received from remote nodes or produced from local ciphertexts.
    #[builder(default)]
    dec_shares: DecShareCache,

    /// Map of received decryption shares for each round.
    /// Useful to prevent DOS or DecShareBatch flooding by malicious peers.
    #[builder(default)]
    acks: BTreeMap<RoundNumber, HashSet<PublicKey>>,

    /// Inclusion lists (possibly encrypted) waiting to be hatched.
    #[builder(default)]
    incls: BTreeMap<RoundNumber, (InclusionList, bool)>,

    /// Pending inclusion lists not yet decrypted due to missing decryption key.
    #[builder(default)]
    pending: BTreeMap<RoundNumber, InclusionList>,

    /// The local clock, driven by round number.
    #[builder(default = RoundNumber::genesis())]
    clock: RoundNumber,

    /// The last round for which ciphertexts have hatched.
    #[builder(default = RoundNumber::genesis())]
    last_hatched_round: RoundNumber,
}

impl Worker {
    pub async fn go(mut self) -> EndOfPlay {
        debug_assert!(matches!(
            self.state,
            WorkerState::HandoverPending(_) | WorkerState::DkgPending(_)
        ));
        // immediately try to catchup first
        match self.dkg_catchup().await {
            Ok(()) => {}
            Err(DecrypterError::End(end)) => return end,
            Err(err) => warn!(node = %self.label, %err, "error on catchup"),
        }

        loop {
            let mut cache_modified = false;
            // process pending inclusion lists received during catchup
            if !self.pending.is_empty() && matches!(self.state, WorkerState::Running) {
                for incl in std::mem::take(&mut self.pending).into_values() {
                    match self.on_decrypt_request(incl, true).await {
                        Ok(()) => {}
                        Err(DecrypterError::End(end)) => return end,
                        Err(err) => {
                            warn!(node = %self.label, %err, "error processing pending inclusion list")
                        }
                    }
                }
                cache_modified = true;
            }

            tokio::select! {
                // received a network message from another node
                msg = self.net.receive() => match msg {
                    Ok((src, data)) => {
                        match self.on_inbound(src, data).await {
                            Ok(updated) => cache_modified |= updated,
                            Err(DecrypterError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, %src, "error on message")
                        }
                    },
                    Err(err) => {
                        let _: NetworkDown = err;
                        debug!(node = %self.label, "network down");
                        return EndOfPlay::NetworkDown
                    }
                },
                // received command from the Decrypter (parent)
                cmd = self.rx.recv() => match cmd {
                    Some(Command::Dkg(b)) => {
                        if *b.committee_id() == self.current {
                            match self.on_dkg_request(b).await {
                                Ok(()) => {}
                                Err(DecrypterError::End(end)) => return end,
                                Err(err) => warn!(node = %self.label, %err, "error on dkg request")
                            }
                        } else {
                            match self.on_resharing_request(b).await {
                                Ok(()) => {}
                                Err(DecrypterError::End(end)) => return end,
                                Err(err) => warn!(node = %self.label, %err, "error on resharing request")
                            }
                        }
                    },
                    Some(Command::Decrypt((incl, is_encrypted))) => {
                        let round = incl.round();
                        trace!(node = %self.label, %round, "decrypt request");
                        match self.on_decrypt_request(incl, is_encrypted).await {
                            Ok(()) => { cache_modified = true }
                            Err(DecrypterError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %round, %err, "error on decrypt request")
                        }
                    },
                    Some(Command::Gc(round))=> {
                        match self.on_gc_request(round).await {
                            Ok(()) => {}
                            Err(DecrypterError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on gc request")
                        }
                    },
                    Some(Command::NextCommittee(c, k)) =>
                        match self.on_next_committee(c, k).await {
                            Ok(()) => {}
                            Err(DecrypterError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on next committee")
                        }
                    Some(Command::UseCommittee(r)) =>
                        match self.on_use_committee(r).await {
                            Ok(()) => {}
                            Err(DecrypterError::End(end)) => return end,
                            Err(err) => warn!(node = %self.label, %err, "error on use committee")
                        }
                    None => {
                        debug!(node = %self.label, "parent down");
                        return EndOfPlay::DecrypterDown
                    }
                },
            }

            if self.first_requested_round.is_none() || !cache_modified {
                // avoid hatching attempt if no requests or no new decryption shares
                continue;
            }

            let round: RoundNumber = self.oldest_cached_round();
            match self.hatch(round).await {
                Ok(_) => {}
                Err(DecrypterError::End(end)) => return end,
                Err(err) => warn!(node = %self.label, %round, %err, "error on hatch"),
            }

            if matches!(self.state, WorkerState::ShuttingDown) {
                // graceful shut down
                if let Some(next_committee) = self.next_committee {
                    if next_committee.num() - 1 == self.last_hatched_round {
                        info!(node = %self.label, "shutting down decrypter");
                        return EndOfPlay::DecrypterDown;
                    }
                }
            }
        }
    }

    /// Returns the smallest round number with a decryption request.
    fn oldest_cached_round(&self) -> RoundNumber {
        self.incls
            .keys()
            .next()
            .copied()
            .unwrap_or(RoundNumber::genesis())
    }

    /// Returns true if completed, false otherwise (ongoing or no pending DKG found)
    fn dkg_completed(&self, committee_id: &CommitteeId) -> bool {
        if let Some(acc) = self.tracker.get(committee_id) {
            acc.completed()
        } else {
            false
        }
    }

    /// A message from another node has been received.
    /// Returns true if decryption shares have been updated.
    async fn on_inbound(&mut self, src: PublicKey, bytes: Bytes) -> Result<bool> {
        // ignore msg sent to self during broadcast
        if src == self.label {
            return Ok(false);
        }
        trace!(node = %self.label, from = %src, buf = %bytes.len(), "inbound message");

        let conf = bincode::config::standard().with_limit::<MAX_MESSAGE_SIZE>();
        match bincode::serde::decode_from_slice(&bytes, conf)?.0 {
            Protocol::DkgRequest(cid) => self.on_dkg_request_msg(src, cid).await?,
            Protocol::DkgResponse(res) => self.on_dkg_response_msg(src, res).await?,
            Protocol::Resharing(msg) => self.on_resharing_msg(src, msg).await?,
            Protocol::Batch(batch) => {
                self.on_batch_msg(src, batch).await?;
                return Ok(true);
            }
        };

        Ok(false)
    }

    /// A DKG subset request (for standard DKG or resharing) has been received.
    async fn on_dkg_request_msg(
        &mut self,
        src: PublicKey,
        committee_id: CommitteeId,
    ) -> Result<()> {
        trace!(node = %self.label, from=%src, %committee_id, "received dkg request");

        let (bundles, mode) = match self.tracker.get(&committee_id) {
            Some(acc) if acc.completed() => (acc.bundles(), acc.mode()),
            _ => {
                trace!(node = %self.label, from=%src, %committee_id, "local dkg incomplete");
                return Ok(());
            }
        };

        self.key_stores
            .read()
            .get(committee_id)
            .ok_or(DecrypterError::NoCommittee(committee_id))?
            .committee()
            .get_index(&src)
            .ok_or(DecrypterError::UnknownKey(src))?;

        let subset = match mode {
            AccumulatorMode::Dkg => DkgSubset::new_dkg(committee_id, bundles.to_vec()),
            AccumulatorMode::Resharing(combkey) => {
                DkgSubset::new_resharing(committee_id, bundles.to_vec(), combkey.to_owned())
            }
        };
        let response = SubsetResponse::new(committee_id, subset);

        self.net
            .unicast(
                src,
                self.oldest_cached_round().u64(),
                serialize(&Protocol::DkgResponse(response))?,
            )
            .await
            .map_err(|e| DecrypterError::End(e.into()))?;

        Ok(())
    }

    /// A response for DKG subset has been received.
    async fn on_dkg_response_msg(&mut self, src: PublicKey, res: SubsetResponse) -> Result<()> {
        trace!(node = %self.label, from=%src, %res.committee_id, "received dkg response");
        if res.committee_id != self.current {
            trace!(node = %self.label, from=%src, %res.committee_id, "not current committee");
            return Ok(());
        }
        let subsets = match &mut self.state {
            WorkerState::DkgPending(subsets) | WorkerState::HandoverPending(subsets) => subsets,
            _ => {
                trace!(node = %self.label, from=%src, %res.committee_id, "not in a pending state");
                return Ok(());
            }
        };

        let guard = self.key_stores.read();
        let current = guard
            .get(res.committee_id)
            .ok_or(DecrypterError::NoCommittee(res.committee_id))?;

        let prev = (guard.len() == 2).then(|| guard.last().clone());
        current
            .committee()
            .get_index(&src)
            .ok_or_else(|| DecrypterError::UnknownKey(src))?;

        subsets.insert(src, res.subset.to_owned());
        let committee = current.committee();
        let threshold: usize = committee.one_honest_threshold().into();

        let mut counts = HashMap::new();
        for subset in subsets.values() {
            *counts.entry(subset).or_insert(0) += 1;
        }

        if let Some((&subset, _)) = counts.iter().find(|(_, count)| **count >= threshold) {
            let acc = DkgAccumulator::from_subset(current.clone(), subset.to_owned());
            self.tracker.insert(committee.id(), acc);
            let dec_key = subset
                .extract_key(current.to_owned(), &self.dkg_sk, prev)
                .map_err(|e| DecrypterError::Dkg(e.to_string()))?;

            self.dec_key.set(dec_key);
            self.state = WorkerState::Running;
            info!(node = %self.label, committee_id = %committee.id(), "dkg finished (catchup successful)");
        }

        Ok(())
    }

    /// A resharing message has been received.
    async fn on_resharing_msg(&mut self, src: PublicKey, msg: ReshareMessage) -> Result<()> {
        trace!(node = %self.label, from=%src, %msg.committee_id, "received resharing message");
        if msg.committee_id != self.current {
            info!(node = %self.label, current = %self.current, %msg.committee_id, "not current committee");
            return Ok(());
        }

        let subsets = match &mut self.state {
            WorkerState::HandoverPending(subsets) => subsets,
            _ => {
                trace!(node = %self.label, current = %self.current, %msg.committee_id, "not awaiting handover");
                return Ok(());
            }
        };

        let guard = self.key_stores.read();
        if guard.len() < 2 {
            warn!(node = %self.label, current = %self.current, %msg.committee_id, "no previous key store");
            return Ok(());
        }
        let (prev, current) = (guard.last(), guard.first());

        subsets.insert(src, msg.subset.to_owned());

        let threshold: usize = prev.committee().one_honest_threshold().into();

        let mut counts = HashMap::new();
        for subset in subsets.values() {
            *counts.entry(subset).or_insert(0) += 1;
        }

        if let Some((&subset, _)) = counts.iter().find(|(_, count)| **count >= threshold) {
            let acc = DkgAccumulator::from_subset(current.clone(), subset.to_owned());
            self.tracker.insert(current.committee().id(), acc);
            let next_dec_key = subset
                .extract_key(current.clone(), &self.dkg_sk, Some(prev.to_owned()))
                .map_err(|e| DecrypterError::Dkg(e.to_string()))?;

            info!(committee_id = %current.committee().id(), node = %self.label, "handover finished");
            self.state = WorkerState::HandoverComplete;
            self.dec_key.set(next_dec_key);
        }

        Ok(())
    }

    /// A batch of decryption shares from another node has been received.
    async fn on_batch_msg(&mut self, src: PublicKey, batch: DecShareBatch) -> Result<()> {
        let round = batch.round.num();
        let committee_id = batch.round.committee();

        self.key_stores
            .read()
            .get(committee_id)
            .ok_or(DecrypterError::NoCommittee(committee_id))?
            .committee()
            .get_index(&src)
            .ok_or(DecrypterError::UnknownKey(src))?;

        // if already sent for this round, `src` will be re-inserted, thus returns false
        // in which case we skip processing this message since this peer has already sent once
        if !self.acks.entry(round).or_default().insert(src) {
            return Ok(());
        };

        if round <= self.last_hatched_round {
            return Ok(());
        }
        trace!(node = %self.label, from=%src, %round, "inserting decrypted shares");

        self.insert_shares(batch)?;

        Ok(())
    }

    /// Received a DkgBundle for the current committee (not resharing).
    async fn on_dkg_request(&mut self, bundle: DkgBundle) -> Result<()> {
        let committee_id = bundle.committee_id();
        if self.dkg_completed(committee_id) {
            trace!(
                node = %self.label,
                %committee_id,
                "received bundle but dkg already completed"
            );
            return Ok(());
        }

        let guard = self.key_stores.read();
        let Some(key_store) = guard.get(*committee_id) else {
            return Err(DecrypterError::NoCommittee(*committee_id));
        };

        let acc = self
            .tracker
            .entry(*committee_id)
            .or_insert_with(|| DkgAccumulator::new_dkg(key_store.clone()));

        acc.try_add(bundle)
            .map_err(|e| DecrypterError::Dkg(format!("unable to add dkg bundle: {e}")))?;

        if let Some(subset) = acc.try_finalize() {
            let dec_key = subset
                .extract_key(key_store.to_owned(), &self.dkg_sk, None)
                .map_err(|e| DecrypterError::Dkg(e.to_string()))?;
            self.dec_key.set(dec_key);
            self.state = WorkerState::Running;
            info!(committee_id = %key_store.committee().id(), node = %self.label, "dkg finished");
        }
        Ok(())
    }

    /// Received a DkgBundle but not for current committee (resharing).
    async fn on_resharing_request(&mut self, bundle: DkgBundle) -> Result<()> {
        let committee_id = bundle.committee_id();
        if self.dkg_completed(committee_id) {
            trace!(
                node = %self.label,
                %committee_id,
                "received bundle but resharing already completed"
            );
            return Ok(());
        }
        let Some(dec_key) = self.dec_key.get() else {
            warn!(
                node = %self.label,
                %committee_id,
                "received resharing bundle but initial DKG has not finished"
            );
            return Ok(());
        };

        let (current, next) = {
            let guard = self.key_stores.read();
            let Some(current_key_store) = guard.get(self.current) else {
                return Err(DecrypterError::NoCommittee(*committee_id));
            };

            let Some(next_key_store) = guard.get(*committee_id) else {
                return Err(DecrypterError::NoCommittee(*committee_id));
            };
            (current_key_store.to_owned(), next_key_store.to_owned())
        };

        let acc = self.tracker.entry(*committee_id).or_insert_with(|| {
            DkgAccumulator::new_resharing(next.clone(), dec_key.combkey().clone())
        });

        acc.try_add(bundle)
            .map_err(|e| DecrypterError::Dkg(format!("unable to add resharing bundle: {e}")))?;

        if let Some(subset) = acc.try_finalize() {
            let committee = acc.committee();

            if committee.contains_key(&self.label) {
                // node is a member of the next committee; decrypting reshares immediately
                let next_dec_key = subset
                    .extract_key(next, &self.dkg_sk, Some(current))
                    .map_err(|e| DecrypterError::Dkg(e.to_string()))?;
                self.state = WorkerState::ResharingComplete(next_dec_key);
            } else {
                // resharing complete; node will shut down at next committee switch
                self.state = WorkerState::ShuttingDown;
            }

            trace!(committee_id = %committee.id(), node = %self.label, "resharing complete; handing over");
            self.send_handover_msg(subset).await?;
        }
        Ok(())
    }

    /// Send ResharingSubsets to nodes in next committee but not in current (handover).
    async fn send_handover_msg(&mut self, subset: DkgSubset) -> Result<()> {
        let (current, next) = {
            let guard = self.key_stores.read();
            let Some(current) = guard.get(self.current) else {
                return Err(DecrypterError::NoCommittee(self.current));
            };

            let Some(next) = guard.get(*subset.committee_id()) else {
                return Err(DecrypterError::NoCommittee(*subset.committee_id()));
            };
            (current.clone(), next.clone())
        };
        let m = ReshareMessage::new(*subset.committee_id(), subset);

        // handover only to new members (nodes not in current)
        let dest: Vec<_> = next
            .committee()
            .parties()
            .filter(|k| !current.committee().contains_key(k))
            .copied()
            .collect();

        self.net
            .multicast(
                dest,
                self.oldest_cached_round().u64(),
                serialize(&Protocol::Resharing(m))?,
            )
            .await
            .map_err(|e| DecrypterError::End(e.into()))?;
        Ok(())
    }

    /// Process a decryption request.
    async fn on_decrypt_request(&mut self, incl: InclusionList, is_encrypted: bool) -> Result<()> {
        let round: RoundNumber = incl.round();

        self.clock = round;
        self.maybe_switch_committee().await?;

        if is_encrypted {
            let dec_shares = self.decrypt(&incl).await?;
            if dec_shares.is_empty() {
                return Err(DecrypterError::EmptyDecShares);
            }
            self.net
                .broadcast(
                    round.u64(),
                    serialize(&Protocol::Batch(dec_shares.clone()))?,
                )
                .await
                .map_err(|e| DecrypterError::End(e.into()))?;
            self.insert_shares(dec_shares)?;
        }

        self.incls.insert(round, (incl, is_encrypted));

        // edge case: when processing the first decrypt request, workers may have received
        // decryption shares of eariler rounds from other decrypters, but this worker
        // doesn't need those shares, thus pruning them.
        if self.first_requested_round.is_none() {
            debug!(node = %self.label, %round, "set first requested round");
            self.dec_shares.retain(|k, _| k >= &round);
            self.first_requested_round = Some(round);
        }

        Ok(())
    }

    /// Catch up by requesting DKG subsets from remote nodes.
    async fn dkg_catchup(&mut self) -> Result<()> {
        let req = Protocol::DkgRequest(self.current);
        // the round number is ignored by the recieving party, but we don't want to give an
        // arbitrary value since `gc()` will probably clean it up too early. Thus, we put in
        // an estimated round number using the `.oldest_cached_round()`.
        self.net
            .broadcast(self.oldest_cached_round().u64(), serialize(&req)?)
            .await
            .map_err(|e| DecrypterError::End(e.into()))?;
        Ok(())
    }

    /// Garbage collect internally cached state. Different from `self.on_gc_request()` which deals
    /// with incoming gc request, indicating more than just local gc, but also overlay
    /// network-wise gc.
    fn gc(&mut self, round: RoundNumber) {
        self.dec_shares.retain(|r, _| *r > round);
        self.incls.retain(|r, _| *r > round);
        self.acks.retain(|r, _| *r > round);
    }

    /// Garbage collect a round (and all prior rounds).
    async fn on_gc_request(&mut self, round: RoundNumber) -> Result<()> {
        let round = round.saturating_sub(self.retain as u64);
        if round > 0 && !self.dec_shares.is_empty() {
            debug!(node = %self.label, %round, "performing garbage collection");
            self.net.gc(round);
            self.gc(round.into());
        }
        Ok(())
    }

    /// scan through the inclusion list and extract the ciphertexts from encrypted
    /// bundle/tx while preserving the order.
    ///
    /// dev: Option<_> return type indicates potential failure in ciphertext deserialization
    fn extract_ciphertexts(incl: &InclusionList) -> impl Iterator<Item = Option<Ciphertext>> {
        incl.priority_bundles()
            .iter()
            .filter(move |pb| pb.bundle().is_encrypted())
            .map(|pb| pb.bundle().data())
            .chain(
                incl.regular_bundles()
                    .iter()
                    .filter(move |b| b.is_encrypted())
                    .map(|b| b.data()),
            )
            .map(|bytes| deserialize::<Ciphertext>(bytes).ok())
    }

    /// Produce decryption shares for each encrypted bundles inside the inclusion list,
    ///
    /// NOTE: when a ciphertext is malformed, we will skip decrypting it (treat as garbage) here.
    /// but will later be marked as decrypted during `hatch()`
    async fn decrypt(&mut self, incl: &InclusionList) -> Result<DecShareBatch> {
        let dec_key: DecryptionKey = match &self.state {
            WorkerState::DkgPending(_) => {
                self.pending.insert(incl.round(), incl.clone());
                return Err(DecrypterError::DkgPending);
            }
            WorkerState::HandoverPending(_) => {
                return Err(DecrypterError::Dkg(
                    "Worker state does not hold decryption key".to_string(),
                ));
            }
            WorkerState::ResharingComplete(_) => {
                return Err(DecrypterError::Dkg(format!(
                    "resharing completed, but Worker not active: label={}, round={}",
                    self.label,
                    incl.round()
                )));
            }
            _ => self.dec_key.get().ok_or_else(|| {
                DecrypterError::Internal("Worker running without dec key".to_string())
            })?,
        };

        let round = Round::new(incl.round(), self.current);
        let dec_shares = Self::extract_ciphertexts(incl)
            .map(|optional_ct| {
                optional_ct.and_then(|ct| {
                    // TODO: (anders) consider using committee_id as part of `aad`.
                    <DecryptionScheme as ThresholdEncScheme>::decrypt(
                        dec_key.privkey(),
                        &ct,
                        &THRES_AAD.to_vec(),
                    )
                    .ok() // decryption failure result in None
                })
            })
            .collect::<Vec<_>>();

        Ok(DecShareBatch {
            round,
            dec_shares,
            evidence: incl.evidence().clone(),
        })
    }

    /// Insert decrypted shares into the local cache.
    fn insert_shares(&mut self, batch: DecShareBatch) -> Result<()> {
        if batch.is_empty() {
            trace!(node = %self.label, "empty decryption share batch, skipped");
            return Err(DecrypterError::EmptyDecShares);
        }
        let round = batch.round;

        if !self
            .key_stores
            .read()
            .is_valid(round.num(), &batch.evidence)
        {
            warn!(
                node     = %self.label,
                round    = %round,
                evidence = %batch.evidence.round(),
                "invalid evidence"
            );
            return Err(DecrypterError::MissingRoundEvidence(round));
        }

        // This operation is doing the following: assumme local cache for this round is:
        // [[s1a, s1b], [s2a, s2b], [s3a, s3b]]
        // there are 3 ciphertexts, and node a and b has contributed their decrypted shares batch so
        // far. with node c's batch [s1c, s2c, s3c], the new local cache is:
        // [[s1a, s1b, s1c], [s2a, s2b, s2c], [s3a, s3b, s3c]]
        let round_num = round.num();
        let round_map = self.dec_shares.entry(round_num).or_default();
        let entry = round_map
            .entry(round)
            .or_insert_with(|| vec![vec![]; batch.len()]);
        entry
            .iter_mut()
            .zip(batch.dec_shares)
            .for_each(|(shares, new)| shares.push(new));

        Ok(())
    }

    /// Attempt to hatch for round, returns Ok(Some(_)) if hatched successfully, Ok(None) if
    /// insufficient shares or inclusion list yet received (hatching target arrive later than
    /// decrypted shares is possible due to out-of-order delivery).
    /// Local cache are garbage collected for hatched rounds.
    async fn hatch(&mut self, round: RoundNumber) -> Result<Option<InclusionList>> {
        let Some((incl, is_encrypted)) = self.incls.get(&round) else {
            return Ok(None);
        };
        let mut incl = incl.clone();

        // return immediately to parent if no encrypted transactions
        if !is_encrypted {
            self.gc(round);
            self.last_hatched_round = round;

            self.tx
                .send(incl.clone())
                .await
                .map_err(|_| EndOfPlay::DecrypterDown)?;
            return Ok(Some(incl));
        }

        let dec_key = match &self.state {
            WorkerState::Running
            | WorkerState::ResharingComplete(_)
            | WorkerState::ShuttingDown => self.dec_key.get().ok_or_else(|| {
                DecrypterError::Internal("Worker running without dec key".to_string())
            })?,
            _ => {
                return Err(DecrypterError::Dkg(
                    "(hatching) worker state does not hold decryption key".to_string(),
                ));
            }
        };

        let ciphertexts = Self::extract_ciphertexts(&incl);

        // find the first round (num, committee) with enough valid shares to hatch
        let Some(dec_shares) = self.dec_shares.get(&round) else {
            return Ok(None);
        };
        let Some((r, key_store)) = dec_shares.iter().find_map(|(r, shares)| {
            let guard = self.key_stores.read();
            let key_store = guard.get(r.committee())?;
            if shares.is_empty()
                || shares.iter().any(|opt_dec_shares| {
                    let valid = opt_dec_shares.iter().filter(|s| s.is_some()).count();
                    let invalid = opt_dec_shares.len() - valid;
                    valid < key_store.committee().one_honest_threshold().get()
                        && invalid < key_store.committee().quorum_size().get()
                })
            {
                None
            } else {
                Some((*r, key_store.clone()))
            }
        }) else {
            return Ok(None);
        };

        // hatching ciphertext
        // Option<_> uses None to indicate either invalid ciphertext, or 2f+1 invalid decryption
        // share both imply "skip hatching this garbage bundle which will result in no-op
        // during execution"

        let mut decrypted: Vec<Option<Plaintext>> = vec![];

        // Now, after immutable borrow is dropped, get mutable access
        let Some(per_ct_opt_dec_shares) =
            self.dec_shares.get_mut(&round).and_then(|m| m.get_mut(&r))
        else {
            return Ok(None);
        };

        for (opt_ct, opt_dec_shares) in ciphertexts.into_iter().zip(per_ct_opt_dec_shares) {
            // only Some(_) for valid ciphertext's decryption shares
            let dec_shares = opt_dec_shares
                .iter()
                .filter_map(|s| s.as_ref())
                .collect::<Vec<_>>();

            if dec_shares.len() < key_store.committee().one_honest_threshold().into() {
                decrypted.push(None);
                continue;
            }

            if let Some(ct) = opt_ct {
                match DecryptionScheme::combine(
                    key_store.committee(),
                    dec_key.combkey(),
                    dec_shares,
                    &ct,
                    &THRES_AAD.to_vec(),
                ) {
                    Ok(pt) => decrypted.push(Some(pt)),
                    // with f+1 decryption shares, which means ciphertext is valid, we just need to
                    // remove bad decryption shares and wait for enough shares from honest nodes
                    Err(ThresholdEncError::FaultySubset(wrong_indices)) => {
                        opt_dec_shares.retain(|opt_s| {
                            opt_s
                                .clone()
                                .is_none_or(|s| !wrong_indices.contains(&s.index()))
                        });
                        debug!(node = %self.label, ?wrong_indices, "combine found faulty subset");
                        // not ready to hatch this ciphertext, thus the containing inclusion list
                        return Ok(None);
                    }
                    Err(e) => return Err(DecrypterError::Decryption(e)),
                }
            } else {
                decrypted.push(None);
            }
        }

        // construct/modify the inclusion list to replace with decrypted payload
        let mut num_encrypted_priority_bundles = 0;
        incl.priority_bundles_mut()
            .iter_mut()
            .filter(|pb| pb.bundle().is_encrypted())
            .zip(decrypted.clone())
            .for_each(|(pb, opt_plaintext)| {
                num_encrypted_priority_bundles += 1;
                match opt_plaintext {
                    Some(pt) => pb.set_data(timeboost_types::Bytes::from(<Vec<u8>>::from(pt))),
                    // None means garbage (undecryptable ciphertext), simply mark as decrypted
                    None => pb.set_data(pb.bundle().data().clone()),
                }
            });
        incl.regular_bundles_mut()
            .iter_mut()
            .filter(|b| b.is_encrypted())
            .zip(decrypted[num_encrypted_priority_bundles..].to_vec())
            .for_each(|(bundle, opt_plaintext)| {
                match opt_plaintext {
                    Some(pt) => bundle.set_data(timeboost_types::Bytes::from(<Vec<u8>>::from(pt))),
                    // None means garbage (undecryptable ciphertext), simply mark as decrypted
                    None => bundle.set_data(bundle.data().clone()),
                }
            });
        if incl.is_encrypted() {
            return Err(DecrypterError::Internal(
                "didn't fully decrypt inclusion list".to_string(),
            ));
        }

        // garbage collect hatched rounds
        self.last_hatched_round = round;

        self.gc(round);

        self.tx
            .send(incl.clone())
            .await
            .map_err(|_| EndOfPlay::DecrypterDown)?;

        Ok(Some(incl))
    }

    async fn on_next_committee(&mut self, c: AddressableCommittee, k: KeyStore) -> Result<()> {
        info!(node = %self.label, committee = %c.committee().id(), "add next committee");
        let key_store = {
            let key_stores = self.key_stores.read();
            if key_stores.contains(c.committee().id()) {
                warn!(node = %self.label, committee = %c.committee().id(), "committee already added");
                return Ok(());
            }
            let Some(key_store) = key_stores.get(self.current) else {
                error!(node = %self.label, committee = %self.current, "current committee not found");
                return Err(DecrypterError::NoCommittee(self.current));
            };
            key_store.clone()
        };
        let mut additional = Vec::new();
        for (k, x, a) in c
            .entries()
            .filter(|(k, ..)| !key_store.committee().contains_key(k))
        {
            additional.push((k, x, a))
        }
        self.net
            .add(additional)
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        let mut key_stores_mut = self.key_stores.write();
        key_stores_mut.add(k);
        Ok(())
    }

    async fn on_use_committee(&mut self, round: Round) -> Result<()> {
        info!(node = %self.label, %round, "use committee");
        if self.key_stores.read().get(round.committee()).is_none() {
            error!(node = %self.label, committee = %round.committee(), "committee to use does not exist");
            return Err(DecrypterError::NoCommittee(round.committee()));
        };
        self.next_committee = Some(round);
        Ok(())
    }

    async fn maybe_switch_committee(&mut self) -> Result<()> {
        let Some(start) = self.next_committee else {
            return Ok(());
        };
        if self.clock < start.num() {
            return Ok(());
        }
        let next = start.committee();
        let key_store = {
            let guard = self.key_stores.read();
            let Some(key_store) = guard.get(next) else {
                return Err(DecrypterError::NoCommittee(next));
            };
            key_store.clone()
        };

        // update network
        let old = self
            .net
            .parties()
            .map(|(p, _)| p)
            .filter(|p| !key_store.committee().contains_key(p))
            .copied();

        self.net
            .remove(old.collect())
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;
        self.net
            .assign(
                Role::Active,
                key_store.committee().parties().copied().collect(),
            )
            .await
            .map_err(|_: NetworkDown| EndOfPlay::NetworkDown)?;

        // update state machine
        self.state = match &self.state {
            WorkerState::HandoverComplete => {
                info!(node = %self.label, committee = %self.current, "(new node) successful committee switch");
                WorkerState::Running
            }
            WorkerState::ResharingComplete(next_key) => {
                info!(node = %self.label, committee = %self.current, "(old node) successful committee switch");
                self.dec_key.set(next_key.clone());
                WorkerState::Running
            }
            WorkerState::ShuttingDown => {
                info!("(old node) not a member of new committee. ready for shut down");
                WorkerState::ShuttingDown
            }
            _ => {
                return Err(DecrypterError::Internal(
                    "did not obtain decryption key in time; node unable to recover".to_string(),
                ));
            }
        };
        // clean up
        self.tracker.remove(&self.current);
        self.current = next;

        Ok(())
    }
}

/// A batch of decryption shares. Each batch is uniquely identified via round_number.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct DecShareBatch {
    round: Round,
    // note: each decrpytion share is for a different ciphertext;
    // None entry indicates invalid/failed decryption, we placehold for those invalid ciphertext
    // for simpler hatch/re-assemble logic without tracking a separate indices of those invalid
    // ones
    dec_shares: Vec<Option<DecShare>>,
    /// round evidence to justify `round`, avoiding unbounded worker buffer w/ future rounds data
    evidence: Evidence,
}

impl DecShareBatch {
    /// Returns the number of decryption share in this batch. Equivalently, it's the number of
    /// ciphertexts.
    pub fn len(&self) -> usize {
        self.dec_shares.len()
    }

    /// Returns true if there's no *valid* decryption share. There are three sub-cases this may be
    /// true
    /// - empty set of ciphertext/encrypted bundle
    /// - ciphertexts are malformed and cannot be deserialized
    /// - ciphertexts are invalid and fail to be decrypted
    pub fn is_empty(&self) -> bool {
        self.dec_shares.is_empty() || self.dec_shares.iter().all(|s| s.is_none())
    }
}

/// A response with the agreed-upon subset of DKG bundles.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SubsetResponse {
    committee_id: CommitteeId,
    subset: DkgSubset,
}

impl SubsetResponse {
    pub fn new(committee_id: CommitteeId, subset: DkgSubset) -> Self {
        Self {
            committee_id,
            subset,
        }
    }
}

/// A message with the agreed-upon subset of resharing dealings.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReshareMessage {
    committee_id: CommitteeId,
    subset: DkgSubset,
}

impl ReshareMessage {
    pub fn new(committee_id: CommitteeId, subset: DkgSubset) -> Self {
        Self {
            committee_id,
            subset,
        }
    }
}

fn serialize<T: Serialize>(d: &T) -> Result<Data> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    Ok(Data::try_from(b.into_inner())?)
}

fn deserialize<T: for<'de> serde::Deserialize<'de>>(d: &bytes::Bytes) -> Result<T> {
    bincode::serde::decode_from_slice(
        d,
        bincode::config::standard().with_limit::<MAX_MESSAGE_SIZE>(),
    )
    .map(|(msg, _)| msg)
    .map_err(Into::into)
}

#[derive(Debug, thiserror::Error)]
#[error("decrypter down")]
pub struct DecrypterDown(());

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecrypterError {
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

    #[error("decryption error: {0}")]
    Decryption(#[from] ThresholdEncError),

    #[error("unexpected internal err: {0}")]
    Internal(String),

    #[error("empty set of valid decryption shares")]
    EmptyDecShares,

    #[error("missing evidence for round: {0}")]
    MissingRoundEvidence(Round),

    #[error("received inclusion list is outdated (already received or hatched)")]
    OutdatedRound,

    #[error("unknown committee: {0}")]
    NoCommittee(CommitteeId),

    #[error("unknown key: {0}")]
    UnknownKey(PublicKey),

    #[error("dkg/resharing not yet complete")]
    DkgPending,

    #[error("dkg err: {0}")]
    Dkg(String),
}

/// Fatal errors.
#[derive(Debug, thiserror::Error)]
pub enum EndOfPlay {
    #[error("network down")]
    NetworkDown,
    #[error("decrypter down")]
    DecrypterDown,
}

impl From<NetworkDown> for EndOfPlay {
    fn from(_: NetworkDown) -> Self {
        Self::NetworkDown
    }
}

#[cfg(test)]
mod tests {
    use ark_std::{UniformRand, rand::seq::SliceRandom, rand::thread_rng, test_rng};
    use futures::future::try_join_all;
    use metrics::NoMetrics;
    use serde::{Deserialize, de::value::StrDeserializer};
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Instant,
    };

    use timeboost_utils::{ports::alloc_port, types::logging};

    use cliquenet::AddressableCommittee;
    use multisig::{Committee, KeyId, Keypair, SecretKey, Signed, VoteAccumulator, x25519};
    use sailfish::types::{Evidence, Round, RoundNumber};
    use timeboost_crypto::{
        DecryptionScheme, Plaintext,
        prelude::{DkgDecKey, DkgEncKey, ThresholdEncKey, Vess, Vss},
        traits::{dkg::VerifiableSecretSharing, threshold_enc::ThresholdEncScheme},
    };
    use timeboost_types::{
        Address, Bundle, ChainId, DecryptionKeyCell, Epoch, InclusionList, KeyStore,
        PriorityBundle, SeqNo, Signer, Timestamp,
    };

    use crate::{
        config::DecrypterConfig,
        decrypt::{DKG_AAD, Decrypter, THRES_AAD},
        metrics::SequencerMetrics,
    };

    // Test constants
    const COMMITTEE_SIZE: usize = 5;
    const DECRYPTION_ROUND: u64 = 42;
    const TEST_EPOCH: u64 = 42;
    const TEST_CHAIN_ID: u64 = 0;
    const TEST_SEQNO: u64 = 10;
    const RETAIN_ROUNDS: usize = 100;
    const COM1: u64 = 1;
    const COM2: u64 = 2;

    // Pre-generated deterministic keys for consistent testing
    // Generated via: `just mkconfig_local 5 --seed 42`
    const COM1_SIGNATURE_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "3hzb3bRzn3dXSV1iEVE6mU4BF2aS725s8AboRxLwULPp",
        "FWJzNGvEjFS3h1N1sSMkcvvroWwjT5LQuGkGHu9JMAYs",
        "2yWTaC6MWvNva97t81cd9QX5qph68NnB1wRVwAChtuGr",
        "CUpkbkn8bix7ZrbztPKJwu66MRpJrc1Wr2JfdrhetASk",
        "6LMMEuoPRCkpDsnxnANCRCBC6JagdCHs2pjNicdmQpQE",
    ];

    const COM2_SIGNATURE_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "6YJc9asDJQsFFHHg8iX23oL1sySx2EgTGM8CqDd71WMa",
        "6NZdk8EGRSVS7sSjcjMiC8vL4KcSY41ELU6HaKyk1Drk",
        "AMJEYXVhS4FfoqfD6VL5nZTNbzJQdtgdxBcVEAwZnLJ3",
        "5mLCMSVT4f8HPqCqdKChxugpMcQ3x1C7hwfEnsTApFfp",
        "4yhZYmNvAouKFpiYomrV9aH8kUZTLRH2hiCZtJzcAASa",
    ];

    const COM1_DH_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "BB3zUfFQGfw3sL6bpp1JH1HozK6ehEDmRGoiCpQH62rZ",
        "4hjtciEvuoFVT55nAzvdP9E76r18QwntWwFoeginCGnP",
        "Fo2nYV4gE9VfoVW9bSySAJ1ZuKT461x6ovZnr3EecCZg",
        "5KpixkV7czZTDVh7nV7VL1vGk4uf4kjKidDWq34CJx1T",
        "39wAn3bQzpn19oa8CiaNUFd8GekQAJMMuzrbp8Jt3FKz",
    ];

    const COM2_DH_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "Ho9ZZCkP1i6f12fkWGUZucJxX2qbv9L3UbB56sqwjvkw",
        "F5E9cp5qUe4z2wdaRYvEhFMYXaLy4sEX1rwCWRcTH69i",
        "5zhwDWJ1ut6q871aHCHmH7QRCHDykXjUSEriGTLkwezL",
        "2PojAT3g5iqGTrgLhTRKKHqwbeoFhRkzkYLM9AttFoKK",
        "Bk2wY7o2YE9gpu6jxiRSbWiMU88H8s9D9MQGMaF2LJ7h",
    ];

    const COM1_DKG_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "BW8gq8MARtDkSJL6daobPtGQm22TKkXdbLNrNGngNGTB",
        "ARtqWGmRWrBqZUr4MmiLaPgzjsiKp5USsC9iQNRMZYy4",
        "77r7T3En7NNQvRA81G5hLhJD3VpnigJdkPonX3oAwWkX",
        "7vWcVJDAhfSvmtm1L7KZvoD9agx6hyy9FvA75xWpjxK7",
        "GFvv2wcQmiGpk5rFp1FGpeUjnVUyZmGM9k8VHb1Jn7EG",
    ];

    const COM2_DKG_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "GLNPt6EYeFQbq8cCX5nKMA4LbCKdrUN5o5hmWTPJbkJZ",
        "2n3Pz5NeUAVu5YaWgXN9CCrS6rC7NZwVZ48AG8m7JRqF",
        "AGxRDhGvgovb1DZMjL3Y6Q4hF6UUpFCtpPD6sTJd827U",
        "A3GUHxG3cPKvCch6XowztrHrrvaGS5JH3CuXQKCxQEnv",
        "216zC1MgfV54cJJtt3AKdjJHhqfgZLZCmEyCkFN1bPoF",
    ];

    #[test]
    /// Tests the local DKG (Distributed Key Generation) end-to-end flow without networking.
    /// Verifies that committee members can generate threshold decryption keys and perform
    /// threshold encryption/decryption operations.
    fn test_local_dkg_e2e() {
        logging::init_logging();
        let mut rng = thread_rng();
        let dkg_aad = DKG_AAD.to_vec();

        // Setup committee with generated keypairs
        let committee_keys: Vec<_> = (0..COMMITTEE_SIZE)
            .map(|i| (i as u8, multisig::Keypair::generate().public_key()))
            .collect();
        let committee = Committee::new(COMMITTEE_SIZE as u64, committee_keys);
        let threshold = committee.one_honest_threshold().get();

        // Generate DKG keypairs for secure communication between committee members
        let dkg_private_keys: Vec<_> = (0..COMMITTEE_SIZE)
            .map(|_| DkgDecKey::rand(&mut rng))
            .collect();
        let dkg_public_keys: Vec<_> = dkg_private_keys.iter().map(DkgEncKey::from).collect();

        let vess = Vess::new_fast();

        // Generate dealings: each committee member contributes a random secret
        let start = Instant::now();
        let dealings: Vec<_> = (0..COMMITTEE_SIZE)
            .map(|_| {
                let secret = <Vss as VerifiableSecretSharing>::Secret::rand(&mut rng);
                vess.encrypt_shares(&committee, &dkg_public_keys, secret, &dkg_aad)
                    .unwrap()
            })
            .collect();
        tracing::info!(
            "VESS::encrypt_shares takes {} ms",
            start.elapsed().as_millis() / COMMITTEE_SIZE as u128
        );

        // double check all dealings are correct
        let start = Instant::now();
        assert!(dealings.iter().all(|(ct, comm)| {
            vess.verify_shares(&committee, dkg_public_keys.iter(), ct, comm, &dkg_aad)
                .is_ok()
        }));
        tracing::info!(
            "VESS::verify takes {} ms",
            start.elapsed().as_millis() / COMMITTEE_SIZE as u128
        );

        // Simulate ACS (Asynchronous Common Subset): randomly select subset of dealings for
        // aggregation
        let mut dealing_indices: Vec<_> = (0..COMMITTEE_SIZE).collect();
        dealing_indices.shuffle(&mut rng);
        let selected_dealing_indices = &dealing_indices[..threshold];

        // Extract commitments from selected dealings
        let commitments: Vec<_> = selected_dealing_indices
            .iter()
            .map(|&idx| dealings[idx].1.clone())
            .collect();

        // Decrypt shares for each node from selected dealings
        let start = Instant::now();
        let decrypted_shares_per_node: Vec<Vec<_>> = (0..COMMITTEE_SIZE)
            .map(|node_idx| {
                let labeled_secret_key = dkg_private_keys[node_idx].clone().label(node_idx);
                selected_dealing_indices
                    .iter()
                    .map(|&dealing_idx| {
                        let (ref ciphertext, _) = dealings[dealing_idx];
                        vess.decrypt_share(&committee, &labeled_secret_key, ciphertext, &dkg_aad)
                            .expect("DKG share decryption should succeed")
                    })
                    .collect()
            })
            .collect();
        tracing::info!(
            "VESS::decrypt_shares takes {} ms",
            start.elapsed().as_millis() / (COMMITTEE_SIZE * threshold) as u128
        );

        // Derive threshold decryption keys for each node using DKG output
        let threshold_decryption_keys: Vec<_> = decrypted_shares_per_node
            .iter()
            .enumerate()
            .map(|(node_idx, shares)| {
                super::DecryptionKey::from_dkg(
                    COMMITTEE_SIZE,
                    node_idx,
                    shares.iter().cloned().zip(commitments.iter().cloned()),
                )
                .expect("threshold key derivation should succeed")
            })
            .collect();
        tracing::info!(
            "Post-ACS processing takes {} ms",
            start.elapsed().as_millis() / COMMITTEE_SIZE as u128
        );

        // Verify that all nodes derive the same public and combiner keys
        let (expected_pubkey, expected_combkey) = {
            let first_key = &threshold_decryption_keys[0];
            (first_key.pubkey(), first_key.combkey())
        };

        for (index, key) in threshold_decryption_keys.iter().enumerate().skip(1) {
            assert_eq!(
                key.pubkey(),
                expected_pubkey,
                "Mismatched public key for node {index}"
            );
            assert_eq!(
                key.combkey(),
                expected_combkey,
                "Mismatched combiner key for node {index}"
            );
        }

        // Test threshold encryption/decryption process
        let sample_plaintext = Plaintext::new(b"fox jumps over the lazy dog".to_vec());
        let threshold_aad = THRES_AAD.to_vec();
        let ciphertext =
            DecryptionScheme::encrypt(&mut rng, expected_pubkey, &sample_plaintext, &threshold_aad)
                .expect("encryption should succeed");

        // Generate decryption shares from all nodes
        let decryption_shares: Vec<_> = threshold_decryption_keys
            .iter()
            .map(|key| {
                DecryptionScheme::decrypt(key.privkey(), &ciphertext, &threshold_aad)
                    .expect("decryption share generation should succeed")
            })
            .collect();

        // Combine threshold number of shares to recover the original plaintext
        let selected_shares: Vec<_> = decryption_shares.iter().take(threshold).collect();
        let recovered_plaintext = DecryptionScheme::combine(
            &committee,
            expected_combkey,
            selected_shares,
            &ciphertext,
            &threshold_aad,
        )
        .expect("threshold decryption combination should succeed");

        assert_eq!(
            recovered_plaintext, sample_plaintext,
            "Recovered plaintext must match the original plaintext"
        );
    }

    #[tokio::test]
    /// Tests integrated DKG to ensure it terminates with consistent public encryption keys
    /// across all committee members in a networked environment.
    async fn test_dkg_termination() {
        logging::init_logging();
        let (mut decrypters, setup) = setup(
            COM1,
            &COM1_SIGNATURE_PRIVATE_KEY_STRINGS,
            &COM1_DH_PRIVATE_KEY_STRINGS,
            &COM1_DKG_PRIVATE_KEY_STRINGS,
            None,
        )
        .await;
        // Enqueuing all DKG bundles
        enqueue_all_dkg_bundles(&mut decrypters, None).await;

        // Verify all committee members derive the same public encryption keys
        let generated_keys = try_join_all(
            setup
                .dec_keys()
                .iter()
                .map(|cell| async { Ok::<_, ()>(cell.read().await) }),
        )
        .await
        .expect("keys should be generated");

        let expected_public_key = generated_keys[0].pubkey();
        for (index, key) in generated_keys.iter().enumerate().skip(1) {
            assert_eq!(
                key.pubkey(),
                expected_public_key,
                "Node {index} has mismatched public key"
            );
        }
    }

    #[tokio::test]
    /// Tests the complete DKG and decryption phase end-to-end flow in a networked environment.
    /// Verifies that encrypted transactions can be properly decrypted after DKG completion.
    async fn test_dkg_and_decryption_phase_e2e() {
        run_dkg_and_decryption_phase_e2e(false).await;
    }

    #[tokio::test]
    /// Tests the complete DKG and decryption phase end-to-end flow in a networked environment.
    /// Verifies that encrypted transactions can be properly decrypted after DKG completion.
    /// The node that is catching up will not have the dealings locally enqueued but will instead
    /// fetch the dealings from other nodes to obtain the DKG key material.
    async fn test_dkg_and_decryption_phase_e2e_with_catchup() {
        run_dkg_and_decryption_phase_e2e(true).await;
    }

    #[tokio::test]
    /// Tests the full spectrum of Decrypter states:
    /// 1. Initial committee completes dkg and decrypts transactions.
    /// 2. NextCommittee and UseCommittee events are triggered adding nodes to the network.
    /// 3. Resharing is done in the background among new/old committee members.
    /// 4. Old committee decrypts its last inclusion list triggering committee switch.
    /// 5. New committee decrypts its first inclusion list using key from resharing.
    async fn run_dkg_handover_decryption_phase_e2e() {
        logging::init_logging();

        let (mut com1_decrypters, com1_setup) = setup(
            COM1,
            &COM1_SIGNATURE_PRIVATE_KEY_STRINGS,
            &COM1_DH_PRIVATE_KEY_STRINGS,
            &COM1_DKG_PRIVATE_KEY_STRINGS,
            None,
        )
        .await;

        let (mut com2_decrypters, com2_setup) = setup(
            COM2,
            &COM2_SIGNATURE_PRIVATE_KEY_STRINGS,
            &COM2_DH_PRIVATE_KEY_STRINGS,
            &COM2_DKG_PRIVATE_KEY_STRINGS,
            Some(com1_setup.clone()),
        )
        .await;

        let com1_round = RoundNumber::new(DECRYPTION_ROUND);
        let com2_round = RoundNumber::new(DECRYPTION_ROUND + 1);

        enqueue_all_dkg_bundles(&mut com1_decrypters, None).await;

        for cell in com1_setup.dec_keys() {
            cell.read().await;
        }

        let encryption_key = com1_setup.dec_keys()[0]
            .get()
            .expect("encryption key should be generated after DKG");

        // trigger NextCommittee event at each decrypter in COM1
        for decrypter in com1_decrypters.iter_mut() {
            decrypter
                .next_committee(
                    com2_setup.addr_comm().clone(),
                    com2_setup.key_store().clone(),
                )
                .await
                .expect("next committee event succeeds");
        }

        // enqueue resharing bundles (for COM2) at each decrypter in COM1
        enqueue_all_dkg_bundles(&mut com1_decrypters, Some(com2_setup.key_store().clone())).await;

        // make sure that all nodes in COM2 consider resharing complete
        for cell in com2_setup.dec_keys() {
            cell.read().await;
        }

        // trigger UseCommittee event for both COM1 and COM2
        for decrypter in com1_decrypters.iter_mut().chain(com2_decrypters.iter_mut()) {
            decrypter
                .use_committee(Round::new(com2_round, COM2))
                .await
                .expect("use committee event succeeds");
        }

        let priority_tx_message = b"Priority message for old committee";
        let regular_tx_message = b"Non-priority message for old committee";

        let encrypted_inclusion_list = create_encrypted_inclusion_list(
            com1_round,
            com1_setup.addr_comm().committee().clone(),
            com1_setup.sig_keys(),
            encryption_key.pubkey(),
            priority_tx_message,
            regular_tx_message,
        );

        // enqueues the same inclusion list to all nodes in COM1
        for decrypter in com1_decrypters.iter_mut() {
            decrypter
                .enqueue(encrypted_inclusion_list.clone())
                .await
                .expect("Inclusion list should be enqueued successfully");
        }

        let _ = collect_inclusion_lists(&mut com1_decrypters).await;

        let priority_tx_message = b"Priority message for new committee";
        let regular_tx_message = b"Non-priority message for new committee";

        let encrypted_inclusion_list = create_encrypted_inclusion_list(
            com2_round,
            com2_setup.addr_comm().committee().clone(),
            com2_setup.sig_keys(),
            encryption_key.pubkey(), // same encryption key
            priority_tx_message,
            regular_tx_message,
        );

        for new_decrypter in com2_decrypters.iter_mut() {
            new_decrypter
                .enqueue(encrypted_inclusion_list.clone())
                .await
                .expect("Inclusion list should be enqueued successfully");
        }

        let decrypted_inclusion_lists = collect_inclusion_lists(&mut com2_decrypters).await;

        // Verify that all decrypted inclusion lists are correct
        for decrypted_list in decrypted_inclusion_lists {
            assert_eq!(
                decrypted_list.round(),
                com2_round,
                "Decrypted list should have the expected round number"
            );
            assert_eq!(
                decrypted_list.priority_bundles().len(),
                1,
                "Should have exactly one priority bundle"
            );
            assert_eq!(
                decrypted_list.regular_bundles().len(),
                1,
                "Should have exactly one regular bundle"
            );

            let decrypted_priority_data = decrypted_list.priority_bundles()[0].bundle().data();
            let decrypted_regular_data = decrypted_list.regular_bundles()[0].data();

            assert_eq!(
                decrypted_priority_data.to_vec(),
                priority_tx_message.to_vec(),
                "Decrypted priority transaction should match original"
            );
            assert_eq!(
                decrypted_regular_data.to_vec(),
                regular_tx_message.to_vec(),
                "Decrypted regular transaction should match original"
            );
        }
    }

    /// Helper to run DKG and decryption phase E2E test.
    async fn run_dkg_and_decryption_phase_e2e(catchup: bool) {
        logging::init_logging();

        let (mut decrypters, setup) = setup(
            COM1,
            &COM1_SIGNATURE_PRIVATE_KEY_STRINGS,
            &COM1_DH_PRIVATE_KEY_STRINGS,
            &COM1_DKG_PRIVATE_KEY_STRINGS,
            None,
        )
        .await;
        if catchup {
            // Only use the first 4 decrypters for catchup scenario.
            enqueue_all_dkg_bundles(&mut decrypters[..4], None).await;
        } else {
            enqueue_all_dkg_bundles(&mut decrypters, None).await;
        }

        for cell in setup.dec_keys() {
            cell.read().await;
        }

        let encryption_key = setup.dec_keys()[0]
            .get()
            .expect("encryption key should be generated after DKG");

        // Phase 2: Encrypted transaction testing
        let priority_tx_message = b"The quick brown fox jumps over the lazy dog";
        let regular_tx_message = b"The slow brown fox jumps over the lazy dog";

        let decryption_round = RoundNumber::new(DECRYPTION_ROUND);
        let encrypted_inclusion_list = create_encrypted_inclusion_list(
            decryption_round,
            setup.addr_comm().committee().clone(),
            setup.sig_keys(),
            encryption_key.pubkey(),
            priority_tx_message,
            regular_tx_message,
        );

        // Enqueues the same inclusion list to all decrypters for processing.
        for decrypter in decrypters.iter_mut() {
            decrypter
                .enqueue(encrypted_inclusion_list.clone())
                .await
                .expect("Inclusion list should be enqueued successfully");
        }

        let decrypted_inclusion_lists = collect_inclusion_lists(&mut decrypters).await;

        // Verify that all decrypted inclusion lists are correct
        for decrypted_list in decrypted_inclusion_lists {
            assert_eq!(
                decrypted_list.round(),
                RoundNumber::new(DECRYPTION_ROUND),
                "Decrypted list should have the expected round number"
            );
            assert_eq!(
                decrypted_list.priority_bundles().len(),
                1,
                "Should have exactly one priority bundle"
            );
            assert_eq!(
                decrypted_list.regular_bundles().len(),
                1,
                "Should have exactly one regular bundle"
            );

            let decrypted_priority_data = decrypted_list.priority_bundles()[0].bundle().data();
            let decrypted_regular_data = decrypted_list.regular_bundles()[0].data();

            assert_eq!(
                decrypted_priority_data.to_vec(),
                priority_tx_message.to_vec(),
                "Decrypted priority transaction should match original"
            );
            assert_eq!(
                decrypted_regular_data.to_vec(),
                regular_tx_message.to_vec(),
                "Decrypted regular transaction should match original"
            );
        }
    }

    /// Generate all DKG bundle (one per decrypter) then enqueue all bundles at all decrypters
    async fn enqueue_all_dkg_bundles(decrypters: &mut [Decrypter], key_store: Option<KeyStore>) {
        let bundles = if let Some(key_store) = key_store {
            decrypters
                .iter_mut()
                .map(|decrypter| {
                    decrypter
                        .gen_resharing_bundle(key_store.clone())
                        .expect("DKG bundle should be generated")
                })
                .collect::<VecDeque<_>>()
        } else {
            decrypters
                .iter_mut()
                .map(|decrypter| {
                    decrypter
                        .gen_dkg_bundle()
                        .expect("DKG bundle should be generated")
                })
                .collect::<VecDeque<_>>()
        };

        // enqueuing them all to decrypters
        for decrypter in decrypters.iter_mut() {
            for dkg in bundles.clone() {
                decrypter
                    .enqueue_dkg(dkg)
                    .await
                    .expect("DKG bundles should be enqueued successfully");
            }
        }
    }

    /// Creates round evidence by having all committee members sign the previous round.
    /// This evidence is required to validate the legitimacy of the current round.
    fn create_round_evidence(
        committee: Committee,
        signature_keys: &[SecretKey],
        previous_round: Round,
    ) -> Evidence {
        let mut vote_accumulator = VoteAccumulator::new(committee);

        for secret_key in signature_keys {
            let keypair = Keypair::from(secret_key.clone());
            let signed_round = Signed::new(previous_round, &keypair);
            vote_accumulator
                .add(signed_round)
                .expect("Vote should be added successfully");
        }

        let certificate = vote_accumulator
            .into_certificate()
            .expect("Certificate should be created successfully");
        certificate.into()
    }

    /// Collects processed inclusion lists from all decrypters.
    /// This simulates gathering the results after decryption processing.
    async fn collect_inclusion_lists(decrypters: &mut [Decrypter]) -> Vec<InclusionList> {
        let mut processed_lists = Vec::with_capacity(decrypters.len());
        for decrypter in decrypters.iter_mut() {
            let processed_list = decrypter
                .next()
                .await
                .expect("Processed inclusion list should be available");
            processed_lists.push(processed_list);
        }
        processed_lists
    }

    /// Creates an inclusion list with encrypted priority and regular transactions.
    /// This simulates the second phase where encrypted transactions are processed.
    fn create_encrypted_inclusion_list(
        round: RoundNumber,
        committee: Committee,
        signature_keys: &[SecretKey],
        encryption_key: &ThresholdEncKey,
        priority_message: &[u8],
        regular_message: &[u8],
    ) -> InclusionList {
        let previous_round = Round::new(round - 1, committee.id());
        let evidence = create_round_evidence(committee, signature_keys, previous_round);

        // Encrypt both message types
        let priority_plaintext = Plaintext::new(priority_message.to_vec());
        let regular_plaintext = Plaintext::new(regular_message.to_vec());

        let priority_ciphertext = DecryptionScheme::encrypt(
            &mut test_rng(),
            encryption_key,
            &priority_plaintext,
            &THRES_AAD.to_vec(),
        )
        .expect("Priority transaction encryption should succeed");

        let regular_ciphertext = DecryptionScheme::encrypt(
            &mut test_rng(),
            encryption_key,
            &regular_plaintext,
            &THRES_AAD.to_vec(),
        )
        .expect("Regular transaction encryption should succeed");

        let priority_ciphertext_bytes =
            bincode::serde::encode_to_vec(&priority_ciphertext, bincode::config::standard())
                .expect("Priority ciphertext encoding should succeed");

        let regular_ciphertext_bytes =
            bincode::serde::encode_to_vec(&regular_ciphertext, bincode::config::standard())
                .expect("Regular ciphertext encoding should succeed");

        // Create inclusion list with encrypted transaction bundles
        let mut inclusion_list = InclusionList::new(round, Timestamp::now(), 0.into(), evidence);
        let chain_id = ChainId::from(TEST_CHAIN_ID);
        let epoch = Epoch::from(TEST_EPOCH);
        let auction_address = Address::default();
        let sequence_number = SeqNo::from(TEST_SEQNO);
        let default_signer = Signer::default();

        // Create priority bundle with encrypted data
        let priority_bundle = PriorityBundle::new(
            Bundle::new(chain_id, epoch, priority_ciphertext_bytes.into(), true),
            auction_address,
            sequence_number,
        );
        let signed_priority_bundle = priority_bundle
            .sign(default_signer)
            .expect("Priority bundle signing should succeed");

        // Create regular bundle with encrypted data
        let regular_bundle = Bundle::new(
            chain_id,
            epoch,
            regular_ciphertext_bytes.into(),
            true, // is_encrypted = true
        );

        inclusion_list.set_priority_bundles(vec![signed_priority_bundle]);
        inclusion_list.set_regular_bundles(vec![regular_bundle]);
        inclusion_list
    }

    #[derive(Clone)]
    struct DecrypterSetup {
        dec_keys: Vec<DecryptionKeyCell>,
        addr_comm: AddressableCommittee,
        key_store: KeyStore,
        sig_keys: Vec<SecretKey>,
    }

    impl DecrypterSetup {
        pub fn new(
            dec_keys: Vec<DecryptionKeyCell>,
            addr_comm: AddressableCommittee,
            key_store: KeyStore,
            sig_keys: Vec<SecretKey>,
        ) -> Self {
            Self {
                dec_keys,
                addr_comm,
                key_store,
                sig_keys,
            }
        }

        pub fn dec_keys(&self) -> &Vec<DecryptionKeyCell> {
            &self.dec_keys
        }

        pub fn addr_comm(&self) -> &AddressableCommittee {
            &self.addr_comm
        }

        pub fn key_store(&self) -> &KeyStore {
            &self.key_store
        }

        pub fn sig_keys(&self) -> &Vec<SecretKey> {
            &self.sig_keys
        }
    }

    async fn setup(
        committee_id: u64,
        sig_keys: &[&str],
        dh_keys: &[&str],
        dkg_keys: &[&str],
        prev_setup: Option<DecrypterSetup>,
    ) -> (Vec<Decrypter>, DecrypterSetup) {
        // Parse all key types from their string representations
        let signature_keys: Vec<_> = sig_keys
            .iter()
            .map(|key_str| SecretKey::try_from(*key_str).expect("Valid signature key string"))
            .collect();

        let dh_keys: Vec<_> = dh_keys
            .iter()
            .map(|key_str| x25519::SecretKey::try_from(*key_str).expect("Valid DH key string"))
            .collect();

        let dkg_keys: Vec<_> = dkg_keys
            .iter()
            .map(|key_str| {
                DkgDecKey::deserialize(StrDeserializer::<serde::de::value::Error>::new(key_str))
                    .expect("Valid DKG key string")
            })
            .collect();

        // Create committee from signature keys
        let committee = Committee::new(
            committee_id,
            signature_keys
                .iter()
                .enumerate()
                .map(|(index, secret_key)| (KeyId::from(index as u8), secret_key.public_key()))
                .collect::<Vec<_>>(),
        );

        // Create DKG key store with committee and DKG public keys
        let key_store = KeyStore::new(
            committee.clone(),
            dkg_keys
                .iter()
                .enumerate()
                .map(|(index, dkg_key)| (KeyId::from(index as u8), DkgEncKey::from(dkg_key))),
        );

        // Set up network peers with available ports
        let mut network_peers = Vec::new();
        for (sig_key, dh_key) in signature_keys.iter().zip(&dh_keys) {
            let available_port = alloc_port().await.unwrap();
            let sig_key = sig_key.public_key();
            let dh_key = dh_key.public_key();
            network_peers.push((
                sig_key,
                dh_key,
                SocketAddr::from((Ipv4Addr::LOCALHOST, available_port)),
            ))
        }

        let addressable_committee =
            AddressableCommittee::new(committee.clone(), network_peers.clone());
        let mut decrypters = Vec::with_capacity(COMMITTEE_SIZE);
        let mut encryption_key_cells = Vec::with_capacity(COMMITTEE_SIZE);

        // Create decrypter instances for each committee member
        for peer_index in 0..network_peers.len() {
            let signature_key = signature_keys[peer_index].clone();
            let dh_key = dh_keys[peer_index].clone();
            let (_, _, network_address) = network_peers[peer_index];
            let encryption_key_cell = DecryptionKeyCell::new();
            let decrypter_config = DecrypterConfig::builder()
                .label(signature_key.public_key())
                .address(network_address.into())
                .dh_keypair(dh_key.into())
                .dkg_key(dkg_keys[peer_index].clone())
                .committee((addressable_committee.clone(), key_store.clone()))
                .maybe_prev_committee(
                    prev_setup
                        .clone()
                        .map(|s| (s.addr_comm().clone(), s.key_store().clone())),
                )
                .retain(RETAIN_ROUNDS)
                .threshold_dec_key(encryption_key_cell.clone())
                .build();

            let decrypter = Decrypter::new(
                decrypter_config,
                &NoMetrics,
                Arc::new(SequencerMetrics::default()),
            )
            .await
            .expect("Decrypter creation should succeed");
            decrypters.push(decrypter);
            encryption_key_cells.push(encryption_key_cell);
        }

        (
            decrypters,
            DecrypterSetup::new(
                encryption_key_cells,
                addressable_committee,
                key_store,
                signature_keys,
            ),
        )
    }
}

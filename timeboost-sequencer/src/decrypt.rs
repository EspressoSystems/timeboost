use ark_std::{UniformRand, rand::thread_rng};
use arrayvec::ArrayVec;
use bon::Builder;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{
    AddressableCommittee, MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics, Role,
};
use multisig::{Committee, CommitteeId, PublicKey};
use parking_lot::RwLock;
use sailfish::types::{CommitteeVec, Evidence, Round, RoundNumber};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::result::Result as StdResult;
use std::sync::Arc;
use timeboost_crypto::prelude::{LabeledDkgDecKey, ThresholdEncKeyCell, Vess, Vss};
use timeboost_crypto::traits::dkg::VerifiableSecretSharing;
use timeboost_crypto::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};
use timeboost_crypto::vess::ShoupVess;
use timeboost_crypto::{DecryptionScheme, Plaintext};
use timeboost_types::{DecryptionKey, DkgAccumulator, DkgBundle, DkgKeyStore, InclusionList};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, error, info, trace, warn};

use crate::config::DecrypterConfig;
use crate::metrics::SequencerMetrics;

type Result<T> = StdResult<T, DecrypterError>;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;
type DecSharesCache = BTreeMap<RoundNumber, HashMap<Round, Vec<Vec<Option<DecShare>>>>>;

/// Command sent to Decrypter's background worker
enum Command {
    // request to inform the worker of DKG bundle (one dealing at a time)
    Dkg(DkgBundle),
    // request to decrypt all encrypted transactions inside the inclusion list
    Decrypt(InclusionList),
    /// Prepare for the next committee.
    NextCommittee(AddressableCommittee),
    /// Use a committee starting at the given round.
    UseCommittee(Round),
    // request to garbage collect all states related to a round (and previous rounds)
    Gc(RoundNumber),
}

/// Inclusion list with status
enum Status {
    Encrypted,
    Decrypted(InclusionList),
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
    /// Public key of the node. "Label" is termed to refer to node identity in SG01 decryption
    /// scheme
    label: PublicKey,
    /// Locally stored incl lists: those still unencrypted and those yet fetched by the next phase
    /// of timeboost
    incls: BTreeMap<RoundNumber, Status>,
    /// Sender end of the worker commands
    worker_tx: Sender<Command>,
    /// Receiver end of the worker response
    worker_rx: Receiver<InclusionList>,
    /// Worker task handle.
    worker: JoinHandle<EndOfPlay>,
    /// Set of committees for which DKG bundle has already been submitted.
    submitted: BTreeSet<CommitteeId>,
    /// decryption committees
    committees: CommitteeVec<2>,
    /// dkg stores (shared with Worker)
    dkg_stores: Arc<RwLock<ArrayVec<DkgKeyStore, 2>>>,
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
        let (cmd_tx, cmd_rx) = channel(cfg.retain);
        let (dec_tx, dec_rx) = channel(cfg.retain);
        let net_metrics = NetworkMetrics::new("decrypt", metrics, cfg.committee.parties().copied());

        let net = Network::create(
            "decrypt",
            cfg.address.clone(),
            cfg.label,
            cfg.dh_keypair.clone(),
            cfg.committee.entries(),
            net_metrics,
        )
        .await
        .map_err(DecrypterError::Net)?;

        let labeled_sk = cfg.dkg_key.label(
            cfg.committee
                .committee()
                .get_index(&cfg.label)
                .ok_or_else(|| {
                    DecrypterError::Internal(format!("missing key id for {}", cfg.label))
                })?
                .into(),
        );

        if cfg.dkg_store.committee().id() != cfg.committee.committee().id() {
            return Err(DecrypterError::Internal(
                "Wrong committee in DkgKeyStore".to_string(),
            ));
        }
        let dkg_stores = Arc::new(RwLock::new({
            let mut arr = ArrayVec::new();
            arr.push(cfg.dkg_store);
            arr
        }));
        let committee = cfg.committee.committee();
        let worker = Worker::builder()
            .label(cfg.label)
            .dkg_sk(Arc::new(labeled_sk))
            .committees(CommitteeVec::new(committee.clone()))
            .dkg_stores(dkg_stores.clone())
            .current(committee.id())
            .net(Overlay::new(net))
            .tx(dec_tx)
            .rx(cmd_rx)
            .enc_key(cfg.threshold_enc_key.clone())
            .retain(cfg.retain)
            .build();

        Ok(Self {
            label: cfg.label,
            incls: BTreeMap::new(),
            worker_tx: cmd_tx,
            worker_rx: dec_rx,
            submitted: BTreeSet::default(),
            worker: spawn(worker.go()),
            committees: CommitteeVec::new(committee.clone()),
            dkg_stores: dkg_stores.clone(),
            current: committee.id(),
            metrics: seq_metrics,
        })
    }

    /// Check if the channels between decrypter and its core worker still have capacity left
    pub fn has_capacity(&mut self) -> bool {
        self.worker_tx.capacity() > 0 && self.worker_rx.capacity() > 0
    }

    /// Returns the currently active decryption committee
    pub fn current_committee(&self) -> &Committee {
        self.committees
            .get(self.current)
            .expect("current decryption committee missing")
    }

    /// Garbage collect cached state of `r` (and prior) rounds
    pub async fn gc(&mut self, r: RoundNumber) -> StdResult<(), DecrypterDown> {
        self.worker_tx
            .send(Command::Gc(r))
            .await
            .map_err(|_| DecrypterDown(()))
    }

    /// Send the inclusion list to worker to decrypt if it contains encrypted bundles,
    /// Else append to local cache waiting to be pulled.
    ///
    /// If the inclusion list contains dealings then the list is forwarded to the worker.
    ///
    /// decrypter will process any encrypted/unencrypted inclusion list
    pub async fn enqueue(&mut self, incl: InclusionList) -> StdResult<(), DecrypterDown> {
        let round = incl.round();

        if incl.is_encrypted() {
            self.worker_tx
                .send(Command::Decrypt(incl))
                .await
                .map_err(|_| DecrypterDown(()))?;
            self.incls.insert(round, Status::Encrypted);

            debug!(node = %self.label, %round, "enqueued encrypted inclusion list");
            self.metrics.queued_encrypted.update(1);
        } else {
            self.incls.insert(round, Status::Decrypted(incl));
            debug!(node = %self.label, %round, "enqueued non-encrypted inclusion list");
        }

        Ok(())
    }

    /// Send the received DKG bundles to worker
    pub async fn enqueue_dkg(
        &self,
        pending_dkgs: &mut VecDeque<DkgBundle>,
    ) -> StdResult<(), DecrypterDown> {
        while let Some(b) = pending_dkgs.pop_front() {
            self.worker_tx
                .send(Command::Dkg(b))
                .await
                .map_err(|_| DecrypterDown(()))?;
            debug!(node = %self.label, "enqueued one dkg bundle");
        }
        Ok(())
    }

    /// Generates and returns a new DKG bundle for the current committee, if not already submitted.
    ///
    /// # Returns
    /// - `Some(DkgBundle)` if a new DKG dealing was successfully created for the current committee.
    /// - `None` if already submitted or if encryption keys are missing.
    pub fn gen_dkg_bundle(&mut self) -> Option<DkgBundle> {
        let committee = self.current_committee();
        let committee_id = committee.id();
        if self.submitted.contains(&committee_id) {
            trace!(node = %self.label, committee = %committee_id, "dkg bundle already submitted");
            return None;
        }
        let stores = self.dkg_stores.read();
        let Some(store) = stores.iter().find(|s| s.committee().id() == committee_id) else {
            warn!(node = %self.label, committee = %committee_id, "missing dkg store");
            return None;
        };
        let vess = Vess::new_fast_from(committee);

        let mut rng = thread_rng();
        let secret = <Vss as VerifiableSecretSharing>::Secret::rand(&mut rng);
        let (ct, cm) = vess
            .encrypted_shares(store.sorted_keys(), secret, b"dkg")
            .ok()?;
        self.submitted.insert(committee_id);
        Some(DkgBundle::new(committee_id, ct, cm))
    }

    /// Produces decrypted inclusion lists ordered by round number
    pub async fn next(&mut self) -> StdResult<InclusionList, DecrypterDown> {
        // first try to return the first inclusion list if it's already decrypted
        if let Some(entry) = self.incls.first_entry() {
            if matches!(entry.get(), Status::Decrypted(_)) {
                if let Status::Decrypted(incl) = entry.remove() {
                    return Ok(incl);
                }
            }
        }

        // normal loop: try to receive the next decrypted inclusion list
        while let Some(dec_incl) = self.worker_rx.recv().await {
            let round = dec_incl.round();
            // update decrypter cache of inclusion list
            debug!(
                node  = %self.label,
                round = %round,
                epoch = %dec_incl.epoch(),
                "inclusion list decrypted"
            );
            debug_assert!(
                !dec_incl.is_encrypted(),
                "decrypter worker returns non-decrypted inclusion list"
            );
            self.incls.insert(round, Status::Decrypted(dec_incl));
            self.metrics.output_decrypted.update(1);

            // since the newly finished/responded inclusion list might belong to a later round
            // the first entry might still be unencrypted, in which case continue the loop and
            // wait until the worker finishes decrypting it.
            if let Some(entry) = self.incls.first_entry() {
                if matches!(entry.get(), Status::Decrypted(_)) {
                    if let Status::Decrypted(incl) = entry.remove() {
                        return Ok(incl);
                    }
                } else {
                    debug!(node = %self.label, round = %entry.key(), "awaiting decryption of")
                }
            }
        }
        Err(DecrypterDown(()))
    }

    /// Prepare for the next committee.
    pub async fn next_committee(
        &mut self,
        c: AddressableCommittee,
    ) -> StdResult<(), DecrypterDown> {
        debug!(node = %self.label, committee = %c.committee().id(), "next committee");
        self.worker_tx
            .send(Command::NextCommittee(c))
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

/// Worker is responsible for "hatching" ciphertexts.
///
/// When ciphertexts in a round have received t+1 decryption shares
/// the shares can be combined to decrypt the ciphertext (hatching).
#[derive(Builder)]
struct Worker {
    /// labeling the node by its signing/consensus public key
    label: PublicKey,

    /// overlay network to connect to other decrypters
    net: Overlay,

    /// decryption committees
    committees: CommitteeVec<2>,

    /// Current committee.
    current: CommitteeId,

    /// The next committee to use, if any.
    next_committee: Option<Round>,

    /// channel for sending inclusion lists back to parent
    tx: Sender<InclusionList>,

    /// channel for receiving commands from the parent
    rx: Receiver<Command>,

    /// pending encryption key that will be updated after DKG/resharing is done
    enc_key: ThresholdEncKeyCell,

    /// round number of the first decrypter request, used to ignore received decryption shares for
    /// eariler rounds
    first_requested_round: Option<RoundNumber>,

    /// decryption key used in the DKG or key resharing for secure communication between nodes
    dkg_sk: Arc<LabeledDkgDecKey>,

    /// public key material encrypted DKG bundles (shared with Decrypter)
    dkg_stores: Arc<RwLock<ArrayVec<DkgKeyStore, 2>>>,

    /// decryption key used to decrypt and combine
    /// At system start-up (or new committee handover), DKG/resharing needs a few rounds to finish
    /// during which time the threshold key is None
    dec_sk: Option<DecryptionKey>,

    /// Number of rounds to retain.
    retain: usize,

    /// Tracker for Dkg bundles received through candidate lists.
    #[builder(default)]
    dkg_tracker: Arc<RwLock<BTreeMap<CommitteeId, DkgAccumulator>>>,

    /// JoinHandle of running threads for processing incoming DKG bundle, which might take a while
    /// Each working task will return the cid and potential finalized decryption key if DKG
    /// finishes
    #[builder(default)]
    dkg_workers: JoinSet<Result<(CommitteeId, Option<DecryptionKey>)>>,

    /// Committees for which Dkg has already been completed.
    #[builder(default)]
    dkg_completed: BTreeSet<CommitteeId>,

    /// cache of decrypted shares (keyed by round), each entry value is a nested vector: an
    /// ordered list of per-ciphertext decryption shares. the order is derived from the
    /// ciphertext payload from the inclusion list `self.incls` of the same round
    ///
    /// note: Option<DecShare> uses None to indicate a failed to decrypt ciphertext
    #[builder(default)]
    dec_shares: DecSharesCache,

    /// Acknowledgement of the set of peers whose decryption share for a round has been received
    /// Useful to prevent DOS or DecShareBatch flooding by malicious peers
    #[builder(default)]
    acks: BTreeMap<RoundNumber, HashSet<PublicKey>>,

    /// cache of encrypted inclusion list waiting to be hatched using `dec_shares`
    #[builder(default)]
    incls: BTreeMap<RoundNumber, InclusionList>,

    /// The local clock, driven by round number.
    #[builder(default = RoundNumber::genesis())]
    clock: RoundNumber,

    /// the latest rounds whose ciphertexts are hatched
    #[builder(default = RoundNumber::genesis())]
    last_hatched_round: RoundNumber,
}

impl Worker {
    // entry point of `worker` thread, it runs in a loop until shutdown or out of channel capacity.
    pub async fn go(mut self) -> EndOfPlay {
        let node = self.label;

        loop {
            // each event loop is triggered by receiving one of the following
            // - batch of decrypted shares from other decrypters
            // - a new request from Decrypter
            tokio::select! {
                // receiving a batch of decrypted shares from other decrypters
                msg = self.net.receive() => match msg {
                    Ok((src, data)) => {
                        match self.on_message(src, data).await {
                            Ok(()) => {}
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
                // one of the DKG processing is done
                Some(res) = self.dkg_workers.join_next() => match res {
                    Ok(inner_res) => { match inner_res {
                        // we update finalized DKG result outside of `on_dkg_request()`
                        // to save from complicating types of mutable variables for thread-safety
                        Ok((cid, k)) => {if let Some(dec_sk) = k {
                            self.enc_key.set(dec_sk.pubkey().clone());
                            self.dec_sk = Some(dec_sk);
                            self.dkg_completed.insert(cid);
                            info!(committee_id = %cid, node = %self.label, "DKG finished");

                            // TODO(resharing): if cid is for the next committee
                            // send the resulting subset to (passive) nodes in the new committee
                        }}
                        Err(DecrypterError::End(end)) => return end,
                        Err(err) => warn!(node = %self.label, %err, "error on dkg request")
                    }},
                    Err(err) => warn!(node = %self.label, %err, "join error on dkg task"),
                },
                // receiving a request from the decrypter
                cmd = self.rx.recv() => match cmd {
                    Some(Command::Dkg(b)) => {
                        // we check DKG completion status outside of `on_dkg_request()`
                        // to save from complicating `dkg_completed` types for thread-safety
                        let cid = b.committee_id();
                        if self.dkg_completed.contains(cid) {
                            trace!(
                                node = %self.label,
                                committee_id = %cid,
                                "received bundle but dkg already completed"
                            );
                            continue;
                        }

                        let dkg_stores = self.dkg_stores.clone();
                        let dkg_tracker = self.dkg_tracker.clone();
                        let dkg_sk = self.dkg_sk.clone();

                        self.dkg_workers.spawn_blocking(move || {
                            Self::on_dkg_request(dkg_stores, dkg_tracker, dkg_sk, b)
                        });
                        trace!(%node, "spawn a dkg processing task");
                        continue;
                    },
                    Some(Command::Decrypt(incl)) => {
                        let round = incl.round();
                        trace!(%node, %round, "decrypt request");
                        match self.on_decrypt_request(incl).await {
                            Ok(()) => {}
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
                        continue;
                    },
                    Some(Command::NextCommittee(c)) =>
                        match self.on_next_committee(c).await {
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

            // workers don't have to hatch for unrequested rounds.
            if self.first_requested_round.is_none() {
                continue;
            }

            // when processing the incoming event (all steps above), we already early-return and
            // continue the loop if any intermediate steps error. If they succeed, then
            // some local decryption shares must have been updated, thus we try to hatch them.
            let round = self.oldest_cached_round();
            match self.hatch(round) {
                Ok(Some(incl)) => {
                    if let Err(err) = self.tx.send(incl.clone()).await {
                        error!(%node, %err, "failed to send hatched inclusion list");
                        return EndOfPlay::DecrypterDown;
                    }
                    trace!(%node, %round, "hatch inclusion list... done");
                }
                Err(err) => warn!(%node, %round, %err, "failed to hatch"),
                Ok(None) => continue,
            }
        }
    }

    /// A batch of decryption shares from another node has been received.
    async fn on_message(&mut self, src: PublicKey, data: Bytes) -> Result<()> {
        debug!(node = %self.label, %src, "incoming message");
        // ignore msg sent to self during broadcast
        if src == self.label {
            return Ok(());
        }
        let dec_shares = deserialize::<DecShareBatch>(&data)?;
        let round = dec_shares.round.num();
        let committee_id = dec_shares.round.committee();

        let Some(committee) = self.committees.get(committee_id).cloned() else {
            return Err(DecrypterError::NoCommittee(committee_id));
        };
        if committee.get_index(&src).is_none() {
            warn!(node = %self.label, %src, "source not in committee");
            return Ok(());
        }

        // if already sent for this round, `src` will be re-inserted, thus returns false
        // in which case we skip processing this message since this peer has already sent once
        if !self.acks.entry(round).or_default().insert(src) {
            return Ok(());
        };

        if round <= self.last_hatched_round || round < self.oldest_cached_round() {
            // shares for which the ciphertexts have already hatched
            // or shares that are older than the first ciphertext in
            // the local cache are not inserted.
            return Ok(());
        }
        trace!(node = %self.label, from=%src, %round, "inserting decrypted shares");

        self.insert_shares(dec_shares)?;

        Ok(())
    }

    /// returns the oldest round number in locally cached decryption shares (w/ smallest round
    /// number)
    fn oldest_cached_round(&self) -> RoundNumber {
        self.dec_shares
            .keys()
            .next()
            .copied()
            .unwrap_or(RoundNumber::genesis())
    }

    /// DKG processing logic in a dedicated thread,
    /// contract: `dkg_completed` for `bundle.committee_id()` is ensured beforehand by the caller
    ///
    /// return: (cid, Some(dec_sk)) if accumulator finalize into the DecryptionKey, else None,
    /// where cid is the CommitteeId of the bundle processed.
    fn on_dkg_request(
        dkg_stores: Arc<RwLock<ArrayVec<DkgKeyStore, 2>>>,
        dkg_tracker: Arc<RwLock<BTreeMap<CommitteeId, DkgAccumulator>>>,
        dkg_sk: Arc<LabeledDkgDecKey>,
        bundle: DkgBundle,
    ) -> Result<(CommitteeId, Option<DecryptionKey>)> {
        let cid = bundle.committee_id().to_owned();
        let stores = dkg_stores.read();
        let Some(dkg_store) = stores.iter().find(|s| s.committee().id() == cid) else {
            return Err(DecrypterError::Dkg(format!(
                "dkg_store missing for committee_id={cid}",
            )));
        };

        let mut tracker = dkg_tracker.write();
        let acc = tracker
            .entry(cid)
            .or_insert_with(|| DkgAccumulator::new(dkg_store.to_owned()));

        acc.try_add(bundle)
            .map_err(|e| DecrypterError::Dkg(format!("unable to add dkg bundle: {e}")))?;

        if let Some(subset) = acc.try_finalize() {
            let committee = dkg_store.committee();
            // TODO:(alex) centralize these constant, redeclared in DkgAccumulator.try_add()
            let aad: &[u8; 3] = b"dkg";
            let vess = ShoupVess::new_fast_from(committee);
            let (shares, commitments) = subset
                .bundles()
                .iter()
                .map(|b| {
                    vess.decrypt_share(&dkg_sk, b.vess_ct(), aad)
                        .map(|s| (s, b.comm().clone()))
                        .map_err(|e| DecrypterError::Dkg(e.to_string()))
                })
                .collect::<Result<(Vec<_>, Vec<_>)>>()?;

            let dec_sk = DecryptionKey::from_dkg(
                committee.size().into(),
                dkg_sk.node_idx(),
                &commitments,
                &shares,
            )
            .map_err(|e| DecrypterError::Dkg(e.to_string()))?;

            Ok((cid, Some(dec_sk)))
        } else {
            Ok((cid, None))
        }
    }

    /// logic to process a decryption request
    async fn on_decrypt_request(&mut self, incl: InclusionList) -> Result<()> {
        let dec_shares = self.decrypt(&incl)?;
        if dec_shares.is_empty() {
            return Err(DecrypterError::EmptyDecShares);
        }
        let round = incl.round();
        self.clock = round;
        self.maybe_switch_committee().await?;

        self.net
            .broadcast(round.u64(), serialize(&dec_shares)?)
            .await
            .map_err(|e| DecrypterError::End(e.into()))?;
        self.insert_shares(dec_shares)?;
        self.incls.insert(round, incl);

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

    /// garbage collect internally cached state. Different from `self.on_gc_request()` which deals
    /// with incoming gc request, indicating more than just local gc, but also overlay
    /// network-wise gc.
    fn gc(&mut self, round: RoundNumber) {
        self.dec_shares.retain(|r, _| *r > round);
        self.incls.retain(|r, _| *r > round);
        self.acks.retain(|r, _| *r > round);
    }

    /// logic to garbage collect a round (and all prior rounds)
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
    fn decrypt(&mut self, incl: &InclusionList) -> Result<DecShareBatch> {
        let Some(dec_sk) = &self.dec_sk else {
            return Err(DecrypterError::DkgPending);
        };
        let round = Round::new(incl.round(), self.current);
        let dec_shares = Self::extract_ciphertexts(incl)
            .map(|optional_ct| {
                optional_ct.and_then(|ct| {
                    // TODO: (anders) consider using committee_id as part of `aad`.
                    <DecryptionScheme as ThresholdEncScheme>::decrypt(
                        dec_sk.privkey(),
                        &ct,
                        &vec![],
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

    /// update local cache of decrypted shares
    fn insert_shares(&mut self, batch: DecShareBatch) -> Result<()> {
        if batch.is_empty() {
            trace!(node = %self.label, "empty decryption share batch, skipped");
            return Err(DecrypterError::EmptyDecShares);
        }
        let round = batch.round;

        if !batch.evidence.is_valid(round.num(), &self.committees) {
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
    fn hatch(&mut self, round: RoundNumber) -> Result<Option<InclusionList>> {
        // first check if a round number is hatchable, if not, return Ok(None)
        let Some(dec_shares) = self.dec_shares.get(&round) else {
            return Ok(None);
        };
        // find the first round (num, committee) with enough valid shares to hatch
        let Some((r, committee)) = dec_shares.iter().find_map(|(r, shares)| {
            let committee = self.committees.get(r.committee())?;
            if shares.is_empty()
                || shares.iter().any(|opt_dec_shares| {
                    let valid = opt_dec_shares.iter().filter(|s| s.is_some()).count();
                    let invalid = opt_dec_shares.len() - valid;
                    valid < committee.one_honest_threshold().get()
                        && invalid < committee.quorum_size().get()
                })
            {
                None
            } else {
                Some((*r, committee.clone()))
            }
        }) else {
            return Ok(None);
        };

        // retreive ciphertext again from the original encrypted inclusion list
        let Some(incl) = self.incls.get(&round) else {
            trace!(
                node = %self.label,
                %round,
                "out-of-order delivery: ready to hatch but inclusion list yet received"
            );
            return Ok(None);
        };
        let mut incl = incl.clone();
        let ciphertexts = Self::extract_ciphertexts(&incl);

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

            if dec_shares.len() < committee.one_honest_threshold().into() {
                decrypted.push(None);
                continue;
            }

            if let Some(ct) = opt_ct {
                let aad = vec![];
                match DecryptionScheme::combine(
                    &committee,
                    self.dec_sk.as_ref().unwrap().combkey(), // TODO: (alex) deal with unready sk
                    dec_shares,
                    &ct,
                    &aad,
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

        Ok(Some(incl))
    }

    async fn on_next_committee(&mut self, c: AddressableCommittee) -> Result<()> {
        info!(node = %self.label, committee = %c.committee().id(), "add next committee");
        if self.committees.contains(c.committee().id()) {
            warn!(node = %self.label, committee = %c.committee().id(), "committee already added");
            return Ok(());
        }
        let Some(committee) = self.committees.get(self.current) else {
            error!(node = %self.label, committee = %self.current, "current committee not found");
            return Err(DecrypterError::NoCommittee(self.current));
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
        let Some(committee) = self.committees.get(self.current) else {
            error!(node = %self.label, committee = %self.current, "current committee not found");
            return Err(DecrypterError::NoCommittee(self.current));
        };
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
        self.current = start.committee();
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

    #[error("DKG/resharing not yet complete")]
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
    use metrics::NoMetrics;
    use std::{
        collections::VecDeque,
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::{Duration, Instant},
    };

    use timeboost_utils::types::logging;

    use cliquenet::AddressableCommittee;
    use multisig::{Committee, KeyId, Keypair, SecretKey, Signed, VoteAccumulator, x25519};
    use sailfish::types::{Evidence, Round, RoundNumber, UNKNOWN_COMMITTEE_ID};
    use timeboost_crypto::{
        DecryptionScheme, Plaintext,
        prelude::{DkgDecKey, DkgEncKey, ThresholdEncKey, ThresholdEncKeyCell, Vess, Vss},
        traits::{dkg::VerifiableSecretSharing, threshold_enc::ThresholdEncScheme},
    };
    use timeboost_types::{
        Address, Bundle, ChainId, DkgKeyStore, Epoch, InclusionList, PriorityBundle, SeqNo, Signer,
        Timestamp,
    };

    use crate::{config::DecrypterConfig, decrypt::Decrypter, metrics::SequencerMetrics};

    // Test constants
    const COMMITTEE_SIZE: usize = 5;
    const DKG_AAD: &[u8] = b"dkg";
    const THRESHOLD_AAD: &[u8] = b"threshold";
    const DECRYPTION_ROUND: u64 = 42;
    const TEST_EPOCH: u64 = 42;
    const TEST_CHAIN_ID: u64 = 0;
    const TEST_SEQNO: u64 = 10;
    const NETWORK_SETUP_DELAY_SECS: u64 = 1;
    const DKG_TERMINATION_DELAY_SECS: f32 = 3.5;
    const RETAIN_ROUNDS: usize = 100;

    // Pre-generated deterministic keys for consistent testing
    // Generated via: `just mkconfig_local 5 --seed 42`
    const SIGNATURE_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "3hzb3bRzn3dXSV1iEVE6mU4BF2aS725s8AboRxLwULPp",
        "FWJzNGvEjFS3h1N1sSMkcvvroWwjT5LQuGkGHu9JMAYs",
        "2yWTaC6MWvNva97t81cd9QX5qph68NnB1wRVwAChtuGr",
        "CUpkbkn8bix7ZrbztPKJwu66MRpJrc1Wr2JfdrhetASk",
        "6LMMEuoPRCkpDsnxnANCRCBC6JagdCHs2pjNicdmQpQE",
    ];

    const DH_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "BB3zUfFQGfw3sL6bpp1JH1HozK6ehEDmRGoiCpQH62rZ",
        "4hjtciEvuoFVT55nAzvdP9E76r18QwntWwFoeginCGnP",
        "Fo2nYV4gE9VfoVW9bSySAJ1ZuKT461x6ovZnr3EecCZg",
        "5KpixkV7czZTDVh7nV7VL1vGk4uf4kjKidDWq34CJx1T",
        "39wAn3bQzpn19oa8CiaNUFd8GekQAJMMuzrbp8Jt3FKz",
    ];

    const DKG_PRIVATE_KEY_STRINGS: [&str; COMMITTEE_SIZE] = [
        "AgrGYiNQMqPpLgwPTuCV5aww6kpcoAQnf4xuFukTEtkL1",
        "Afn2hPWpcvMnRp7uRdPPpmTMgjgJfejjULpg7wr5v62qt",
        "AcTyyLHHyWsy1B4DVGsmBXkxu3JR8ZLZfE2LC4XTjTzdM",
        "AdGeUNYGN7B3X2XpNbj147rsqaVYSYeEAjYgWdSBPGSBw",
        "Amc4mvBfcBDsQziud5cvm1i9RnJ5KQRXNdNetq4fsJb76",
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

        let vess = Vess::new_fast_from(&committee);

        // Generate dealings: each committee member contributes a random secret
        let start = Instant::now();
        let dealings: Vec<_> = (0..COMMITTEE_SIZE)
            .map(|_| {
                let secret = <Vss as VerifiableSecretSharing>::Secret::rand(&mut rng);
                vess.encrypted_shares(&dkg_public_keys, secret, &dkg_aad)
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
            vess.verify(dkg_public_keys.iter(), ct, comm, &dkg_aad)
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
                        vess.decrypt_share(&labeled_secret_key, ciphertext, &dkg_aad)
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
                super::DecryptionKey::from_dkg(COMMITTEE_SIZE, node_idx, &commitments, shares)
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
        let threshold_aad = THRESHOLD_AAD.to_vec();
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
        let (enc_key_cells, _committee, mut decrypters, _signature_keys) = setup().await;

        // Enqueuing all DKG bundles
        enqueue_all_dkg_bundles(&mut decrypters).await;

        // Allow time for DKG bundles to be processed
        tokio::time::sleep(Duration::from_secs_f32(DKG_TERMINATION_DELAY_SECS)).await;

        // Verify all committee members derive the same public encryption keys
        let generated_keys: Vec<_> = enc_key_cells
            .iter()
            .map(|cell| {
                cell.get()
                    .expect("Encryption key should be generated after DKG completion")
            })
            .collect();

        let expected_public_key = &generated_keys[0];
        for (index, key) in generated_keys.iter().enumerate().skip(1) {
            assert_eq!(
                key, expected_public_key,
                "Node {index} has mismatched public key"
            );
        }
    }

    #[tokio::test]
    /// Tests the complete DKG and decryption phase end-to-end flow in a networked environment.
    /// Verifies that encrypted transactions can be properly decrypted after DKG completion.
    async fn test_dkg_and_decryption_phase_e2e() {
        logging::init_logging();

        let (enc_key_cells, committee, mut decrypters, signature_keys) = setup().await;

        // Enqueuing all DKG bundles
        enqueue_all_dkg_bundles(&mut decrypters).await;

        // Allow time for DKG bundle processing
        tokio::time::sleep(Duration::from_secs_f32(DKG_TERMINATION_DELAY_SECS)).await;

        let encryption_key = &enc_key_cells[0]
            .get()
            .expect("encryption key should be generated after DKG");

        // Phase 2: Encrypted transaction testing
        let priority_tx_message = b"The quick brown fox jumps over the lazy dog";
        let regular_tx_message = b"The slow brown fox jumps over the lazy dog";

        let decryption_round = RoundNumber::new(DECRYPTION_ROUND);
        let encrypted_inclusion_list = create_encrypted_inclusion_list(
            decryption_round,
            committee,
            &signature_keys,
            encryption_key,
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
    async fn enqueue_all_dkg_bundles(decrypters: &mut [Decrypter]) {
        let dkg_bundles = decrypters
            .iter_mut()
            .map(|decrypter| {
                decrypter
                    .gen_dkg_bundle()
                    .expect("DKG bundle should be generated")
            })
            .collect::<VecDeque<_>>();

        // enqueuing them all to decrypters
        for decrypter in decrypters.iter_mut() {
            let mut pending_dkgs = dkg_bundles.clone();
            decrypter
                .enqueue_dkg(&mut pending_dkgs)
                .await
                .expect("DKG bundles should be enqueued successfully");
        }
    }

    /// Creates round evidence by having all committee members sign the previous round.
    /// This evidence is required to validate the legitimacy of the current round.
    fn create_round_evidence(
        committee: Committee,
        signature_keys: &[SecretKey],
        current_round: RoundNumber,
    ) -> Evidence {
        let mut vote_accumulator = VoteAccumulator::new(committee);
        let previous_round = Round::new(current_round - 1, UNKNOWN_COMMITTEE_ID);

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
        let evidence = create_round_evidence(committee, signature_keys, round);
        let empty_aad = vec![];

        // Encrypt both message types
        let priority_plaintext = Plaintext::new(priority_message.to_vec());
        let regular_plaintext = Plaintext::new(regular_message.to_vec());

        let priority_ciphertext = DecryptionScheme::encrypt(
            &mut test_rng(),
            encryption_key,
            &priority_plaintext,
            &empty_aad,
        )
        .expect("Priority transaction encryption should succeed");

        let regular_ciphertext = DecryptionScheme::encrypt(
            &mut test_rng(),
            encryption_key,
            &regular_plaintext,
            &empty_aad,
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

    /// Sets up a complete test environment with committee members, decrypters, and network
    /// connections. Returns encryption key cells, committee, decrypters, and signature keys for
    /// testing.
    async fn setup() -> (
        Vec<ThresholdEncKeyCell>,
        Committee,
        Vec<Decrypter>,
        Vec<SecretKey>,
    ) {
        // Parse all key types from their string representations
        let signature_keys: Vec<_> = SIGNATURE_PRIVATE_KEY_STRINGS
            .iter()
            .map(|key_str| SecretKey::try_from(*key_str).expect("Valid signature key string"))
            .collect();

        let dh_keys: Vec<_> = DH_PRIVATE_KEY_STRINGS
            .iter()
            .map(|key_str| x25519::SecretKey::try_from(*key_str).expect("Valid DH key string"))
            .collect();

        let dkg_keys: Vec<_> = DKG_PRIVATE_KEY_STRINGS
            .iter()
            .map(|key_str| DkgDecKey::try_from_str::<64>(key_str).expect("Valid DKG key string"))
            .collect();

        // Create committee from signature keys
        let committee = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            signature_keys
                .iter()
                .enumerate()
                .map(|(index, secret_key)| (KeyId::from(index as u8), secret_key.public_key()))
                .collect::<Vec<_>>(),
        );

        // Create DKG key store with committee and DKG public keys
        let dkg_store = DkgKeyStore::new(
            committee.clone(),
            dkg_keys
                .iter()
                .enumerate()
                .map(|(index, dkg_key)| (KeyId::from(index as u8), DkgEncKey::from(dkg_key))),
        );

        // Set up network peers with available ports
        let network_peers: Vec<_> = signature_keys
            .iter()
            .zip(&dh_keys)
            .map(|(sig_key, dh_key)| {
                let available_port =
                    portpicker::pick_unused_port().expect("Should find available port");
                (
                    sig_key.public_key(),
                    dh_key.public_key(),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, available_port)),
                )
            })
            .collect();

        let addressable_committee =
            AddressableCommittee::new(committee.clone(), network_peers.clone());
        let mut decrypters = Vec::with_capacity(COMMITTEE_SIZE);
        let mut encryption_key_cells = Vec::with_capacity(COMMITTEE_SIZE);

        // Create decrypter instances for each committee member
        for peer_index in 0..network_peers.len() {
            let signature_key = signature_keys[peer_index].clone();
            let dh_key = dh_keys[peer_index].clone();
            let (_, _, network_address) = network_peers[peer_index];
            let encryption_key_cell = ThresholdEncKeyCell::new();

            let decrypter_config = DecrypterConfig::builder()
                .label(signature_key.public_key())
                .address(network_address.into())
                .dh_keypair(dh_key.into())
                .dkg_key(dkg_keys[peer_index].clone())
                .dkg_store(dkg_store.clone())
                .committee(addressable_committee.clone())
                .retain(RETAIN_ROUNDS)
                .threshold_enc_key(encryption_key_cell.clone())
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

        // Allow time for network setup
        tokio::time::sleep(Duration::from_secs(NETWORK_SETUP_DELAY_SECS)).await;

        (encryption_key_cells, committee, decrypters, signature_keys)
    }
}

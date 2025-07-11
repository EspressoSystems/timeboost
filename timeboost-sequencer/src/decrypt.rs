use arrayvec::ArrayVec;
use bon::Builder;
use bytes::{BufMut, Bytes, BytesMut};
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use cliquenet::{AddressableCommittee, MAX_MESSAGE_SIZE, Network, NetworkError, NetworkMetrics};
use multisig::{Committee, PublicKey};
use sailfish::types::{Evidence, Round, RoundNumber};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::result::Result as StdResult;
use timeboost_crypto::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};
use timeboost_crypto::{DecryptionScheme, Plaintext};
use timeboost_types::{DecryptionKey, InclusionList};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use crate::config::DecrypterConfig;

type Result<T> = std::result::Result<T, DecrypterError>;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;

/// Command sent to Decrypter's background worker
#[allow(dead_code)]
enum Command {
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
    /// Status of the distributed key gen/resharing: true means Worker has the decryption key share
    is_ready: bool,
}

impl Decrypter {
    pub async fn new<M>(cfg: DecrypterConfig, metrics: &M) -> Result<Self>
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

        let is_ready = cfg.decryption_key.is_some();
        let worker = Worker::builder()
            .label(cfg.label)
            .committees({
                let mut v = ArrayVec::new();
                v.push((RoundNumber::genesis(), cfg.committee.committee().clone()));
                v
            })
            .net(Overlay::new(net))
            .tx(dec_tx)
            .rx(cmd_rx)
            .maybe_dec_sk(cfg.decryption_key)
            .last_hatched_round(RoundNumber::genesis())
            .retain(cfg.retain)
            .build();

        Ok(Self {
            label: cfg.label,
            incls: BTreeMap::new(),
            worker_tx: cmd_tx,
            worker_rx: dec_rx,
            worker: spawn(worker.go()),
            is_ready,
        })
    }

    /// Check if the channels between decrypter and its core worker still have capacity left
    pub fn has_capacity(&mut self) -> bool {
        self.worker_tx.capacity() > 0 && self.worker_rx.capacity() > 0
    }

    /// Check if decrypter is ready to threshold decrypt encrypted bundles.
    /// Only true after DKG/resharing is done which equip Worker with dec key share.
    pub fn is_ready(&self) -> bool {
        self.is_ready
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
    /// decrypter will process any encrypted/unencrypted inclusion list
    pub async fn enqueue(&mut self, incl: InclusionList) -> StdResult<(), DecrypterDown> {
        let round = incl.round();

        if incl.is_encrypted() {
            self.worker_tx
                // TODO:(alex) don't send this command if not ready
                .send(Command::Decrypt(incl))
                .await
                .map_err(|_| DecrypterDown(()))?;
            self.incls.insert(round, Status::Encrypted);
        } else {
            self.incls.insert(round, Status::Decrypted(incl));
        }

        debug!(node = %self.label, %round, "enqueued inclusion list");

        Ok(())
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
}

impl Drop for Decrypter {
    fn drop(&mut self) {
        self.worker.abort()
    }
}

/// Max. supported number of committees.
const MAX_COMMITTEES: usize = 2;

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
    committees: ArrayVec<(RoundNumber, Committee), MAX_COMMITTEES>,
    /// channel for sending inclusion lists back to parent
    tx: Sender<InclusionList>,
    /// channel for receiving commands from the parent
    rx: Receiver<Command>,
    /// round number of the first decrypter request, used to ignore received decryption shares for
    /// eariler rounds
    first_requested_round: Option<RoundNumber>,
    /// decryption key used to decrypt and combine
    /// At system start-up (or new committee handover), DKG/resharing needs a few rounds to finish
    /// during which time the threshold key is None
    dec_sk: Option<DecryptionKey>,
    /// Number of rounds to retain.
    retain: usize,

    /// cache of decrtyped shares (keyed by round number), each entry value is a nested vector: an
    /// ordered list of per-ciphertext decryption shares. the order is derived from the
    /// ciphertext payload from the inclusion list `self.incls` of the same round
    ///
    /// note: Option<DecShare> uses None to indicate a failed to decrypt ciphertext
    #[builder(default)]
    dec_shares: BTreeMap<RoundNumber, Vec<Vec<Option<DecShare>>>>,
    /// Acknowledgement of the set of peers whose decryption share for a round has been received
    /// Useful to prevent DOS or DecShareBatch flooding by malicious peers
    #[builder(default)]
    acks: BTreeMap<RoundNumber, HashSet<PublicKey>>,
    /// cache of encrypted inclusion list waiting to be hatched using `dec_shares`
    #[builder(default)]
    incls: BTreeMap<RoundNumber, InclusionList>,
    /// the latest rounds whose ciphertexts are hatched
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
                // receiving a request from the decrypter
                cmd = self.rx.recv() => match cmd {
                    Some(Command::Decrypt(incl)) => {
                        let round = incl.round();
                        trace!(%node, %round, "decrypt request");

                        match self.on_decrypt_request(round, incl).await {
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
                    Some(_) => { /* todo: dynamic committees */ },
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

        let round = dec_shares.round;
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

    /// logic to process a `WorkerRequest::Decrypt` request from the decrypter
    async fn on_decrypt_request(&mut self, round: RoundNumber, incl: InclusionList) -> Result<()> {
        let dec_shares = self.decrypt(round, &incl)?;
        if dec_shares.is_empty() {
            return Err(DecrypterError::EmptyDecShares);
        }

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
    fn decrypt(&mut self, round: RoundNumber, incl: &InclusionList) -> Result<DecShareBatch> {
        let Some(dec_sk) = &self.dec_sk else {
            return Err(DecrypterError::DecKeyShareNotReady);
        };
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
        // Validate evidence:
        {
            let pred: RoundNumber = round.saturating_sub(1).into();

            let Some(committee) = self.round_committee(pred) else {
                warn!(node = %self.label, %round, "no committee for evidence round");
                return Err(DecrypterError::NoCommitteeForRound(pred));
            };

            let is_valid_evidence = match &batch.evidence {
                Evidence::Genesis => pred.is_genesis(),
                e @ Evidence::Regular(x) => e.round() == pred && x.is_valid_par(committee),
                e @ Evidence::Timeout(x) => e.round() == pred && x.is_valid_par(committee),
                e @ Evidence::Handover(x) => e.round() == pred && x.is_valid_par(committee),
            };

            if !is_valid_evidence {
                warn!(
                    node     = %self.label,
                    round    = %round,
                    evidence = %batch.evidence.round(),
                    "invalid evidence"
                );
                return Err(DecrypterError::MissingRoundEvidence(round));
            }
        }
        // This operation is doing the following: assumme local cache for this round is:
        // [[s1a, s1b], [s2a, s2b], [s3a, s3b]]
        // there are 3 ciphertexts, and node a and b has contributed their decrypted shares batch so
        // far. with node c's batch [s1c, s2c, s3c], the new local cache is:
        // [[s1a, s1b, s1c], [s2a, s2b, s2c], [s3a, s3b, s3c]]
        self.dec_shares
            .entry(round)
            .or_insert(vec![vec![]; batch.len()])
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
        // first check if hatchable, if not, return Ok(None)
        let Some(per_ct_opt_dec_shares) = self.dec_shares.get(&round) else {
            return Ok(None);
        };
        if per_ct_opt_dec_shares.is_empty()
            || per_ct_opt_dec_shares.iter().any(|opt_dec_shares| {
                let num_valid_shares = opt_dec_shares.iter().filter(|s| s.is_some()).count();
                let num_invalid_shares = opt_dec_shares.len() - num_valid_shares;

                // for valid decryption shares, as long as reaching f+1, we may try to hatch
                // for invalid ones, we need 2f+1 to ensure consensus (to ignore invalid ciphertext)
                // TODO: fix when dynamic committees
                let committee = self.committees.iter().last().expect("singleton committee");
                num_valid_shares < committee.1.one_honest_threshold().get()
                    && num_invalid_shares < committee.1.quorum_size().get()
            })
        {
            return Ok(None);
        }

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
        // a mutable ref
        let Some(per_ct_opt_dec_shares) = self.dec_shares.get_mut(&round) else {
            return Ok(None);
        };

        for (opt_ct, opt_dec_shares) in ciphertexts.into_iter().zip(per_ct_opt_dec_shares) {
            // only Some(_) for valid ciphertext's decryption shares
            let dec_shares = opt_dec_shares
                .iter()
                .filter_map(|s| s.as_ref())
                .collect::<Vec<_>>();

            // TODO: fix dynamic committees
            let committee = self.committees.iter().last().expect("singleton committee");
            if dec_shares.len() < committee.1.one_honest_threshold().into() {
                decrypted.push(None);
                continue;
            }

            if let Some(ct) = opt_ct {
                let aad = vec![];
                match DecryptionScheme::combine(
                    &committee.1,
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

    fn round_committee(&self, r: RoundNumber) -> Option<&Committee> {
        self.committees
            .iter()
            .find_map(|(n, c)| (r >= *n).then_some(c))
    }
}

/// A batch of decryption shares. Each batch is uniquely identified via round_number.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct DecShareBatch {
    round: RoundNumber,
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
    MissingRoundEvidence(RoundNumber),

    #[error("received inclusion list is outdated (already received or hatched)")]
    OutdatedRound,

    #[error("no committee for round: {0}")]
    NoCommitteeForRound(RoundNumber),

    #[error("decryption key share not ready, DKG/resharing yet finished")]
    DecKeyShareNotReady,
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
    use metrics::NoMetrics;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        time::Duration,
    };
    use timeboost_utils::types::logging;

    use ark_std::test_rng;
    use cliquenet::AddressableCommittee;
    use multisig::{Committee, KeyId, Keypair, SecretKey, Signed, VoteAccumulator, x25519};
    use sailfish::types::{Round, RoundNumber, UNKNOWN_COMMITTEE_ID};
    use timeboost_crypto::{
        DecryptionScheme, Plaintext, traits::threshold_enc::ThresholdEncScheme,
    };
    use timeboost_types::{
        Address, Bundle, ChainId, DecryptionKey, Epoch, InclusionList, PriorityBundle, SeqNo,
        Signer, Timestamp,
    };
    use tracing::warn;

    use crate::{config::DecrypterConfig, decrypt::Decrypter};

    #[tokio::test]
    async fn test_with_encrypted_data() {
        logging::init_logging();

        let (enc_key, committee, mut decrypters, signature_keys) = setup().await;

        // Craft a ciphertext for decryption
        let ptx_message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let tx_message = b"The slow brown fox jumps over the lazy dog".to_vec();
        let ptx_plaintext = Plaintext::new(ptx_message.clone());
        let tx_plaintext = Plaintext::new(tx_message.clone());
        let ptx_ciphertext =
            DecryptionScheme::encrypt(&mut test_rng(), &enc_key, &ptx_plaintext, &vec![]).unwrap();
        let tx_ciphertext =
            DecryptionScheme::encrypt(&mut test_rng(), &enc_key, &tx_plaintext, &vec![]).unwrap();
        let ptx_ciphertext_bytes =
            bincode::serde::encode_to_vec(&ptx_ciphertext, bincode::config::standard())
                .expect("Failed to encode ciphertext");
        let tx_ciphertext_bytes =
            bincode::serde::encode_to_vec(&tx_ciphertext, bincode::config::standard())
                .expect("Failed to encode ciphertext");

        // Create inclusion lists with encrypted transactions
        let round = RoundNumber::new(42);
        // generate round evidence by signing for round-1
        let evidence = {
            let mut va = VoteAccumulator::new(committee);
            for sk in signature_keys {
                let keypair = Keypair::from(sk);
                va.add(Signed::new(
                    Round::new(round - 1, UNKNOWN_COMMITTEE_ID),
                    &keypair,
                ))
                .unwrap();
            }
            let cert = va.into_certificate().unwrap();
            cert.into()
        };
        let mut incl_list = InclusionList::new(round, Timestamp::now(), 0.into(), evidence);
        let chain_id = ChainId::from(0);
        let epoch = Epoch::from(42);
        let auction = Address::default();
        let seqno = SeqNo::from(10);
        let signer = Signer::default();
        let bundle = PriorityBundle::new(
            Bundle::new(chain_id, epoch, ptx_ciphertext_bytes.into(), true),
            auction,
            seqno,
        );
        let signed_bundle = bundle.sign(signer).expect("default signer");
        incl_list.set_priority_bundles(vec![signed_bundle]);
        incl_list.set_regular_bundles(vec![Bundle::new(
            chain_id,
            epoch,
            tx_ciphertext_bytes.into(),
            true,
        )]);

        // Enqueue inclusion lists to each decrypter
        for d in decrypters.iter_mut() {
            if let Err(e) = d.enqueue(incl_list.clone()).await {
                warn!("failed to enqueue inclusion list: {:?}", e);
            }
        }

        // Collect decrypted inclusion lists
        let mut decrypted_lists = Vec::new();
        for d in decrypters.iter_mut() {
            let incl = d.next().await.unwrap();
            decrypted_lists.push(incl);
        }

        // Verify that all decrypted inclusion lists are correct
        for d in decrypted_lists {
            assert_eq!(d.round(), RoundNumber::new(42));
            assert_eq!(d.priority_bundles().len(), 1);
            assert_eq!(d.regular_bundles().len(), 1);
            let decrypted_ptx_data = d.priority_bundles()[0].bundle().data();
            let decrypted_tx_data = d.regular_bundles()[0].data();
            assert_eq!(decrypted_ptx_data.to_vec(), ptx_message);
            assert_eq!(decrypted_tx_data.to_vec(), tx_message);
        }
    }

    async fn setup() -> (
        <DecryptionScheme as ThresholdEncScheme>::PublicKey,
        Committee,
        Vec<Decrypter>,
        Vec<SecretKey>,
    ) {
        // these keys are generated via
        // `just mkconfig_local 5 --seed 42`
        let signature_private_keys = [
            "3hzb3bRzn3dXSV1iEVE6mU4BF2aS725s8AboRxLwULPp",
            "FWJzNGvEjFS3h1N1sSMkcvvroWwjT5LQuGkGHu9JMAYs",
            "2yWTaC6MWvNva97t81cd9QX5qph68NnB1wRVwAChtuGr",
            "CUpkbkn8bix7ZrbztPKJwu66MRpJrc1Wr2JfdrhetASk",
            "6LMMEuoPRCkpDsnxnANCRCBC6JagdCHs2pjNicdmQpQE",
        ];
        let dh_private_keys = [
            "BB3zUfFQGfw3sL6bpp1JH1HozK6ehEDmRGoiCpQH62rZ",
            "4hjtciEvuoFVT55nAzvdP9E76r18QwntWwFoeginCGnP",
            "Fo2nYV4gE9VfoVW9bSySAJ1ZuKT461x6ovZnr3EecCZg",
            "5KpixkV7czZTDVh7nV7VL1vGk4uf4kjKidDWq34CJx1T",
            "39wAn3bQzpn19oa8CiaNUFd8GekQAJMMuzrbp8Jt3FKz",
        ];
        let decryption_private_keys = [
            "jYLeZYQfgrLR34UL64j9nT4ZocR5YVxRJMjrR7uzJQGfTV",
            "j4xTAWUDJSN82nvGxdT7MC3pFAAPRRraWr9NvrztCBni7S",
            "jSMBhEpzSHiyzJSVca4fehTWuPCbHHd9oaEvp5NdQ3F56Z",
            "jH4QtGCEWjQzKYXpiVmsv8dFSj2qi7pkWY9bpiNjzkNLk2",
            "jeG3jCVLoireFivujES1Ws4pr7s577yhYaEwveXpQh2aaX",
        ];

        let encryption_key = "8sz9Bu5ECvR42x69tBm2W8GaaMrm1LQnm9rmT3EL5EdbPP3TqrLUyoUkxBzpCzPy4Vu";
        let comb_key = "y7D4UxEgJtRshdYfZu1NY4RyJxAzjjf3AGhf4AihP4epZffaoYRjFeCEaD9uCjNJVCDPZmjwnfB6v1gyZmrQsiCT5PDcHNzS7qfxP8GatiFes3nUs3xTxQLThqvrfdEv3S48jArK75FJoPRk5cKEBodTv1BVKu3GNgYHmcK731MKTJoMS16ukYxrSKg7KxzeQCZwBcamW1YQpVkHqbkvVif8wekSxfpz3CGrw2WKadzVbK1x1pUDFTrtSZU2eyTKVvrW4YJ2zKPm5FYXTaYMJqRXkyBFnvfR9NxgLHq6i5AuArTxrD772Rs1YX8bXu9fR4nLHt14SUJAGqf";

        let signature_keys: Vec<_> = signature_private_keys
            .iter()
            .map(|s| SecretKey::try_from(*s).expect("into secret key"))
            .collect();

        let dh_keys: Vec<_> = dh_private_keys
            .iter()
            .map(|s| x25519::SecretKey::try_from(*s).expect("into secret key"))
            .collect();

        let enc_key: <DecryptionScheme as ThresholdEncScheme>::PublicKey =
            decode_bincode(encryption_key);
        let decryption_keys: Vec<DecryptionKey> = decryption_private_keys
            .iter()
            .map(|k| {
                DecryptionKey::new(enc_key.clone(), decode_bincode(comb_key), decode_bincode(k))
            })
            .collect();
        let c = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            signature_keys
                .iter()
                .enumerate()
                .map(|(i, k)| (KeyId::from(i as u8), k.public_key()))
                .collect::<Vec<_>>(),
        );

        let peers: Vec<_> = signature_keys
            .iter()
            .zip(&dh_keys)
            .map(|(k, x)| {
                let port = portpicker::pick_unused_port().expect("find open port");
                (
                    k.public_key(),
                    x.public_key(),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                )
            })
            .collect();
        let ac = AddressableCommittee::new(c.clone(), peers.clone());
        let mut decrypters = Vec::new();
        for i in 0..peers.len() {
            let sig_key = signature_keys[i].clone();
            let dh_key = dh_keys[i].clone();
            let (_, _, addr) = peers[i];

            let conf = DecrypterConfig::builder()
                .label(sig_key.public_key())
                .address(addr.into())
                .dh_keypair(dh_key.into())
                .committee(ac.clone())
                .decryption_key(decryption_keys[i].clone())
                .retain(100)
                .build();

            let decrypter = Decrypter::new(conf, &NoMetrics).await.unwrap();
            decrypters.push(decrypter);
        }
        // wait for network
        let _ = tokio::time::sleep(Duration::from_secs(1)).await;
        (enc_key, c, decrypters, signature_keys)
    }

    fn decode_bincode<T: serde::de::DeserializeOwned>(encoded: &str) -> T {
        let conf = bincode::config::standard().with_limit::<{ 1024 * 1024 }>();
        bincode::serde::decode_from_slice(&bs58::decode(encoded).into_vec().unwrap(), conf)
            .unwrap()
            .0
    }
}

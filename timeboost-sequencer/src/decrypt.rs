use bytes::{BufMut, BytesMut};
use cliquenet::MAX_MESSAGE_SIZE;
use cliquenet::overlay::{Data, DataError, NetworkDown, Overlay};
use multisig::PublicKey;
use sailfish::types::RoundNumber;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use timeboost_crypto::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};
use timeboost_crypto::{DecryptionScheme, Keyset, KeysetId, Plaintext};
use timeboost_types::{Bytes, DecryptionKey, InclusionList};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

type Result<T> = std::result::Result<T, DecryptError>;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;

const MAX_ROUNDS: usize = 100;

/// Command sent to Decrypter's background worker
enum WorkerRequest {
    // request to decrypt all encrypted transactions inside the inclusion list
    Decrypt(InclusionList),
    // request to garbage collect all states related to a round (and previous rounds)
    Gc(RoundNumber),
}

/// response from `WorkerRequest`
enum WorkerResponse {
    // response to decrypt request, return the decrypted inclusion list
    Decrypt(InclusionList),
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
    /// Decryption committee this decrypter belongs to
    keyset: Keyset,
    /// Locally stored incl lists: those still unencrypted and those yet fetched by the next phase
    /// of timeboost
    incls: BTreeMap<RoundNumber, Status>,
    /// Sender end of the worker requests
    req_tx: Sender<WorkerRequest>,
    /// Receiver end of the worker response
    res_rx: Receiver<WorkerResponse>,
    /// Worker task handle.
    jh: JoinHandle<()>,
}

impl Decrypter {
    pub fn new(label: PublicKey, net: Overlay, keyset: Keyset, dec_sk: DecryptionKey) -> Self {
        let (req_tx, req_rx) = channel(MAX_ROUNDS);
        let (res_tx, res_rx) = channel(MAX_ROUNDS);
        let worker = Worker::new(label, net, keyset, dec_sk);

        Self {
            label,
            keyset,
            incls: BTreeMap::new(),
            req_tx,
            res_rx,
            jh: spawn(worker.go(req_rx, res_tx)),
        }
    }

    /// Check if the channels between decrypter and its core worker still have capacity left
    pub fn has_capacity(&mut self) -> bool {
        self.req_tx.capacity() > 0 && self.res_rx.capacity() > 0
    }

    /// Garbage collect cached state of `r` (and prior) rounds
    pub async fn gc(&mut self, r: RoundNumber) -> Result<()> {
        self.req_tx
            .send(WorkerRequest::Gc(r))
            .await
            .map_err(|_| DecryptError::Shutdown)
    }

    /// Send the inclusion list to worker to decrypt if it contains encrypted bundles,
    /// Else append to local cache waiting to be pulled.
    ///
    /// decrypter will process any unencrypted inclusion list, or those encrypted under the keyset
    /// this decrypter belongs to, but will reject bundles encrypted for totally a different
    /// keyset.
    pub async fn enqueue(&mut self, incl: InclusionList) -> Result<()> {
        let round = incl.round();
        let incl_digest = incl.digest();

        let required_keysets = incl.kids();
        if !required_keysets.is_empty() {
            // ensure encrypted inclusion list is sent to the correct decrypter
            if !required_keysets.contains(&self.keyset.id()) {
                return Err(DecryptError::WrongDecrypter(
                    required_keysets[0], // safe index-access
                    self.keyset.id(),
                ));
            }

            self.req_tx
                .send(WorkerRequest::Decrypt(incl))
                .await
                .map_err(|_| DecryptError::Shutdown)?;
            self.incls.insert(round, Status::Encrypted);
        } else {
            self.incls.insert(round, Status::Decrypted(incl));
        }

        trace!(
            node        = %self.label,
            round       = %round,
            digest      = ?incl_digest,
            "enqueued InclusionList"
        );

        Ok(())
    }

    /// Produces decrypted inclusion lists ordered by round number
    pub async fn next(&mut self) -> Result<InclusionList> {
        // first try to return the first inclusion list if it's already decrypted
        if let Some(entry) = self.incls.first_entry() {
            if matches!(entry.get(), Status::Decrypted(_)) {
                if let Status::Decrypted(incl) = entry.remove() {
                    return Ok(incl);
                }
            }
        }

        // normal loop: try to receive the next decrypted inclusion list
        while let Some(WorkerResponse::Decrypt(dec_incl)) = self.res_rx.recv().await {
            let round = dec_incl.round();
            // update decrypter cache of inclusion list
            info!(node = %self.label, %round, epoch = %dec_incl.epoch(), "InclusionList decrypted!");
            debug_assert!(
                !dec_incl.is_encrypted(),
                "decrypter worker returns non-decrypted InclusionList"
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
                }
            }
        }
        Err(DecryptError::Shutdown)
    }
}

impl Drop for Decrypter {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

/// Worker is responsible for "hatching" ciphertexts.
///
/// When ciphertexts in a round have received t+1 decryption shares
/// the shares can be combined to decrypt the ciphertext (hatching).
struct Worker {
    /// labeling the node by its signing/consensus public key
    label: PublicKey,
    /// overlay network to connect to other decrypters
    net: Overlay,
    /// keyset metadata about the decryption committee
    keyset: Keyset,
    /// round number of the first decrypter request, used to ignore received decryption shares for
    /// eariler rounds
    first_requested_round: Option<RoundNumber>,
    /// decryption key used to decrypt and combine
    dec_sk: DecryptionKey,

    /// cache of decrtyped shares (keyed by round number), each entry value is a nested vector: an
    /// ordered list of per-ciphertext decryption shares. the order is derived from the
    /// ciphertext payload from the inclusion list `self.incls` of the same round
    ///
    /// note: Option<DecShare> uses None to indicate a failed to decrypt ciphertext
    dec_shares: BTreeMap<RoundNumber, Vec<Vec<Option<DecShare>>>>,
    /// Acknowledgement of the set of peers whose decryption share for a round has been received
    /// Useful to prevent DOS or DecShareBatch flooding by malicious peers
    acks: BTreeMap<RoundNumber, HashSet<PublicKey>>,
    /// cache of encrypted inclusion list waiting to be hatched using `dec_shares`
    incls: BTreeMap<RoundNumber, InclusionList>,
    /// the latest rounds whose ciphertexts are hatched
    last_hatched_round: RoundNumber,
}

impl Worker {
    pub fn new(label: PublicKey, net: Overlay, keyset: Keyset, dec_sk: DecryptionKey) -> Self {
        Self {
            label,
            net,
            keyset,
            first_requested_round: None,
            dec_sk,
            dec_shares: BTreeMap::default(),
            acks: BTreeMap::default(),
            incls: BTreeMap::default(),
            last_hatched_round: RoundNumber::genesis(),
        }
    }

    // entry point of `worker` thread, it runs in a loop until shutdown or out of channel capacity.
    pub async fn go(mut self, mut req_rx: Receiver<WorkerRequest>, res_tx: Sender<WorkerResponse>) {
        let node = self.label;

        loop {
            // each event loop is triggered by receiving one of the following
            // - a new request from Decrypter
            // - batch of decrypted shares from other decrypters
            tokio::select! {
                // receiving a request from the decrypter
                val = req_rx.recv() => match val {
                    Some(WorkerRequest::Decrypt(incl)) => {
                        let round = incl.round();
                        trace!(%node, %round, "decrypt request");

                        match self.on_decrypt_request(round, incl).await {
                            Err(DecryptError::Shutdown) => return,
                            Err(err) => {
                                error!(%node, %round, %err, "failed to process decrypt request");
                                continue;
                            },
                            _ => trace!(%node, %round, "decrypt request... DONE"),
                        }
                    },
                    Some(WorkerRequest::Gc(round))=> {
                        trace!(%node, %round, "gc request");
                        if let Err(err) = self.on_gc_request(round).await {
                            error!(%node, %round, %err, "failed to gc");
                        }
                        trace!(%node, %round, "gc request... DONE");
                        continue;
                    },
                    None => {
                        debug!(%node, "decrypter has shutdown, shutting down its worker");
                        return;
                    }
                },

                // receiving a batch of decrypted shares from other decrypters
                val = self.net.receive() => match val {
                    Ok((src, data)) => {
                        // ignore msg sent to self during broadcast
                        if src == self.label {
                            continue;
                        }
                        let Ok(dec_shares) = deserialize::<DecShareBatch>(&data) else {
                            error!(%node, from=%src, "failed to deserialize decrypted shares");
                            continue;
                        };

                        let round = dec_shares.round;
                        // if already sent for this round, `src` will be re-inserted, thus returns false
                        // in which case we skip processing this message since this peer has already sent once
                        if !self.acks.entry(round).or_default().insert(src) {
                            continue;
                        };
                        trace!(%node, from=%src, %round, "receive decrypted shares");

                        if round <= self.last_hatched_round || round < self.oldest_cached_round() {
                            // shares for which the ciphertexts have already hatched
                            // or shares that are older than the first ciphertext in
                            // the local cache are not inserted.
                            continue;
                        }
                        if let Err(err) = self.insert_shares(dec_shares) {
                            error!(%node, from=%src, %round, %err, "failed to process decrypted shares");
                            continue;
                        }
                        trace!(%node, from=%src, %round, "receive decrypted shares... DONE");
                    },
                    Err(e) => {
                        let _: NetworkDown = e; // ensure err type
                        debug!(%node, "Overlay network has shutdown, shutting down worker");
                        return;
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
                    if let Err(err) = res_tx.send(WorkerResponse::Decrypt(incl.clone())).await {
                        error!(%node, %err, "failed to send hatched inclusion list");
                        return;
                    }
                    debug!(%node, %round, "hatch inclusion list... DONE");
                }
                Err(err) => warn!(%round, %err, %node, "failed to hatch"),
                Ok(None) => continue,
            }
        }
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
        let dec_shares = self.decrypt(round, &incl);
        if dec_shares.is_empty() {
            return Err(DecryptError::EmptyDecShares);
        }

        self.net
            .broadcast(round.u64(), serialize(&dec_shares)?)
            .await?;
        self.insert_shares(dec_shares)?;
        self.incls.insert(round, incl);

        // edge case: when processing the first decrypt request, workers may have received
        // decryption shares of eariler rounds from other decrypters, but this worker
        // doesn't need those shares, thus pruning them.
        if self.first_requested_round.is_none() {
            debug!(node=%self.label, %round, "set first requested round");
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
        if round.u64() > 0 && !self.dec_shares.is_empty() {
            self.net.gc(round.u64());
            self.gc(round);
        }
        Ok(())
    }

    /// scan through the inclusion list and extract the relevant ciphertext from encrypted
    /// bundle/tx, preserving the order, "relevant" means encrypted under the keyset this worker
    /// belongs to.
    ///
    /// dev: Option<_> return type indicates potential failure in ciphertext deserialization
    fn extract_ciphertexts(
        kid: KeysetId,
        incl: &InclusionList,
    ) -> impl Iterator<Item = Option<Ciphertext>> {
        incl.filter_ciphertexts(kid)
            .map(|bytes| deserialize::<Ciphertext>(bytes).ok())
    }

    /// Produce decryption shares for each *relevant* encrypted bundles inside the inclusion list,
    /// where "relevant" means targetted to the same `KeysetId` as the current decrypter/worker.
    /// Also see [`DecShareBatch`] doc.
    ///
    /// NOTE: when a ciphertext is malformed, we will skip decrypting it (treat as garbage) here.
    /// but will later be marked as decrypted during `hatch()`
    fn decrypt(&mut self, round: RoundNumber, incl: &InclusionList) -> DecShareBatch {
        let dec_shares = Self::extract_ciphertexts(self.keyset.id(), incl)
            .map(|optional_ct| {
                optional_ct.and_then(|ct| {
                    <DecryptionScheme as ThresholdEncScheme>::decrypt(
                        self.dec_sk.privkey(),
                        &ct,
                        &vec![],
                    )
                    .ok() // decryption failure result in None
                })
            })
            .collect::<Vec<_>>();

        DecShareBatch {
            round,
            kid: self.keyset.id(),
            dec_shares,
        }
    }

    /// update local cache of decrypted shares
    fn insert_shares(&mut self, batch: DecShareBatch) -> Result<()> {
        if batch.is_empty() {
            trace!("Empty decryption share batch, skipped");
            return Err(DecryptError::EmptyDecShares);
        }
        // This operation is doing the following: assumme local cache for this round is:
        // [[s1a, s1b], [s2a, s2b], [s3a, s3b]]
        // there are 3 ciphertexts, and node a and b has contributed their decrypted shares batch so
        // far. with node c's batch [s1c, s2c, s3c], the new local cache is:
        // [[s1a, s1b, s1c], [s2a, s2b, s2c], [s3a, s3b, s3c]]
        self.dec_shares
            .entry(batch.round)
            .or_insert(vec![vec![]; batch.len()])
            .iter_mut()
            .zip(batch.dec_shares)
            .for_each(|(shares, new)| shares.push(new));

        Ok(())
    }

    /// Attempt to hatch for round, returns Ok(Some(_)) if hatched successfully, Ok(None) if
    /// insufficient shares. Local cache are garbage collected for hatched rounds.
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
                num_valid_shares < self.keyset.one_honest_threshold().get()
                    && num_invalid_shares < self.keyset.honest_majority_threshold().get()
            })
        {
            return Ok(None);
        }

        // retreive ciphertext again from the original encrypted inclusion list, and some sanity
        // check
        let mut incl = self
            .incls
            .get(&round)
            .ok_or_else(|| {
                DecryptError::Internal(format!(
                    "missing inclusion list for round={round} in local cache"
                ))
            })?
            .clone();
        let ciphertexts = Self::extract_ciphertexts(self.keyset.id(), &incl);

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

            if dec_shares.len() < self.keyset.one_honest_threshold().get() {
                decrypted.push(None);
                continue;
            }

            if let Some(ct) = opt_ct {
                let aad = vec![];
                match DecryptionScheme::combine(
                    &self.keyset,
                    self.dec_sk.combkey(),
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
                        debug!(
                            "combine at node={} found faulty subset indices={:?}",
                            self.label, wrong_indices
                        );
                        // not ready to hatch this ciphertext, thus the containing inclusion list
                        return Ok(None);
                    }
                    Err(e) => return Err(DecryptError::Decryption(e)),
                }
            } else {
                decrypted.push(None);
            }
        }

        // construct/modify the inclusion list to replace with decrypted payload
        let kid = self.keyset.id();
        let mut num_encrypted_priority_bundles = 0;
        incl.priority_bundles_mut()
            .iter_mut()
            .filter(|pb| pb.bundle().kid() == Some(kid))
            .zip(decrypted.clone())
            .for_each(|(pb, opt_plaintext)| {
                num_encrypted_priority_bundles += 1;
                match opt_plaintext {
                    Some(pt) => pb.set_data(Bytes::from(<Vec<u8>>::from(pt))),
                    // None means garbage (undecryptable ciphertext), simply mark as decrypted
                    None => pb.set_data(pb.bundle().data().clone()),
                }
            });
        incl.regular_bundles_mut()
            .iter_mut()
            .filter(|b| b.kid() == Some(kid))
            .zip(decrypted[num_encrypted_priority_bundles..].to_vec())
            .for_each(|(bundle, opt_plaintext)| {
                match opt_plaintext {
                    Some(pt) => bundle.set_data(Bytes::from(<Vec<u8>>::from(pt))),
                    // None means garbage (undecryptable ciphertext), simply mark as decrypted
                    None => bundle.set_data(bundle.data().clone()),
                }
            });
        if incl.is_encrypted() {
            return Err(DecryptError::Internal(
                "didn't fully decrypt inclusion list".to_string(),
            ));
        }

        // garbage collect hatched rounds
        self.last_hatched_round = round;
        self.gc(round);

        Ok(Some(incl))
    }
}

/// A batch of decryption shares. Each batch is uniquely identified via (round_number, keyset_id).
/// Each inclusion list, w/ a unique round number, may contain encrypted bundles with different
/// keysets, those bundles are split into batches, one for each keyset.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct DecShareBatch {
    round: RoundNumber,
    kid: KeysetId,
    // note: each decrpytion share is for a different ciphertext;
    // None entry indicates invalid/failed decryption, we placehold for those invalid ciphertext
    // for simpler hatch/re-assemble logic without tracking a separate indices of those invalid
    // ones
    dec_shares: Vec<Option<DecShare>>,
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
#[non_exhaustive]
pub enum DecryptError {
    #[error("Decryption request for: {0}, but send to decrypter in: {1}")]
    WrongDecrypter(KeysetId, KeysetId),

    #[error("decryption error: {0}")]
    Decryption(#[from] ThresholdEncError),

    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("data error: {0}")]
    DataError(#[from] DataError),

    #[error("decrypter has shut down")]
    Shutdown,

    #[error("unexpected internal err: {0}")]
    Internal(String),

    #[error("empty set of valid decryption shares")]
    EmptyDecShares,

    #[error("missing evidence for round: {0}")]
    MissingRoundEvidence(RoundNumber),

    #[error("received inclusion list is outdated (already received or hatched)")]
    OutdatedRound,
}

impl From<NetworkDown> for DecryptError {
    fn from(_: NetworkDown) -> Self {
        Self::Shutdown
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        num::NonZeroUsize,
        time::Duration,
    };
    use timeboost_utils::types::logging;

    use ark_std::test_rng;
    use cliquenet::{Network, NetworkMetrics, Overlay};
    use multisig::SecretKey;
    use sailfish::types::RoundNumber;
    use timeboost_crypto::{
        DecryptionScheme, Keyset, Plaintext, PublicKey, traits::threshold_enc::ThresholdEncScheme,
    };
    use timeboost_types::{
        Address, Bundle, ChainId, DecryptionKey, Epoch, InclusionList, PriorityBundle, SeqNo,
        Signer, Timestamp,
    };
    use tracing::warn;

    use crate::decrypt::Decrypter;

    #[tokio::test]
    async fn test_with_encrypted_data() {
        logging::init_logging();
        let num_nodes = 5;
        let keyset = timeboost_crypto::Keyset::new(1, NonZeroUsize::new(num_nodes).unwrap());
        let encryption_key: PublicKey<_> =
            decode_bincode("kjGsCSgKRoBte3ohUroYzckRZCTknNbF44EagVmYGGp1YK");

        let mut decrypters = setup(keyset).await;

        // Craft a ciphertext for decryption
        let ptx_message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let tx_message = b"The slow brown fox jumps over the lazy dog".to_vec();
        let ptx_plaintext = Plaintext::new(ptx_message.clone());
        let tx_plaintext = Plaintext::new(tx_message.clone());
        let ptx_ciphertext = DecryptionScheme::encrypt(
            &mut test_rng(),
            &keyset.id(),
            &encryption_key,
            &ptx_plaintext,
            &vec![],
        )
        .unwrap();
        let tx_ciphertext = DecryptionScheme::encrypt(
            &mut test_rng(),
            &keyset.id(),
            &encryption_key,
            &tx_plaintext,
            &vec![],
        )
        .unwrap();
        let ptx_ciphertext_bytes =
            bincode::serde::encode_to_vec(&ptx_ciphertext, bincode::config::standard())
                .expect("Failed to encode ciphertext");
        let tx_ciphertext_bytes =
            bincode::serde::encode_to_vec(&tx_ciphertext, bincode::config::standard())
                .expect("Failed to encode ciphertext");

        // Create inclusion lists with encrypted transactions
        let mut incl_list = InclusionList::new(RoundNumber::new(42), Timestamp::now(), 0.into());
        let keyset_id = keyset.id();
        let chain_id = ChainId::from(0);
        let epoch = Epoch::from(42);
        let auction = Address::default();
        let seqno = SeqNo::from(10);
        let signer = Signer::default();
        let bundle = PriorityBundle::new(
            Bundle::new(
                chain_id,
                epoch,
                ptx_ciphertext_bytes.into(),
                Some(keyset_id),
            ),
            auction,
            seqno,
        );
        let signed_bundle = bundle.sign(signer).expect("default signer");
        incl_list.set_priority_bundles(vec![signed_bundle]);
        incl_list.set_regular_bundles(vec![Bundle::new(
            chain_id,
            epoch,
            tx_ciphertext_bytes.into(),
            Some(keyset_id),
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

    async fn setup(keyset: Keyset) -> Vec<Decrypter> {
        let signature_private_keys = [
            "24f9BtAxuZziE4BWMYA6FvyBuedxU9SVsgsoVcyw3aEWagH8eXsV6zi2jLnSvRVjpZkf79HDJNicXSF6FpRWkCXg",
            "2gtHurFq5yeJ8HGD5mHUPqniHbpEE83ELLpPqhxEvKhPJFcjMnUwdH2YsdhngMmQTqHo9B1Qna6uM13ug2Pir97k",
            "4Y7yyg11MBYJaeD2UWCh5cto8wizJoUCqFm7YjMbY3hXyWSWVPgi7y1D9e7D78a1NcWdE4k59D6vK9f6eCpzVkbQ",
            "zrjZDknq9nPhiBXKeG2PeotwxAayYkv2UFmxc2UsCGHsdu5vCsjqxn8ko2Rh2fWts76u6eCJYjDgKEaveutVhjW",
            "jW98dJM94zuvhRCA1bGLiPjakePTc1CYPP2V5iCswfayZiYujGYdSoE1MYDa61dHCyzPdEvGNBDmnFHS6jf83Km",
        ];
        let decryption_private_keys = [
            "jMbTDiLo8tgyERv92mGrCAe1s3KnnnyqhQeSYte6vUhZy1",
            "jysmvvvwSHu872gmxkejPP8RxUDpSpKChnkPMVeXyRibwN",
            "kCioHtYdX7pUVXJLceFFKx7j4czcqDjjS52FYbvy2AuyQV",
            "jVEU8hbv7uUntaDt4GgDxUKgoCu8UCXugx1coMeiVfn31L",
            "jUzpdPzgxn2zpaLXaHJiWJ2jbbD3scsP8YqscA1uZGhPfZ",
        ];

        let encryption_key = "kjGsCSgKRoBte3ohUroYzckRZCTknNbF44EagVmYGGp1YK";
        let comb_key = "AuMP7yjmQH98sUnn7gcP7UUEZ1zNNbzESuNFkizXXHLeyyeH89Ky6F3M5xQ5kDXHyBAuza2CJmyXG9r1n38dW5GYj3asqB1TJzxmCDpmQo7eGjQEgcfEhz521k91kymL7u14EaGriN43WfzDBvcvWjNq93tjTUpRtv4kBycAujLxsWUoaCZBFDVcYMrLAoNXAaCMZHNerseE5V9vqMmgDXRqXZZZtJFv6kgARqmqH";

        let signature_keys: Vec<_> = signature_private_keys
            .iter()
            .map(|s| SecretKey::try_from(&decode_bs58(s)[..]).expect("into secret key"))
            .collect();

        let decryption_keys: Vec<DecryptionKey> = decryption_private_keys
            .iter()
            .map(|k| {
                DecryptionKey::new(
                    decode_bincode(encryption_key),
                    decode_bincode(comb_key),
                    decode_bincode(k),
                )
            })
            .collect();

        let peers: Vec<_> = signature_keys
            .iter()
            .map(|k| {
                let port = portpicker::pick_unused_port().expect("find open port");
                (
                    k.public_key(),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                )
            })
            .collect();

        let mut decrypters = Vec::new();
        for i in 0..usize::from(keyset.size()) {
            let sig_key = signature_keys[i].clone();
            let (_, addr) = peers[i];

            let network = Network::create(
                "decrypt",
                addr,
                sig_key.clone().into(),
                peers.clone(),
                NetworkMetrics::default(),
            )
            .await
            .expect("starting network");

            let decrypter = Decrypter::new(
                sig_key.public_key(),
                Overlay::new(network),
                keyset,
                decryption_keys[i].clone(),
            );
            decrypters.push(decrypter);
        }
        // wait for network
        let _ = tokio::time::sleep(Duration::from_secs(1)).await;
        decrypters
    }

    fn decode_bs58(encoded: &str) -> Vec<u8> {
        bs58::decode(encoded).into_vec().unwrap()
    }

    fn decode_bincode<T: serde::de::DeserializeOwned>(encoded: &str) -> T {
        let conf = bincode::config::standard().with_limit::<{ 1024 * 1024 }>();
        bincode::serde::decode_from_slice(&decode_bs58(encoded), conf)
            .unwrap()
            .0
    }
}

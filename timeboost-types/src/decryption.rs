use anyhow::anyhow;
use ark_ec::AffineRepr;
use arrayvec::ArrayVec;
use multisig::{Committee, CommitteeId, KeyId};
use parking_lot::RwLock;
use rayon::prelude::*;
use sailfish_types::{Evidence, RoundNumber};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;
use std::{
    collections::{BTreeMap, btree_map},
    sync::Arc,
};
use timeboost_crypto::prelude::{
    LabeledDkgDecKey, ThresholdCombKey, ThresholdEncKey, ThresholdKeyShare, VssCommitment, VssShare,
};
use timeboost_crypto::{
    prelude::FeldmanVssPublicParam,
    prelude::VessError,
    prelude::{DkgEncKey, Vess, Vss},
    prelude::{KeyResharing, VerifiableSecretSharing},
};
use tokio::sync::Notify;
use tokio::task::spawn_blocking;

use crate::DkgBundle;

const DKG_AAD: &[u8; 3] = b"dkg";

/// Key materials related to the decryption phase, including the public key for encryption,
/// the per-node key share for decryption, and combiner key for hatching decryption shares into
/// plaintext
#[derive(Debug, Clone)]
pub struct ThresholdKey {
    pubkey: ThresholdEncKey,
    combkey: ThresholdCombKey,
    privkey: ThresholdKeyShare,
}

impl ThresholdKey {
    pub fn new(
        pubkey: ThresholdEncKey,
        combkey: ThresholdCombKey,
        privkey: ThresholdKeyShare,
    ) -> Self {
        ThresholdKey {
            pubkey,
            combkey,
            privkey,
        }
    }

    /// Construct all key material for threshold decryption from DKG outputs.
    /// The ACS subprotocol in DKG outputs a subset of commitments and key shares.
    ///
    /// # Parameters
    /// - `committee_size`: size of the threshold committee
    /// - `node_idx`: in 0..committee_size, currently same as KeyId
    /// - `dealings`: ResultIter containing decrypted shares and commitments
    pub fn from_dkg<I>(
        committee_size: usize,
        node_idx: usize,
        mut dealings: I,
    ) -> anyhow::Result<Self>
    where
        I: Iterator<Item = (VssShare, VssCommitment)>,
    {
        // aggregate selected dealings
        let (agg_key_share, agg_comm) = Vss::aggregate(&mut dealings)?;

        // derive key material
        Self::from_single_dkg(committee_size, node_idx, agg_key_share, &agg_comm)
    }

    /// Construct all key material for the threshold decryption from Key resharing.
    pub fn from_resharing<I>(
        old_committee: &Committee,
        new_committee: &Committee,
        recv_node_idx: usize,
        dealings: I,
    ) -> anyhow::Result<Self>
    where
        I: Iterator<Item = (usize, VssShare, VssCommitment)>,
    {
        let old_pp = FeldmanVssPublicParam::from(old_committee);
        let new_pp = FeldmanVssPublicParam::from(new_committee);

        let (new_share, new_comm) = Vss::combine(&old_pp, &new_pp, recv_node_idx, dealings)?;
        Self::from_single_dkg(new_pp.num_nodes(), recv_node_idx, new_share, &new_comm)
    }

    /// inner routine to construct from a single (aggregated or interpolated) DKG output,
    /// shared in both DKG and resharing logic.
    fn from_single_dkg(
        committee_size: usize,
        node_idx: usize,
        key_share: VssShare,
        commitment: &VssCommitment,
    ) -> anyhow::Result<Self> {
        // note: all .into() are made available via derive_more::From on those structs
        let pk: ThresholdEncKey = commitment
            .first()
            .ok_or_else(|| anyhow!("feldman commitment can't be empty"))?
            .into_group()
            .into();

        let combkey: ThresholdCombKey = (0..committee_size)
            .into_par_iter()
            .map(|idx| Vss::derive_public_share_unchecked(idx, commitment))
            .collect::<Vec<_>>()
            .into();

        let privkey: ThresholdKeyShare = (key_share, node_idx as u32).into();

        Ok(Self::new(pk, combkey, privkey))
    }

    pub fn pubkey(&self) -> &ThresholdEncKey {
        &self.pubkey
    }

    pub fn combkey(&self) -> &ThresholdCombKey {
        &self.combkey
    }

    pub fn privkey(&self) -> &ThresholdKeyShare {
        &self.privkey
    }
}

/// `ThresholdKeyCell` is a thread-safe container for an optional `ThresholdKey`
/// that allows asynchronous notification when the key is set.
#[derive(Clone, Debug, Default)]
pub struct ThresholdKeyCell {
    inner: Arc<ThresholdKeyCellInner>,
}

#[derive(Debug, Default)]
struct ThresholdKeyCellInner {
    key: RwLock<Option<ThresholdKey>>,
    notify: Notify,
}

impl ThresholdKeyCell {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, key: ThresholdKey) {
        *self.inner.key.write() = Some(key);
        self.inner.notify.notify_waiters();
    }

    pub fn get(&self) -> Option<ThresholdKey> {
        (*self.inner.key.read()).clone()
    }

    pub fn enc_key(&self) -> Option<ThresholdEncKey> {
        self.get().map(|sk| sk.pubkey)
    }

    pub fn get_ref(&self) -> impl Deref<Target = Option<ThresholdKey>> {
        self.inner.key.read()
    }

    pub async fn read(&self) -> ThresholdKey {
        loop {
            let fut = self.inner.notify.notified();
            if let Some(k) = self.get() {
                return k;
            }
            fut.await;
        }
    }
}

/// A small, non-empty collection of KeyStores.
#[derive(Debug, Default, Clone)]
#[allow(clippy::len_without_is_empty)]
pub struct KeyStoreVec<const N: usize> {
    vec: ArrayVec<KeyStore, N>,
}

impl<const N: usize> KeyStoreVec<N> {
    /// Create a key store vector with the given entry.
    pub fn new(k: KeyStore) -> Self {
        const { assert!(N > 0) }
        let mut this = Self {
            vec: ArrayVec::new(),
        };
        this.add(k);
        this
    }

    /// Check if an entry with the given committee ID exists.
    pub fn contains(&self, id: CommitteeId) -> bool {
        self.vec.iter().any(|k| k.committee().id() == id)
    }

    /// Get the index position for the given committee ID (if any).
    ///
    /// Key stores are ordered by recency, i.e. the higher the index,
    /// the older the key store.
    pub fn position(&self, id: CommitteeId) -> Option<usize> {
        self.vec.iter().position(|k| k.committee().id() == id)
    }

    /// Get the key store corresponding to the given committee ID (if any).
    pub fn get(&self, id: CommitteeId) -> Option<&KeyStore> {
        self.vec.iter().find(|k| k.committee().id() == id)
    }

    /// Get the first (newest) key store.
    pub fn first(&self) -> &KeyStore {
        self.vec.first().expect("non-empty vector")
    }

    /// Get the last (oldest) key store.
    pub fn last(&self) -> &KeyStore {
        self.vec.last().expect("non-empty vector")
    }

    /// Get the number of key stores stored.
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Add a key store entry.
    ///
    /// If an entry with the given committee ID already exists, `add` is a NOOP.
    /// This method will remove the oldest entry when at capacity.
    pub fn add(&mut self, k: KeyStore) {
        const { assert!(N > 0) }
        if self.contains(k.committee().id()) {
            return;
        }
        self.vec.truncate(N.saturating_sub(1));
        self.vec.insert(0, k);
    }

    /// Like `add`, but moves `self`.
    pub fn with(mut self, k: KeyStore) -> Self {
        self.add(k);
        self
    }

    /// Get an iterator over all key stores.
    pub fn iter(&self) -> impl Iterator<Item = &KeyStore> {
        self.vec.iter()
    }

    /// Check that the provided evidence is valid for the key stores.
    pub fn is_valid(&self, r: RoundNumber, evidence: &Evidence) -> bool {
        match evidence {
            Evidence::Genesis => r.is_genesis(),
            Evidence::Regular(x) => {
                let Some(key_store) = self.get(x.data().committee()) else {
                    return false;
                };
                evidence.round() + 1 == r && x.is_valid_par(key_store.committee())
            }
            Evidence::Timeout(x) => {
                let Some(key_store) = self.get(x.data().round().committee()) else {
                    return false;
                };
                evidence.round() + 1 == r && x.is_valid_par(key_store.committee())
            }
            Evidence::Handover(x) => {
                let Some(key_store) = self.get(x.data().round().committee()) else {
                    return false;
                };
                evidence.round() + 1 == r && x.is_valid_par(key_store.committee())
            }
        }
    }
}

impl<const N: usize> From<KeyStore> for KeyStoreVec<N> {
    fn from(k: KeyStore) -> Self {
        const { assert!(N > 0) }
        Self::new(k)
    }
}

/// A `KeyStore` with committee information and public keys used in the DKG or key resharing
#[derive(Debug, Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

#[derive(Debug)]
struct KeyStoreInner {
    committee: Committee,
    keys: BTreeMap<KeyId, DkgEncKey>,
}

impl KeyStore {
    pub fn new<I, T>(c: Committee, keys: I) -> Self
    where
        I: IntoIterator<Item = (T, DkgEncKey)>,
        T: Into<KeyId>,
    {
        let this = Self(Arc::new(KeyStoreInner {
            committee: c,
            keys: keys.into_iter().map(|(i, k)| (i.into(), k)).collect(),
        }));

        // basic sanity check
        // Current secret sharing impl assumes node_idx/key_id to range from 0..n
        for (node_idx, (key_id, p)) in this.0.committee.entries().enumerate() {
            assert_eq!(
                KeyId::from(node_idx as u8),
                key_id,
                "{p}'s key ID is not {node_idx}"
            );
            assert!(this.0.keys.contains_key(&key_id), "{p} has no DkgEncKey");
        }
        for id in this.0.keys.keys() {
            assert!(
                this.0.committee.contains_index(id),
                "ID {id:?} not in committee",
            );
        }
        this
    }

    /// Returns a reference to the committee.
    pub fn committee(&self) -> &Committee {
        &self.0.committee
    }

    /// Returns an iterator over all public keys sorted by their node's KeyId
    pub fn sorted_keys(&self) -> btree_map::Values<'_, KeyId, DkgEncKey> {
        self.0.keys.values()
    }
}

/// The mode of operation for the accumulator.
#[derive(Debug, Clone)]
pub enum AccumulatorMode {
    /// Standard DKG mode
    Dkg,
    /// Resharing mode with the previous committee's combined key
    Resharing(ThresholdCombKey),
}

impl fmt::Display for AccumulatorMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dkg => f.write_str("initial DKG"),
            Self::Resharing(_) => f.write_str("resharing"),
        }
    }
}

/// Accumulates DKG bundles for a given committee and finalizes when enough have been collected.
///
/// DkgAccumulator tracks received bundles and determines when the threshold for finalizing
/// the DKG process is met. Once enough valid bundles are collected, it can produce a finalized
/// Subset containing the aggregated contributions.
#[derive(Debug, Clone)]
pub struct DkgAccumulator {
    store: KeyStore,
    bundles: Vec<DkgBundle>,
    mode: AccumulatorMode,
    complete: bool,
}

impl DkgAccumulator {
    /// Create a new accumulator with the specified mode.
    pub fn new(store: KeyStore, mode: AccumulatorMode) -> Self {
        Self {
            store,
            bundles: Vec::new(),
            mode,
            complete: false,
        }
    }

    /// Get a reference to the committee.
    pub fn committee(&self) -> &Committee {
        self.store.committee()
    }

    /// Get the bundles collected so far.
    pub fn bundles(&self) -> &[DkgBundle] {
        &self.bundles
    }

    /// Get the mode of the accumulator.
    pub fn mode(&self) -> &AccumulatorMode {
        &self.mode
    }

    /// Get the completed state of the accumulator
    pub fn completed(&self) -> bool {
        self.complete
    }

    /// Check if the accumulator is empty.
    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Try to add a bundle to the accumulator.
    pub async fn try_add(&mut self, bundle: DkgBundle) -> anyhow::Result<()> {
        // caller should ensure that no bundles are added after finalization
        if self.bundles().contains(&bundle) || self.complete {
            return Ok(());
        }

        let vess = Vess::new_fast();
        let store = self.store.clone();
        let mode = self.mode.clone();

        let bundle = spawn_blocking(move || {
            // verify the bundle based on the mode
            match mode {
                AccumulatorMode::Dkg => {
                    vess.verify_shares(
                        store.committee(),
                        store.sorted_keys(),
                        bundle.vess_ct(),
                        bundle.comm(),
                        DKG_AAD,
                    )?;
                }
                AccumulatorMode::Resharing(combkey) => {
                    let Some(pub_share) = combkey.get_pub_share(bundle.origin().0.into()) else {
                        return Err(VessError::FailedVerification);
                    };
                    vess.verify_reshares(
                        store.committee(),
                        store.sorted_keys(),
                        bundle.vess_ct(),
                        bundle.comm(),
                        DKG_AAD,
                        *pub_share,
                    )?;
                }
            }
            Ok(bundle)
        })
        .await??;

        self.bundles.push(bundle);
        // only store the necessary amount of bundles in the accumulator
        if self.bundles.len() >= self.store.committee().one_honest_threshold().into() {
            self.complete = true;
        }
        Ok(())
    }

    /// Try to finalize the accumulator into a subset if enough bundles are collected.
    /// Returns a reference to the internal data to avoid cloning the bundles.
    pub fn try_finalize(&self) -> Option<DkgSubsetRef<'_>> {
        if self.complete {
            let combkey = match &self.mode {
                AccumulatorMode::Dkg => None,
                AccumulatorMode::Resharing(combkey) => Some(combkey.clone()),
            };

            Some(DkgSubsetRef {
                committee_id: self.committee().id(),
                bundles: &self.bundles,
                combkey,
            })
        } else {
            None
        }
    }

    /// Create a new finalized accumulator directly from key store and subset.
    pub fn from_subset(key_store: KeyStore, subset: DkgSubset) -> Self {
        let mode = match &subset.combkey {
            None => AccumulatorMode::Dkg,
            Some(combkey) => AccumulatorMode::Resharing(combkey.clone()),
        };
        Self {
            store: key_store,
            bundles: subset.bundles().to_vec(),
            mode,
            complete: true,
        }
    }
}

/// A unified subset that can represent both DKG and Resharing results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DkgSubset {
    committee_id: CommitteeId,
    bundles: Vec<DkgBundle>,
    combkey: Option<ThresholdCombKey>,
}

/// A reference-based version of DkgSubset to avoid cloning bundles.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DkgSubsetRef<'a> {
    committee_id: CommitteeId,
    bundles: &'a [DkgBundle],
    combkey: Option<ThresholdCombKey>,
}

impl DkgSubset {
    /// Create a new subset with DKG bundles.
    pub fn new_dkg(committee_id: CommitteeId, bundles: Vec<DkgBundle>) -> Self {
        Self {
            committee_id,
            bundles,
            combkey: None,
        }
    }

    /// Create a new subset with resharing bundles.
    pub fn new_resharing(
        committee_id: CommitteeId,
        bundles: Vec<DkgBundle>,
        combkey: ThresholdCombKey,
    ) -> Self {
        Self {
            committee_id,
            bundles,
            combkey: Some(combkey),
        }
    }

    /// Get the committee ID.
    pub fn committee_id(&self) -> &CommitteeId {
        &self.committee_id
    }

    /// Get the bundles in this subset.
    pub fn bundles(&self) -> &[DkgBundle] {
        &self.bundles
    }

    /// Get the combiner key if this is a resharing subset.
    pub fn combkey(&self) -> Option<&ThresholdCombKey> {
        self.combkey.as_ref()
    }

    /// Check if this is a DKG subset.
    pub fn is_dkg(&self) -> bool {
        self.combkey.is_none()
    }

    /// Check if this is a resharing subset.
    pub fn is_resharing(&self) -> bool {
        self.combkey.is_some()
    }

    /// Convert this DkgSubset to a DkgSubsetRef.
    pub fn as_ref(&self) -> DkgSubsetRef<'_> {
        DkgSubsetRef {
            committee_id: self.committee_id,
            bundles: &self.bundles,
            combkey: self.combkey.as_ref().cloned(),
        }
    }

    /// Extract the new threshold decryption key from the subset.
    pub fn extract_key(
        &self,
        curr: &KeyStore,
        dkg_sk: &LabeledDkgDecKey,
        prev: Option<&KeyStore>,
    ) -> anyhow::Result<ThresholdKey> {
        self.as_ref().extract_key(curr, dkg_sk, prev)
    }
}

impl<'a> DkgSubsetRef<'a> {
    /// Extract the new threshold decryption key from the subset.
    pub fn extract_key(
        &self,
        curr: &KeyStore,
        dkg_sk: &LabeledDkgDecKey,
        prev: Option<&KeyStore>,
    ) -> anyhow::Result<ThresholdKey> {
        let vess = Vess::new_fast();

        match &self.combkey {
            None => {
                let mut dealings_iter = ResultIter::new(self.bundles.iter().map(|b| {
                    vess.decrypt_share(curr.committee(), dkg_sk, b.vess_ct(), DKG_AAD)
                        .map(|s| (s, b.comm().clone()))
                }));

                let dec_key = ThresholdKey::from_dkg(
                    curr.committee().size().into(),
                    dkg_sk.node_idx(),
                    &mut dealings_iter,
                )?;

                dealings_iter.result()?;
                Ok(dec_key)
            }
            Some(combkey) => {
                let prev = prev.ok_or_else(|| anyhow!("previous key store missing"))?;
                let mut dealings_iter = ResultIter::new(self.bundles.iter().map(|b| {
                    let node_idx = b.origin().0.into();
                    let pub_share = combkey
                        .get_pub_share(node_idx)
                        .ok_or(VessError::FailedVerification)?;
                    vess.decrypt_reshare(curr.committee(), dkg_sk, b.vess_ct(), DKG_AAD, *pub_share)
                        .map(|s| (node_idx, s, b.comm().clone()))
                }));

                let dec_key = ThresholdKey::from_resharing(
                    prev.committee(),
                    curr.committee(),
                    dkg_sk.node_idx(),
                    &mut dealings_iter,
                )?;

                dealings_iter.result()?;
                Ok(dec_key)
            }
        }
    }
}

/// Wrapper iterator that bridges type conversion
/// from Iterator<Item = Result<T, E>> to Iterator<Item = T>
/// while early-returning an Err(E) if any item is an Err, without collecting or allocating memory.
///
/// # Usage
/// ```no_run
/// use timeboost_types::ResultIter;
///
/// fn use_result_iter<I, T, E>(iter: I) -> Result<(), E>
/// where
///     I: Iterator<Item = Result<T, E>>,
/// {
///     let mut result_iter = ResultIter::new(iter);
///     for _ in &mut result_iter {
///         // use item
///     }
///     result_iter.result()
/// }
/// ```
pub struct ResultIter<I, T, E>
where
    I: Iterator<Item = Result<T, E>>,
{
    iter: I,
    error: Option<E>,
}

impl<I, T, E> ResultIter<I, T, E>
where
    I: Iterator<Item = Result<T, E>>,
{
    /// construct a new ResultIter
    pub fn new(iter: I) -> Self {
        Self { iter, error: None }
    }

    /// Get the early-return result
    pub fn result(self) -> Result<(), E> {
        match self.error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl<I, T, E> Iterator for ResultIter<I, T, E>
where
    I: Iterator<Item = Result<T, E>>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() {
            return None;
        }
        match self.iter.next() {
            Some(Ok(v)) => Some(v),
            Some(Err(e)) => {
                self.error = Some(e);
                None
            }
            None => None,
        }
    }
}

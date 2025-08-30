use anyhow::anyhow;
use ark_ec::AffineRepr;
use arrayvec::ArrayVec;
use multisig::{Committee, CommitteeId, KeyId};
use parking_lot::RwLock;
use rayon::prelude::*;
use sailfish_types::{Evidence, RoundNumber};
use serde::{Deserialize, Serialize};
use std::ops::Deref;
use std::{
    collections::{BTreeMap, btree_map},
    sync::Arc,
};
use timeboost_crypto::prelude::{LabeledDkgDecKey, ThresholdEncKey};
use timeboost_crypto::{
    DecryptionScheme,
    feldman::FeldmanVssPublicParam,
    prelude::{DkgEncKey, Vess, Vss},
    traits::{
        dkg::{KeyResharing, VerifiableSecretSharing},
        threshold_enc::ThresholdEncScheme,
    },
    vess::VessError,
};
use tokio::sync::Notify;

use crate::DkgBundle;

const DKG_AAD: &[u8; 3] = b"dkg";

type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;
type PublicKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;
type CombKey = <DecryptionScheme as ThresholdEncScheme>::CombKey;

/// Key materials related to the decryption phase, including the public key for encryption,
/// the per-node key share for decryption, and combiner key for hatching decryption shares into
/// plaintext
#[derive(Debug, Clone)]
pub struct DecryptionKey {
    pubkey: PublicKey,
    combkey: CombKey,
    privkey: KeyShare,
}

impl DecryptionKey {
    pub fn new(pubkey: PublicKey, combkey: CombKey, privkey: KeyShare) -> Self {
        DecryptionKey {
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
        I: Iterator<
            Item = (
                <Vss as VerifiableSecretSharing>::SecretShare,
                <Vss as VerifiableSecretSharing>::Commitment,
            ),
        >,
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
        I: ExactSizeIterator<
                Item = (
                    usize,
                    <Vss as VerifiableSecretSharing>::SecretShare,
                    <Vss as VerifiableSecretSharing>::Commitment,
                ),
            > + Clone,
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
        key_share: <Vss as VerifiableSecretSharing>::SecretShare,
        commitment: &<Vss as VerifiableSecretSharing>::Commitment,
    ) -> anyhow::Result<Self> {
        // note: all .into() are made available via derive_more::From on those structs
        let pk: PublicKey = commitment
            .first()
            .ok_or_else(|| anyhow!("feldman commitment can't be empty"))?
            .into_group()
            .into();

        let combkey: CombKey = (0..committee_size)
            .into_par_iter()
            .map(|idx| Vss::derive_public_share_unchecked(idx, commitment))
            .collect::<Vec<_>>()
            .into();

        let prikey: KeyShare = (key_share, node_idx as u32).into();

        Ok(Self::new(pk, combkey, prikey))
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    pub fn combkey(&self) -> &CombKey {
        &self.combkey
    }

    pub fn privkey(&self) -> &KeyShare {
        &self.privkey
    }
}

/// `DecryptionKeyCell` is a thread-safe container for an optional `DecryptionKey`
/// that allows asynchronous notification when the key is set.
#[derive(Debug, Clone, Default)]
pub struct DecryptionKeyCell {
    key: Arc<RwLock<Option<DecryptionKey>>>,
    notify: Arc<Notify>,
}

impl DecryptionKeyCell {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, key: DecryptionKey) {
        *self.key.write() = Some(key);
        self.notify.notify_waiters();
    }

    pub fn get(&self) -> Option<DecryptionKey> {
        (*self.key.read()).clone()
    }

    pub fn enc_key(&self) -> Option<ThresholdEncKey> {
        self.get().map(|sk| sk.pubkey)
    }

    pub fn get_ref(&self) -> impl Deref<Target = Option<DecryptionKey>> {
        self.key.read()
    }

    pub async fn read(&self) -> DecryptionKey {
        loop {
            let fut = self.notify.notified();
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
pub struct KeyStore {
    committee: Committee,
    keys: Arc<BTreeMap<KeyId, DkgEncKey>>,
}

impl KeyStore {
    pub fn new<I, T>(c: Committee, keys: I) -> Self
    where
        I: IntoIterator<Item = (T, DkgEncKey)>,
        T: Into<KeyId>,
    {
        let this = Self {
            committee: c,
            keys: Arc::new(
                keys.into_iter()
                    .map(|(i, k)| (i.into(), k))
                    .collect::<BTreeMap<_, _>>(),
            ),
        };

        // basic sanity check
        // Current secret sharing impl assumes node_idx/key_id to range from 0..n
        for (node_idx, (key_id, p)) in this.committee.entries().enumerate() {
            assert_eq!(
                KeyId::from(node_idx as u8),
                key_id,
                "{p}'s key ID is not {node_idx}"
            );
            assert!(this.keys.contains_key(&key_id), "{p} has no DkgEncKey");
        }
        for id in this.keys.keys() {
            assert!(
                this.committee.contains_index(id),
                "ID {id:?} not in committee",
            );
        }
        this
    }

    /// Returns a reference to the committee.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// Returns an iterator over all public keys sorted by their node's KeyId
    pub fn sorted_keys(&self) -> btree_map::Values<'_, KeyId, DkgEncKey> {
        self.keys.values()
    }
}

/// The mode of operation for the accumulator.
#[derive(Debug, Clone)]
pub enum AccumulatorMode {
    /// Standard DKG mode
    Dkg,
    /// Resharing mode with the previous committee's combined key
    Resharing(CombKey),
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
    /// Create a new accumulator for DKG operations.
    pub fn new_dkg(store: KeyStore) -> Self {
        Self {
            store,
            bundles: Vec::new(),
            mode: AccumulatorMode::Dkg,
            complete: false,
        }
    }

    /// Create a new accumulator for resharing operations.
    pub fn new_resharing(store: KeyStore, combkey: CombKey) -> Self {
        Self {
            store,
            bundles: Vec::new(),
            mode: AccumulatorMode::Resharing(combkey),
            complete: false,
        }
    }

    /// Get a reference to the committee.
    pub fn committee(&self) -> &Committee {
        &self.store.committee
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
    pub fn try_add(&mut self, bundle: DkgBundle) -> Result<(), VessError> {
        // caller should ensure that no bundles are added after finalization
        if self.bundles().contains(&bundle) || self.complete {
            return Ok(());
        }

        let aad: &[u8; 3] = b"dkg";
        let committee = self.store.committee();
        let vess = Vess::new_fast();

        // verify the bundle based on the mode
        match &self.mode {
            AccumulatorMode::Dkg => {
                vess.verify_shares(
                    committee,
                    self.store.sorted_keys(),
                    bundle.vess_ct(),
                    bundle.comm(),
                    aad,
                )?;
            }
            AccumulatorMode::Resharing(combkey) => {
                let Some(pub_share) = combkey.get_pub_share(bundle.origin().0.into()) else {
                    return Err(VessError::FailedVerification);
                };
                vess.verify_reshares(
                    committee,
                    self.store.sorted_keys(),
                    bundle.vess_ct(),
                    bundle.comm(),
                    aad,
                    *pub_share,
                )?;
            }
        }

        self.bundles.push(bundle);
        // only store the necessary amount of bundles in the accumulator
        if self.bundles.len() >= self.store.committee().one_honest_threshold().into() {
            self.complete = true;
        }
        Ok(())
    }

    /// Try to finalize the accumulator into a subset if enough bundles are collected.
    pub fn try_finalize(&mut self) -> Option<DkgSubset> {
        if self.complete {
            let combkey = match &self.mode {
                AccumulatorMode::Dkg => None,
                AccumulatorMode::Resharing(combkey) => Some(combkey.clone()),
            };

            let subset = DkgSubset {
                committee_id: self.committee().id(),
                bundles: self.bundles.clone(),
                combkey,
            };

            Some(subset)
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
    combkey: Option<CombKey>,
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
        combkey: CombKey,
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
    pub fn combkey(&self) -> Option<&CombKey> {
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

    /// Extract the new threshold decryption key from the subset.
    pub fn extract_key(
        &self,
        curr: &KeyStore,
        dkg_sk: &LabeledDkgDecKey,
        prev: Option<&KeyStore>,
    ) -> anyhow::Result<DecryptionKey> {
        let vess = Vess::new_fast();

        match &self.combkey {
            None => {
                let mut dealings_iter = ResultIter::new(self.bundles().iter().map(|b| {
                    vess.decrypt_share(curr.committee(), dkg_sk, b.vess_ct(), DKG_AAD)
                        .map(|s| (s, b.comm().clone()))
                }));

                let dec_key = DecryptionKey::from_dkg(
                    curr.committee().size().into(),
                    dkg_sk.node_idx(),
                    &mut dealings_iter,
                )?;

                dealings_iter.result()?;

                Ok(dec_key)
            }
            Some(combkey) => {
                let Some(prev) = prev else {
                    return Err(anyhow!("previous key store missing"));
                };

                let dealings: Vec<_> = self
                    .bundles()
                    .iter()
                    .map(|b| {
                        let node_idx = b.origin().0.into();
                        let pub_share = combkey
                            .get_pub_share(node_idx)
                            .ok_or(VessError::FailedVerification)?;
                        let s = vess.decrypt_reshare(
                            curr.committee(),
                            dkg_sk,
                            b.vess_ct(),
                            DKG_AAD,
                            *pub_share,
                        )?;
                        Ok((node_idx, s, b.comm().clone()))
                    })
                    .collect::<Result<Vec<_>, VessError>>()?;
                DecryptionKey::from_resharing(
                    prev.committee(),
                    curr.committee(),
                    dkg_sk.node_idx(),
                    dealings.into_iter(),
                )
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

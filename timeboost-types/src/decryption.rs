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
use timeboost_crypto::prelude::ThresholdCombKey;
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
///
/// Internally, it uses an `RwLock<Option<DecryptionKey>>` to guard the key,
/// and a `Notify` to wake up tasks waiting for the key to become available.
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
    keys: BTreeMap<KeyId, DkgEncKey>,
}

impl KeyStore {
    pub fn new<I, T>(c: Committee, keys: I) -> Self
    where
        I: IntoIterator<Item = (T, DkgEncKey)>,
        T: Into<KeyId>,
    {
        let this = Self {
            committee: c,
            keys: keys
                .into_iter()
                .map(|(i, k)| (i.into(), k))
                .collect::<BTreeMap<_, _>>(),
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

/// Accumulates DKG bundles for a given committee and finalizes when enough have been collected.
///
/// DkgAccumulator tracks received bundles and determines when the threshold for finalizing
/// the DKG process is met. Once enough valid bundles are collected, it can produce a finalized
/// Subset containing the aggregated contributions.
#[derive(Debug, Clone)]
pub struct DkgAccumulator {
    store: KeyStore,
    threshold: usize,
    bundles: Vec<DkgBundle>,
}

impl DkgAccumulator {
    pub fn new(store: KeyStore) -> Self {
        Self {
            threshold: store.committee().one_honest_threshold().get(),
            store,
            bundles: Vec::new(),
        }
    }

    pub fn committee(&self) -> &Committee {
        &self.store.committee
    }

    pub fn bundles(&self) -> &[DkgBundle] {
        &self.bundles
    }

    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    pub fn try_add(&mut self, bundle: DkgBundle) -> Result<(), VessError> {
        // caller should ensure that no bundles are added after finalization
        let aad: &[u8; 3] = b"dkg";
        let committee = self.store.committee();
        let vess = Vess::new_fast();
        vess.verify_shares(
            committee,
            self.store.sorted_keys(),
            bundle.vess_ct(),
            bundle.comm(),
            aad,
        )?;
        self.bundles.push(bundle);
        Ok(())
    }

    pub fn try_finalize(&mut self) -> Option<DkgSubset> {
        if self.bundles.len() >= self.threshold {
            let subset = DkgSubset::new(
                self.committee().id(),
                self.bundles.clone().into_iter().collect(),
            );
            Some(subset)
        } else {
            None
        }
    }
}

/// Represents a finalized subset of DKG bundles sufficient to combine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DkgSubset {
    committe_id: CommitteeId,
    bundles: Vec<DkgBundle>,
}

impl DkgSubset {
    pub fn new(committe_id: CommitteeId, bundles: Vec<DkgBundle>) -> Self {
        Self {
            committe_id,
            bundles,
        }
    }

    pub fn committe_id(&self) -> &CommitteeId {
        &self.committe_id
    }

    pub fn bundles(&self) -> &[DkgBundle] {
        &self.bundles
    }
}

/// Accumulates resharing bundles (see `DkgAccumulator`).
#[derive(Debug, Clone)]
pub struct ResharingAccumulator {
    store: KeyStore,
    threshold: usize,
    combkey: CombKey,
    bundles: Vec<DkgBundle>,
}

impl ResharingAccumulator {
    pub fn new(store: KeyStore, combkey: CombKey) -> Self {
        Self {
            threshold: store.committee().one_honest_threshold().get(),
            store,
            combkey,
            bundles: Vec::new(),
        }
    }

    pub fn committee(&self) -> &Committee {
        &self.store.committee
    }

    pub fn bundles(&self) -> &[DkgBundle] {
        &self.bundles
    }

    pub fn combkey(&self) -> &ThresholdCombKey {
        &self.combkey
    }

    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    pub fn try_add(&mut self, bundle: DkgBundle) -> Result<(), VessError> {
        // caller should ensure that no bundles are added after finalization
        let Some(pub_share) = self.combkey.get_pub_share(bundle.origin().0.into()) else {
            return Err(VessError::FailedVerification);
        };

        let aad: &[u8; 3] = b"dkg";
        let committee = self.store.committee();
        let vess = Vess::new_fast();
        vess.verify_reshares(
            committee,
            self.store.sorted_keys(),
            bundle.vess_ct(),
            bundle.comm(),
            aad,
            *pub_share,
        )?;
        self.bundles.push(bundle);
        Ok(())
    }

    pub fn try_finalize(&mut self) -> Option<ResharingSubset> {
        if self.bundles.len() >= self.threshold {
            let subset = ResharingSubset::new(
                self.committee().id(),
                self.bundles.clone().into_iter().collect(),
                self.combkey().clone(),
            );
            Some(subset)
        } else {
            None
        }
    }
}

/// Represents a finalized subset of resharing bundles sufficient to combine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ResharingSubset {
    committee_id: CommitteeId,
    bundles: Vec<DkgBundle>,
    combkey: CombKey,
}

impl ResharingSubset {
    pub fn new(committee_id: CommitteeId, bundles: Vec<DkgBundle>, combkey: CombKey) -> Self {
        Self {
            committee_id,
            bundles,
            combkey,
        }
    }

    pub fn committee_id(&self) -> &CommitteeId {
        &self.committee_id
    }

    pub fn bundles(&self) -> &[DkgBundle] {
        &self.bundles
    }

    pub fn combkey(&self) -> &CombKey {
        &self.combkey
    }
}

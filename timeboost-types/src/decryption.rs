use std::collections::{BTreeMap, HashMap};

use either::Either;
use multisig::{Committee, CommitteeId, KeyId};
use timeboost_crypto::{
    DecryptionScheme, prelude::DkgEncKey, traits::threshold_enc::ThresholdEncScheme,
};

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

/// A `Committee` with everyone's public key used in the DKG or key resharing for secure
/// communication
#[derive(Debug, Clone)]
pub struct DkgKeyStore {
    committee: Committee,
    keys: BTreeMap<KeyId, DkgEncKey>,
}

impl DkgKeyStore {
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

    /// Returns an iterator over all public keys sorted by their node's KeyId
    pub fn sorted_keys(&self) -> impl Iterator<Item = &DkgEncKey> {
        self.keys.values()
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }
}

#[derive(Debug, Clone)]
pub struct DkgAccumulator {
    store: DkgKeyStore,
    threshold: usize,
    bundles: HashMap<CommitteeId, BTreeMap<KeyId, DkgBundle>>,
    subset: Option<ValidSubset>,
}

#[derive(Debug, Clone)]
pub struct ValidSubset {
    committe_id: CommitteeId,
    bundles: BTreeMap<KeyId, DkgBundle>,
}

impl ValidSubset {
    pub fn new(committe_id: CommitteeId, bundles: BTreeMap<KeyId, DkgBundle>) -> Self {
        Self {
            committe_id,
            bundles,
        }
    }

    pub fn committee_id(&self) -> &CommitteeId {
        &self.committe_id
    }

    pub fn bundles(&self) -> &BTreeMap<KeyId, DkgBundle> {
        &self.bundles
    }
}

impl DkgAccumulator {
    pub fn new(committee: DkgKeyStore) -> Self {
        Self {
            threshold: committee.committee().one_honest_threshold().get(),
            store: committee,
            bundles: HashMap::new(),
            subset: None,
        }
    }

    pub fn committee(&self) -> &Committee {
        &self.store.committee
    }

    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Return the amount of bundles for a given committee.
    pub fn bundles(&self, c: &Committee) -> usize {
        self.bundles.get(&c.id()).map(|b| b.len()).unwrap_or(0)
    }

    /// Return iterator for each public key for a given committee.
    pub fn submitters(&self, c: &CommitteeId) -> impl Iterator<Item = &multisig::PublicKey> {
        if let Some(e) = self.bundles.get(c) {
            Either::Right(e.iter().filter_map(|i| self.store.committee.get_key(*i.0)))
        } else {
            Either::Left(std::iter::empty())
        }
    }

    /// Returns a reference to the subset, if available.
    pub fn subset(&self) -> Option<&ValidSubset> {
        self.subset.as_ref()
    }

    /// Consumes this dkg accumulator and returns the subset, if available.
    pub fn into_subset(self) -> Option<ValidSubset> {
        self.subset
    }

    /// Adds a bundle into the dkg accumulator.
    ///
    /// This function will:
    /// - Validate the origin of the bundle
    /// - Add the bundle into the accumulator if we have not seen it yet
    /// - Create a subset if we have t + 1 bundles
    pub fn add(&mut self, bundle: DkgBundle) -> Result<Option<&ValidSubset>, Error> {
        let Some(ix) = self.store.committee.get_index(bundle.origin()) else {
            return Err(Error::UnknownDkgSubmitter);
        };

        let committee = bundle.committee_id();

        let entry_set = self.bundles.entry(*committee).or_default();

        if entry_set.contains_key(&ix) {
            return Ok(self.subset());
        }
        entry_set.insert(ix, bundle.clone());

        if entry_set.len() < self.threshold {
            return Ok(None);
        }

        let subset = ValidSubset::new(*committee, entry_set.clone());
        self.subset = Some(subset);

        Ok(self.subset())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unknown dkg bundle submitter")]
    UnknownDkgSubmitter,
}

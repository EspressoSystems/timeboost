use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use bimap::BiBTreeMap;

use super::{KeyId, PublicKey, Version};
use parking_lot::RwLock;

const DEFAULT_MAX_VERSIONS: usize = 2;

#[derive(Debug, Clone)]
pub struct Committee {
    parties: Arc<RwLock<BTreeMap<Version, CommitteeView>>>,
    max_versions: usize,
}

#[derive(Debug, Clone)]
pub struct CommitteeView {
    version: Version,
    parties: Arc<BiBTreeMap<KeyId, PublicKey>>,
}

impl Committee {
    /// Create a new committee with a given version.
    ///
    /// Also configure how many versions can exist at most.
    /// `Committee::try_add` will automatically remove the oldest version
    /// when approaching the limit.
    ///
    /// # Panics
    ///
    /// If the given iterator of parties is empty.
    pub fn new<I, T, V>(v: V, it: I) -> Self
    where
        I: IntoIterator<Item = (T, PublicKey)>,
        T: Into<KeyId>,
        V: Into<Version>,
    {
        let this = Self {
            parties: Default::default(),
            max_versions: DEFAULT_MAX_VERSIONS,
        };
        this.try_add(v, it).expect("empty map => no version error");
        this
    }

    /// Set the max. number of supported versions.
    ///
    /// This will also remove all entries that exceed the new maximum.
    pub fn set_max_versions(&mut self, m: NonZeroUsize) {
        let mut parties = self.parties.write();
        while parties.len() > m.get() {
            parties.pop_first();
        }
        self.max_versions = m.get()
    }

    /// View a committee at the given version.
    pub fn at(&self, v: Version) -> Option<CommitteeView> {
        let p = self.parties.read();
        p.get(&v).cloned()
    }

    /// Get the latest committee version.
    pub fn latest(&self) -> CommitteeView {
        let p = self.parties.read();
        p.last_key_value().expect("some committee exists").1.clone()
    }

    /// Get the latest version number.
    pub fn latest_version(&self) -> Version {
        let p = self.parties.read();
        *p.last_key_value().expect("some committee exists").0
    }

    /// Try to add a new committee.
    ///
    /// The version needs to be greater than the latest version. This will
    /// also remove the oldest version, if more than the configured max. number
    /// of versions exist.
    ///
    /// # Panics
    ///
    /// If the given iterator of parties is empty.
    pub fn try_add<I, T, V>(&self, v: V, it: I) -> Result<(), VersionError>
    where
        I: IntoIterator<Item = (T, PublicKey)>,
        T: Into<KeyId>,
        V: Into<Version>,
    {
        let v = v.into();
        let map = BiBTreeMap::from_iter(it.into_iter().map(|(i, k)| (i.into(), k)));
        assert!(!map.is_empty());
        let view = CommitteeView {
            version: v,
            parties: Arc::new(map),
        };
        let mut parties = self.parties.write();
        let latest = parties.last_key_value().map(|entry| entry.0).copied();
        if Some(v) <= latest {
            return Err(VersionError::Collision);
        }
        parties.insert(v, view);
        while parties.len() > self.max_versions {
            parties.pop_first();
        }
        Ok(())
    }

    /// Try to delete a committee by version.
    ///
    /// All versions other than the latest can be removed.
    pub fn try_remove(&self, v: Version) -> Result<(), VersionError> {
        let mut parties = self.parties.write();
        let latest = *parties.last_key_value().expect("some committee exists").0;
        if v == latest {
            return Err(VersionError::RemoveLastestVersion);
        }
        parties.remove(&v);
        Ok(())
    }
}

impl CommitteeView {
    /// The version of this committee.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns the size of the committee as a non-zero unsigned integer.
    pub fn size(&self) -> NonZeroUsize {
        NonZeroUsize::new(self.parties.len()).expect("committee is not empty")
    }

    /// Returns the at-least-one-honest threshold for consensus,
    /// which is `ceil(n/3)` where `n` is the committee size.
    pub fn one_honest_threshold(&self) -> NonZeroUsize {
        let t = self.parties.len().div_ceil(3);
        NonZeroUsize::new(t).expect("ceil(n/3) with n > 0 never gives 0")
    }

    /// Computes the quorum size
    pub fn quorum_size(&self) -> NonZeroUsize {
        let q = self.parties.len() * 2 / 3 + 1;
        NonZeroUsize::new(q).expect("n + 1 > 0")
    }

    /// Retrieves the public key associated with the given key ID.
    pub fn get_key<T: Into<KeyId>>(&self, ix: T) -> Option<&PublicKey> {
        self.parties.get_by_left(&ix.into())
    }

    /// Finds the key ID for a given public key.
    pub fn get_index(&self, k: &PublicKey) -> Option<KeyId> {
        self.parties.get_by_right(k).copied()
    }

    /// Checks if a public key is part of the committee.
    pub fn contains_key(&self, k: &PublicKey) -> bool {
        self.parties.contains_right(k)
    }

    /// Returns an iterator over all entries in the committee.
    pub fn entries(&self) -> impl Iterator<Item = (KeyId, &PublicKey)> {
        self.parties.iter().map(|e| (*e.0, e.1))
    }

    /// Provides an iterator over all public keys in the committee.
    pub fn parties(&self) -> impl Iterator<Item = &PublicKey> {
        self.parties.right_values()
    }

    /// Determines the leader for a given round number using a round-robin method.
    pub fn leader(&self, round: usize) -> PublicKey {
        let i = round % self.parties.len();
        self.parties
            .right_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }

    /// Returns the key ID of the leader for a given round number.
    pub fn leader_index(&self, round: usize) -> KeyId {
        let i = round % self.parties.len();
        self.parties
            .left_values()
            .nth(i)
            .copied()
            .expect("round % len < len")
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VersionError {
    #[error("version already exists")]
    Collision,

    #[error("can not remove latest version")]
    RemoveLastestVersion,
}

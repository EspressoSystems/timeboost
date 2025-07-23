use std::collections::{BTreeMap, HashSet, btree_map};

use anyhow::anyhow;
use ark_ec::{AffineRepr, CurveGroup};
use multisig::{Committee, CommitteeId, KeyId};
use rayon::prelude::*;
use timeboost_crypto::{
    DecryptionScheme,
    prelude::{DkgEncKey, Vess, Vss},
    traits::{dkg::VerifiableSecretSharing, threshold_enc::ThresholdEncScheme},
    vess::VessError,
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

    /// Construct all key material for threshold decryption from DKG outputs.
    /// The ACS subprotocol in DKG outputs a subset of commitments and key shares.
    ///
    /// # Parameters
    /// - `committee_size`: size of the threshold committee
    /// - `node_idx`: in 0..committee_size, currently same as KeyId
    /// - `commitments`: the Feldman Commitments: multiple output of `ShoupVess::encrypted_shares()`
    /// - `key_shares`: multiple decrypted secret shares from `ShoupVess::decrypt_share()`
    pub fn from_dkg(
        committee_size: usize,
        node_idx: usize,
        commitments: &[<Vss as VerifiableSecretSharing>::Commitment],
        key_shares: &[<Vss as VerifiableSecretSharing>::SecretShare],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            commitments.len() == key_shares.len(),
            "mismatched input length"
        );

        // aggregate selected dealings/contributions
        let agg_comm = commitments
            .par_iter()
            .cloned()
            .reduce_with(|a, b| {
                let combined: Vec<_> = a
                    .into_iter()
                    .zip(b.into_iter())
                    // NOTE: ideally we can use C::normalize_batch(), but C is not exposed,
                    // minor optimization, so ignore for now.
                    .map(|(x, y)| (x + y).into_affine())
                    .collect();
                combined.into()
            })
            .ok_or_else(|| anyhow!("no commitments provided"))?;
        let agg_key_share = key_shares.iter().sum();

        // derive key material
        Self::from_single_dkg(committee_size, node_idx, &agg_comm, agg_key_share)
    }

    /// inner routine to construct from a single (aggregated or interpolated) DKG output,
    /// shared in both DKG and resharing logic.
    fn from_single_dkg(
        committee_size: usize,
        node_idx: usize,
        commitment: &<Vss as VerifiableSecretSharing>::Commitment,
        key_share: <Vss as VerifiableSecretSharing>::SecretShare,
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

    pub fn from_resharing() -> anyhow::Result<Self> {
        todo!("after #406 merged, invoked FeldmanVss.combine(), then from_single_dkg()")
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

    /// Returns a reference to the committee.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// Returns an iterator over all public keys sorted by their node's KeyId
    pub fn sorted_keys(&self) -> btree_map::Values<KeyId, DkgEncKey> {
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
    store: DkgKeyStore,
    threshold: usize,
    bundles: HashSet<DkgBundle>,
}

impl DkgAccumulator {
    pub fn new(store: DkgKeyStore) -> Self {
        Self {
            threshold: store.committee().one_honest_threshold().get(),
            store,
            bundles: HashSet::new(),
        }
    }

    pub fn committee(&self) -> &Committee {
        &self.store.committee
    }

    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    pub fn try_add(&mut self, bundle: DkgBundle) -> Result<(), VessError> {
        let aad: &[u8; 3] = b"dkg";
        let committee = self.store.committee();
        let vess = Vess::new_fast_from(committee);
        vess.verify(
            self.store.sorted_keys(),
            bundle.vess_ct(),
            bundle.comm(),
            aad,
        )?;
        self.bundles.insert(bundle);
        Ok(())
    }

    pub fn try_finalize(&self) -> Option<Subset> {
        if self.bundles.len() >= self.threshold {
            Some(Subset {
                committe_id: self.committee().id(),
                bundles: &self.bundles,
            })
        } else {
            None
        }
    }
}

/// Represents a finalized subset of DKG bundles sufficient to combine.
#[derive(Debug, Clone)]
pub struct Subset<'a> {
    committe_id: CommitteeId,
    bundles: &'a HashSet<DkgBundle>,
}

impl<'a> Subset<'a> {
    pub fn committe_id(&self) -> &CommitteeId {
        &self.committe_id
    }

    pub fn bundles(&self) -> &HashSet<DkgBundle> {
        self.bundles
    }
}

#[test]
fn test_dkg_e2e() {
    use ark_std::rand::seq::SliceRandom;
    use ark_std::{UniformRand, rand::thread_rng};
    use timeboost_crypto::Plaintext;
    use timeboost_crypto::prelude::DkgDecKey;
    use timeboost_crypto::prelude::{Vess, Vss};

    // Test parameters
    let committee_size = 5;
    let dkg_aad: &[u8; 3] = b"dkg";
    let threshold_aad = b"threshold";
    let mut rng = thread_rng();

    // Setup committee with keypairs
    let committee_keys: Vec<_> = (0..committee_size)
        .map(|i| (i as u8, multisig::Keypair::generate().public_key()))
        .collect();
    let committee = Committee::new(committee_size as u64, committee_keys);
    let threshold = committee.one_honest_threshold().get();

    // Generate DKG keypairs for secure communication
    let dkg_priv_keys: Vec<_> = (0..committee_size)
        .map(|_| DkgDecKey::rand(&mut rng))
        .collect();
    let dkg_pub_keys: Vec<_> = dkg_priv_keys.iter().map(DkgEncKey::from).collect();

    let vess = Vess::new_fast_from(&committee);

    // Generate dealings: each committee member contributes a random secret
    let dealings: Vec<_> = (0..committee_size)
        .map(|_| {
            let secret = <Vss as VerifiableSecretSharing>::Secret::rand(&mut rng);
            vess.encrypted_shares(&dkg_pub_keys, secret, dkg_aad)
                .unwrap()
        })
        .collect();

    // Simulate ACS: randomly select subset of dealings for aggregation
    let mut dealing_indices: Vec<_> = (0..committee_size).collect();
    dealing_indices.shuffle(&mut rng);
    let selected_dealings = &dealing_indices[..threshold];

    // Extract commitments from selected dealings
    let commitments: Vec<_> = selected_dealings
        .iter()
        .map(|&idx| dealings[idx].1.clone())
        .collect();

    // Decrypt shares for each node from selected dealings
    let node_shares: Vec<Vec<_>> = (0..committee_size)
        .map(|node_idx| {
            let labeled_sk = dkg_priv_keys[node_idx].clone().label(node_idx);
            selected_dealings
                .iter()
                .map(|&dealing_idx| {
                    let (ref ciphertext, _) = dealings[dealing_idx];
                    vess.decrypt_share(&labeled_sk, ciphertext, dkg_aad)
                        .expect("decryption should succeed")
                })
                .collect()
        })
        .collect();

    // Generate threshold decryption keys for each node
    let threshold_keys: Vec<_> = node_shares
        .iter()
        .enumerate()
        .map(|(node_idx, shares)| {
            super::DecryptionKey::from_dkg(committee_size, node_idx, &commitments, shares)
                .expect("from_dkg should succeed")
        })
        .collect();

    // Verify all nodes derive the same public and combiner keys
    let (expected_pubkey, expected_combkey) = {
        let first = &threshold_keys[0];
        (first.pubkey(), first.combkey())
    };

    for (idx, key) in threshold_keys.iter().enumerate().skip(1) {
        assert_eq!(
            key.pubkey(),
            expected_pubkey,
            "Node {idx} has mismatched public key"
        );
        assert_eq!(
            key.combkey(),
            expected_combkey,
            "Node {idx} has mismatched combiner key"
        );
    }

    // Test threshold encryption/decryption
    let test_plaintext = Plaintext::new(b"fox jumps over the lazy dog".to_vec());
    let ciphertext = DecryptionScheme::encrypt(
        &mut rng,
        expected_pubkey,
        &test_plaintext,
        &threshold_aad.to_vec(),
    )
    .expect("encryption should succeed");

    // Generate decryption shares from all nodes
    let decryption_shares: Vec<_> = threshold_keys
        .iter()
        .map(|key| {
            DecryptionScheme::decrypt(key.privkey(), &ciphertext, &threshold_aad.to_vec())
                .expect("decryption share should succeed")
        })
        .collect();

    // Combine threshold number of shares to recover plaintext
    let selected_shares: Vec<_> = decryption_shares.iter().take(threshold).collect();
    let recovered = DecryptionScheme::combine(
        &committee,
        expected_combkey,
        selected_shares,
        &ciphertext,
        &threshold_aad.to_vec(),
    )
    .expect("combine should succeed");

    assert_eq!(
        recovered, test_plaintext,
        "Recovered plaintext should match original"
    );
}

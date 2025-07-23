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

    // Parameters
    let committee_size = 5;
    let aad: &[u8; 3] = b"dkg";
    let mut rng = thread_rng();

    let committee_keys: Vec<_> = (0..committee_size)
        .map(|i| (i as u8, multisig::Keypair::generate().public_key()))
        .collect();
    let committee = Committee::new(committee_size as u64, committee_keys);

    // Generate keypairs for the committee
    let dkg_priv_keys: Vec<_> = (0..committee_size)
        .map(|_| DkgDecKey::rand(&mut rng))
        .collect();

    let dkg_keys: Vec<_> = dkg_priv_keys.iter().map(|k| DkgEncKey::from(k)).collect();

    // Generate a random secret
    let secret = <Vss as VerifiableSecretSharing>::Secret::rand(&mut rng);

    // Create Vess instance
    let vess = Vess::new_fast_from(&committee);

    // Encrypt shares and get Feldman commitment
    let (ciphertexts, commitments) = vess
        .encrypted_shares(&dkg_keys, secret.clone(), aad)
        .unwrap();

    // Choose a random subset of ciphertexts to decrypt
    let mut indices: Vec<_> = (0..committee_size).collect();
    indices.shuffle(&mut rng);
    let chosen_indices = &indices[..committee.one_honest_threshold().get()];

    // Decrypt the chosen shares
    let mut shares = Vec::new();
    let mut comms = Vec::new();
    for &i in chosen_indices {
        let labeled_key = dkg_priv_keys[i].clone().label(i);

        let share = vess
            .decrypt_share(&labeled_key, &ciphertexts, aad)
            .expect("decryption should succeed");
        shares.push(share);
        comms.push(commitments.clone()); // All commitments are the same in this context
    }

    // Use from_dkg to obtain the DecryptionKey for each node
    let mut thres_dec_keys = Vec::new();
    for node_idx in 0..committee_size {
        let thres_dec_key =
            super::DecryptionKey::from_dkg(committee_size, node_idx, &comms, &shares)
                .expect("from_dkg should succeed");
        thres_dec_keys.push(thres_dec_key);
    }
    let first_pubkey = thres_dec_keys[0].pubkey();
    let first_combkey = thres_dec_keys[0].combkey();
    for node_idx in 1..committee_size {
        assert_eq!(
            thres_dec_keys[node_idx].pubkey(),
            first_pubkey,
            "pubkeys should be identical for all nodes: idx={}, pubkey={:?}, first_pubkey={:?}",
            node_idx,
            thres_dec_keys[node_idx].pubkey(),
            first_pubkey
        );
        assert_eq!(
            thres_dec_keys[node_idx].combkey(),
            first_combkey,
            "combkeys should be identical for all nodes: idx={}, combkey={:?}, first_combkey={:?}",
            node_idx,
            thres_dec_keys[node_idx].combkey(),
            first_combkey
        );
    }

    let ad = b"threshold";

    // Create a plaintext and encrypt it with the derived threshold public key
    let test_plaintext = Plaintext::new(b"fox jumps over the lazy dog".to_vec());
    let pubkey = thres_dec_keys[0].pubkey();
    let ciphertext = DecryptionScheme::encrypt(&mut rng, &pubkey, &test_plaintext, &ad.to_vec())
        .expect("encryption should succeed");

    // Each node computes its decryption share
    let mut dec_shares = Vec::new();
    for dec_key in thres_dec_keys.iter() {
        let share = DecryptionScheme::decrypt(dec_key.privkey(), &ciphertext, &ad.to_vec())
            .expect("decryption share should succeed");
        dec_shares.push(share);
    }

    // Select threshold number of shares and combine to recover the plaintext
    let selected_shares: Vec<_> = dec_shares
        .iter()
        .take(committee.one_honest_threshold().get())
        .collect();

    let recovered = DecryptionScheme::combine(
        &committee,
        thres_dec_keys[0].combkey(),
        selected_shares,
        &ciphertext,
        &ad.to_vec(),
    )
    .expect("combine should succeed");
    assert_eq!(
        recovered, test_plaintext,
        "decrypted plaintext matches original"
    );
}

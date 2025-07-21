use std::collections::BTreeMap;

use anyhow::anyhow;
use ark_ec::{AffineRepr, CurveGroup};
use multisig::{Committee, KeyId};
use rayon::prelude::*;
use timeboost_crypto::{
    DecryptionScheme,
    prelude::{DkgEncKey, Vss},
    traits::{dkg::VerifiableSecretSharing, threshold_enc::ThresholdEncScheme},
};

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

    /// Returns an iterator over all public keys sorted by their node's KeyId
    pub fn sorted_keys(&self) -> impl Iterator<Item = &DkgEncKey> {
        self.keys.values()
    }
}

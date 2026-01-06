use crate::serde_bridge::SerdeAs;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use anyhow::anyhow;
use ark_ec::{AffineRepr, CurveGroup, hashing::HashToCurve};
use ark_ff::{PrimeField, UniformRand};
use ark_poly::{DenseUVPolynomial, Polynomial, polynomial::univariate::DensePolynomial};
use ark_serialize::SerializationError;
use ark_std::rand::Rng;
use ark_std::rand::rngs::OsRng;
use derive_more::From;
use digest::{Digest, generic_array::GenericArray};
use multisig::Committee;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use spongefish::DuplexSpongeInterface;
use std::marker::PhantomData;
use std::{
    any::TypeId,
    collections::BTreeSet,
    io::{BufWriter, Write},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::cp_proof::Proof;
use crate::interpolation::interpolate_in_exponent;
use crate::{
    cp_proof::{ChaumPedersen, DleqTuple},
    traits::{
        dleq_proof::DleqProofScheme,
        tpke::{ThresholdEncError, ThresholdEncScheme},
    },
};

/// Shoup-Gennaro [[SG01]](https://www.shoup.net/papers/thresh1.pdf) threshold encryption scheme (TDH2)
/// instantiated as a key encapsulation mechanism (hybrid cryptosystem) for a symmetric key.
///
/// NOTE:
/// 1. k-out-of-n threshold scheme means >= k correct decryption shares lead to successful
///    `combine()` in the case of timeboost, k=f+1 where f is the (inclusive) faulty nodes
pub struct ShoupGennaro<C, H, D, H2C>
where
    C: CurveGroup,
    H: Digest,
    D: DuplexSpongeInterface,
    H2C: HashToCurve<C>,
{
    _group: PhantomData<C>,
    _hash: PhantomData<H>,
    _duplex: PhantomData<D>,
    _hash_to_curve: PhantomData<H2C>,
}

impl<C, H, D, H2C> ThresholdEncScheme for ShoupGennaro<C, H, D, H2C>
where
    H: Digest,
    D: DuplexSpongeInterface,
    C: CurveGroup,
    C::ScalarField: PrimeField,
    H2C: HashToCurve<C>,
{
    type Committee = Committee;
    type PublicKey = PublicKey<C>;
    type CombKey = CombKey<C>;
    type KeyShare = KeyShare<C>;
    type Plaintext = Plaintext;
    type AssociatedData = Vec<u8>;
    type Ciphertext = Ciphertext<C>;
    type DecShare = DecShare<C>;

    fn keygen<R: Rng>(
        rng: &mut R,
        committee: &Committee,
    ) -> Result<(Self::PublicKey, Self::CombKey, Vec<Self::KeyShare>), ThresholdEncError> {
        let committee_size = committee.size().get();
        let degree = committee.one_honest_threshold().get() - 1;
        let generator = C::generator();
        let mut poly: DensePolynomial<_> = DensePolynomial::rand(degree, rng);

        let mut alpha_0 = poly[0];

        // Evaluate polynomial at points 1, 2, 3, ..., committee_size (same as Feldman VSS)
        let mut evals = Vec::with_capacity(committee_size);
        for i in 0..committee_size {
            let eval_point = C::ScalarField::from((i + 1) as u64);
            let eval = poly.evaluate(&eval_point);
            evals.push(eval);
        }

        let u_0 = generator * alpha_0;
        let pub_key = PublicKey { key: u_0 };
        let comb_key = CombKey {
            key: evals.iter().map(|alpha| generator * alpha).collect(),
        };

        let key_shares = evals
            .into_iter()
            .enumerate()
            .map(|(i, alpha)| KeyShare {
                share: alpha,
                index: i as u32,
            })
            .collect();

        alpha_0.zeroize();
        poly.coeffs.zeroize();
        Ok((pub_key, comb_key, key_shares))
    }

    fn encrypt<R: Rng>(
        rng: &mut R,
        pub_key: &Self::PublicKey,
        message: &Self::Plaintext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Ciphertext, ThresholdEncError> {
        let beta = C::ScalarField::rand(rng);
        let generator = C::generator();
        let v = generator * beta;
        let w = pub_key.key * beta;

        let key = hash_to_key::<C, H>(v, w)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to key failed: {:?}", e)))?;
        let k = GenericArray::from_slice(&key);

        // AES encrypt using `k`, `nonce` and `message`
        let cipher = <Aes256Gcm as KeyInit>::new(k);
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let payload = Payload {
            msg: &message.0,
            aad,
        };
        let e = Aead::encrypt(&cipher, &nonce, payload).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Unable to encrypt plaintext: {:?}", e))
        })?;
        let u_hat = hash_to_curve::<C, H2C>(v, e.clone(), aad.clone())?;

        let w_hat = u_hat * beta;

        // Produce DLEQ proof for CCA security
        let tuple = DleqTuple::new(generator, v, u_hat, w_hat);
        let pi = ChaumPedersen::<C, D>::prove(tuple, &beta).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Encrypt: Proof generation failed: {:?}", e))
        })?;

        Ok(Ciphertext {
            v,
            w_hat,
            nonce,
            e,
            pi,
        })
    }

    fn decrypt(
        sk: &Self::KeyShare,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::DecShare, ThresholdEncError> {
        let generator = C::generator();
        let alpha = sk.share;
        let v = ciphertext.v;

        // check ciphertext integrity against associated data
        Self::ct_check(ciphertext, aad)?;

        let w = v * alpha;
        let u_i = generator * alpha;
        let tuple = DleqTuple::new(generator, u_i, v, w);
        let phi =
            ChaumPedersen::<C, D>::prove(tuple, &alpha).map_err(ThresholdEncError::DleqError)?;

        Ok(DecShare {
            w,
            index: sk.index,
            phi,
        })
    }

    fn combine(
        committee: &Committee,
        comb_key: &Self::CombKey,
        dec_shares: Vec<&Self::DecShare>,
        ciphertext: &Self::Ciphertext,
        aad: &Self::AssociatedData,
    ) -> Result<Self::Plaintext, ThresholdEncError> {
        let threshold = committee.one_honest_threshold().get();
        let generator = C::generator();

        // check ciphertext integrity against associated data
        Self::ct_check(ciphertext, aad)?;

        if dec_shares.len() < threshold {
            return Err(ThresholdEncError::NotEnoughShares);
        }

        let pk_comb = comb_key.key.clone();

        // Verify DLEQ proofs to ensure correctness of the decryption share w_i
        // keeping a list of faulty shares (their node indices) to blame
        let mut valid_shares = Vec::new();
        let mut faulty_shares = Vec::new();
        for share in &dec_shares {
            let (w, phi) = (share.w, &share.phi);
            let u = pk_comb.get(share.index as usize).ok_or_else(|| {
                ThresholdEncError::Argument(format!("CombKey missing idx: {}", share.index))
            })?;

            let tuple = DleqTuple::new(generator, *u, ciphertext.v, w);
            if ChaumPedersen::<C, D>::verify(tuple, phi).is_ok() {
                valid_shares.push(share);
            } else {
                faulty_shares.push(share);
            }
        }

        let mut faulty_subset = BTreeSet::new();
        for s in faulty_shares {
            faulty_subset.insert(s.index);
        }
        if valid_shares.len() < threshold {
            return Err(ThresholdEncError::FaultySubset(faulty_subset));
        }

        // Collect eval points using simple evaluation points (same as Feldman VSS)
        let (x, w_vec): (Vec<_>, Vec<_>) = dec_shares
            .iter()
            .take(threshold)
            .map(|share| (C::ScalarField::from((share.index + 1) as u64), share.w))
            .unzip();

        // interpolate in the exponent
        let w = interpolate_in_exponent(&x, &C::normalize_batch(&w_vec)).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Interpolate in the exponent failed: {:?}", e))
        })?;

        // Hash to symmetric key `k`
        let key = hash_to_key::<C, H>(ciphertext.v, w)
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to key failed: {:?}", e)))?;
        let k = GenericArray::from_slice(&key);
        let cipher = <Aes256Gcm as KeyInit>::new(k);

        let payload = Payload {
            msg: &ciphertext.e.clone(),
            aad,
        };
        let plaintext = Aead::decrypt(&cipher, &ciphertext.nonce, payload).map_err(|e| {
            ThresholdEncError::Internal(anyhow!("Symmetric decrypt failed: {:?}", e))
        })?;
        Ok(Plaintext(plaintext))
    }
}

impl<C, H, D, H2C> ShoupGennaro<C, H, D, H2C>
where
    C: CurveGroup,
    H: Digest,
    D: DuplexSpongeInterface,
    H2C: HashToCurve<C>,
{
    fn ct_check(
        ct: &Ciphertext<C>,
        aad: &<Self as ThresholdEncScheme>::AssociatedData,
    ) -> Result<(), ThresholdEncError> {
        let g = C::generator();
        let (v, e, w_hat, pi) = (ct.v, ct.e.clone(), ct.w_hat, ct.pi.clone());

        let u_hat = hash_to_curve::<C, H2C>(v, e, aad.clone())
            .map_err(|e| ThresholdEncError::Internal(anyhow!("Hash to curve failed: {:?}", e)))?;
        let tuple = DleqTuple::new(g, v, u_hat, w_hat);
        ChaumPedersen::<C, D>::verify(tuple, &pi).map_err(ThresholdEncError::DleqError)?;

        Ok(())
    }
}

fn hash_to_curve<C, H2C>(v: C, e: Vec<u8>, aad: Vec<u8>) -> Result<C, ThresholdEncError>
where
    C: CurveGroup,
    H2C: HashToCurve<C>,
{
    // first serialize preimages into bytes as input message to the HashToCurve function
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    writer.write(&e)?;
    writer.write(&aad)?;
    writer.flush()?;
    drop(writer);

    // Currently, we only support BLS12-381's G1 as its HashToCurve is available in arkworks,
    // will add support for more curves in the future using SW06 method
    // <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-shallue-van-de-woestijne-me>
    //
    // maintenance note: update domain separator when Timeboost has minor version upgrade or there
    // are multiple usages of HashToCurve oracle (currently we only have 1 in threshold
    // signature, assigned with `CS01`). e.g. Timeboost upgraded to `2.4.x` and there are 3
    // occurrences of this oracles, the full tag should be:
    // `TIMEBOOST-V24-CS03-with-BLS12381G1_XMD:SHA-256_SSWU_RO_`
    // See: <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-domain-separation-requireme>
    // and <https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-16.html#name-suite-id-naming-conventions>
    let curve_type_id = TypeId::of::<C>();
    if curve_type_id == TypeId::of::<ark_bls12_381::G1Projective>() {
        let h2c_hasher =
            H2C::new(b"TIMEBOOST-V01-CS01-with-BLS12381G1_XMD:SHA-256_SSWU_RO_".as_ref())?;
        Ok(h2c_hasher.hash(&buffer)?.into_group())
    } else {
        Err(ThresholdEncError::UnsupportedCurve)
    }
}

fn hash_to_key<C: CurveGroup, H: Digest>(v: C, w: C) -> Result<Vec<u8>, ThresholdEncError> {
    let mut hasher = H::new();
    let mut buffer = Vec::new();
    let mut writer = BufWriter::new(&mut buffer);
    v.serialize_compressed(&mut writer)?;
    w.serialize_compressed(&mut writer)?;
    writer.flush()?;
    drop(writer);
    hasher.update(buffer);
    let key = hasher.finalize();
    Ok(key.to_vec())
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, From, Hash)]
pub struct CombKey<C: CurveGroup> {
    #[serde_as(as = "Vec<SerdeAs>")]
    pub key: Vec<C>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, From, Hash)]
pub struct PublicKey<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    key: C,
}

impl<C: CurveGroup> PublicKey<C> {
    pub fn to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut v = Vec::new();
        self.key.serialize_compressed(&mut v)?;
        Ok(v)
    }

    pub fn from_bytes(value: &[u8]) -> Result<Self, SerializationError> {
        let key = C::deserialize_compressed(value)?;
        Ok(Self { key })
    }
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, From)]
pub struct KeyShare<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    share: C::ScalarField,
    index: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Plaintext(Vec<u8>);

#[serde_as]
#[derive(Clone, Debug, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ciphertext<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    v: C,
    #[serde_as(as = "SerdeAs")]
    w_hat: C,
    e: Vec<u8>,
    nonce: Nonce<<Aes256Gcm as AeadCore>::NonceSize>,
    pi: Proof,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DecShare<C: CurveGroup> {
    #[serde_as(as = "SerdeAs")]
    w: C,
    index: u32,
    phi: Proof,
}

impl<C: CurveGroup> CombKey<C> {
    pub fn get_pub_share(&self, idx: usize) -> Option<&C> {
        self.key.get(idx)
    }
}

impl<C: CurveGroup> KeyShare<C> {
    pub fn share(&self) -> &C::ScalarField {
        &self.share
    }
}

impl Plaintext {
    pub fn new(data: Vec<u8>) -> Self {
        Plaintext(data)
    }
}

impl From<Plaintext> for Vec<u8> {
    fn from(plaintext: Plaintext) -> Self {
        plaintext.0
    }
}

impl<C: CurveGroup> DecShare<C> {
    pub fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use crate::{
        cp_proof::Proof,
        sg_encryption::{DecShare, Plaintext, ShoupGennaro},
        traits::tpke::{ThresholdEncError, ThresholdEncScheme},
    };

    use ark_bls12_381::{G1Projective, g1::Config};
    use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher};
    use ark_ff::field_hashers::DefaultFieldHasher;
    use ark_std::rand::seq::SliceRandom;
    use ark_std::test_rng;
    use multisig::{Committee, KeyId, Keypair};
    use sha2::Sha256;
    use spongefish::DigestBridge;

    type G = G1Projective;
    type H = Sha256;
    type D = DigestBridge<H>;
    type H2C = MapToCurveBasedHasher<G, DefaultFieldHasher<H>, WBMap<Config>>;

    #[test]
    fn test_correctness() {
        let rng = &mut test_rng();
        let committee = generate_committee(20);

        // setup schemes
        let (pk, comb_key, key_shares) =
            ShoupGennaro::<G, H, D, H2C>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let aad = b"cred~abcdef".to_vec();
        let ciphertext = ShoupGennaro::<G, H, D, H2C>::encrypt(rng, &pk, &plaintext, &aad).unwrap();

        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D, H2C>::decrypt(s, &ciphertext, &aad))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let check_message = ShoupGennaro::<G, H, D, H2C>::combine(
            &committee,
            &comb_key,
            dec_shares_refs.clone(),
            &ciphertext,
            &aad,
        )
        .unwrap();
        assert_eq!(
            message, check_message.0,
            "encrypted message:{:?} should be the same as the output of combine: {:?}",
            message, check_message.0
        );

        // make sure that wrong associated data will fail decryption
        assert!(
            ShoupGennaro::<G, H, D, H2C>::combine(
                &committee,
                &comb_key,
                dec_shares_refs,
                &ciphertext,
                b"cred~bad".to_vec().as_ref(),
            )
            .is_err()
        );
    }

    #[test]
    fn test_not_enough_shares() {
        let rng = &mut test_rng();
        let committee = generate_committee(10);

        // setup schemes
        let (pk, comb_key, key_shares) =
            ShoupGennaro::<G, H, D, H2C>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message);
        let aad = b"cred~abcdef".to_vec();
        let ciphertext = ShoupGennaro::<G, H, D, H2C>::encrypt(rng, &pk, &plaintext, &aad).unwrap();

        let threshold = committee.one_honest_threshold().get();
        let dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D, H2C>::decrypt(s, &ciphertext, &aad))
            .filter_map(|res| res.ok())
            .take(threshold - 1) // not enough shares to combine
            .collect::<Vec<_>>();

        let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();

        let result = ShoupGennaro::<G, H, D, H2C>::combine(
            &committee,
            &comb_key,
            dec_shares_refs,
            &ciphertext,
            &aad,
        );
        assert!(
            result.is_err(),
            "Should fail to combine; insufficient amount of shares"
        );
    }

    #[test]
    // NOTE: we are using (t, N) threshold scheme, where exactly =t valid shares can successfully
    // decrypt, in the context of timeboost, t=f+1 where f is the upper bound of faulty nodes.
    // In the original spec, authors used `t+1` shares to decrypt, but here, we are testing SG01
    // scheme purely from the perspective of the standalone cryptographic scheme, so be aware of
    // the slight mismatch of notation.
    fn test_combine_invalid_shares() {
        let rng = &mut test_rng();
        let committee = generate_committee(10);

        // setup schemes
        let (pk, comb_key, key_shares) =
            ShoupGennaro::<G, H, D, H2C>::keygen(rng, &committee).unwrap();
        let message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let plaintext = Plaintext(message.clone());
        let aad = b"cred~abcdef".to_vec();
        let ciphertext = ShoupGennaro::<G, H, D, H2C>::encrypt(rng, &pk, &plaintext, &aad).unwrap();

        let mut dec_shares: Vec<_> = key_shares
            .iter()
            .map(|s| ShoupGennaro::<G, H, D, H2C>::decrypt(s, &ciphertext, &aad))
            .filter_map(|res| res.ok())
            .collect::<Vec<_>>();

        // 1. Change the order of the shares received by combiner
        dec_shares.shuffle(rng);

        let check_message = ShoupGennaro::<G, H, D, H2C>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
            &aad,
        )
        .unwrap();
        assert_eq!(
            message, check_message.0,
            "Combine should be indifferent to the order of incoming shares"
        );

        // 2. Invalidate n - t + 1 shares (left with t-1 valid shares)
        let c_size = committee.size().get();
        let c_threshold = committee.one_honest_threshold().get();
        let first_correct_share = dec_shares[0].clone();
        // modify the first n - t + 1 shares
        let mut expected_faulty_subset = BTreeSet::new();
        (0..(c_size - c_threshold + 1)).for_each(|i| {
            let mut share: DecShare<_> = dec_shares[i].clone();
            expected_faulty_subset.insert(share.index);
            share.phi = Proof { transcript: vec![] };
            dec_shares[i] = share;
        });
        let result = ShoupGennaro::<G, H, D, H2C>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
            &aad,
        );
        match result {
            Err(ThresholdEncError::FaultySubset(set)) => {
                assert_eq!(set, expected_faulty_subset);
            }
            _ => panic!("Should fail with faulty subset to blame"),
        };
        // 3. Reattach the first correct share to the combining set
        // to obtain exactly t correct shares (enough to combine)
        dec_shares[0] = first_correct_share;
        let result = ShoupGennaro::<G, H, D, H2C>::combine(
            &committee,
            &comb_key,
            dec_shares.iter().collect(),
            &ciphertext,
            &aad,
        );
        assert!(
            result.is_ok(),
            "Should succeed; we have exactly t+1 valid shares"
        );
    }

    fn generate_committee(nodes: usize) -> Committee {
        let public_keys = (0..nodes)
            .map(|i| {
                let kp = Keypair::generate();
                (KeyId::from(i as u8), kp.public_key())
            })
            .collect::<Vec<_>>();
        Committee::new(0, public_keys)
    }
}

use std::num::NonZeroUsize;

use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use ark_std::test_rng;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use digest::{DynDigest, FixedOutputReset};
use sha2::{Digest, Sha256};
use spongefish::{DigestBridge, DuplexSpongeInterface};
use timeboost_crypto::{
    Keyset, Plaintext, sg_encryption::ShoupGennaro, traits::threshold_enc::ThresholdEncScheme,
};

const KB: usize = 1 << 10;
const MB: usize = KB << 10;

pub fn shoup_gennaro<G, H, D>(c: &mut Criterion, curve: &str)
where
    H: Digest + Default + DynDigest + Clone + FixedOutputReset + 'static,
    D: DuplexSpongeInterface,
    G: CurveGroup,
    G::ScalarField: PrimeField,
{
    let committee_sizes = [5, 10, 15, 20];
    let byte_lens = [100 * KB, 200 * KB, 500 * KB, MB];

    let rng = &mut test_rng();
    for len in byte_lens {
        let payload_bytes = {
            let mut payload_bytes = vec![0u8; len];
            rng.fill_bytes(&mut payload_bytes);
            payload_bytes
        };
        let benchmark_group_name = |op_name| format!("SG01_{}_{}_{}KB", curve, op_name, len / KB);

        // encrypt
        let mut grp = c.benchmark_group(benchmark_group_name("encrypt"));
        grp.throughput(Throughput::Bytes(len as u64));
        for size in committee_sizes {
            let committee = Keyset::new(0, NonZeroUsize::new(size).unwrap());
            let (pk, _, _) =
                ShoupGennaro::<G, H, D>::keygen(rng, &committee).expect("generate key material");
            let plaintext = Plaintext::new(payload_bytes.to_vec());
            let aad = b"cred~abcdef".to_vec();

            grp.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
                b.iter(|| {
                    ShoupGennaro::<G, H, D>::encrypt(rng, &committee.id(), &pk, &plaintext, &aad)
                        .expect("encrypt message");
                });
            });
        }
        grp.finish();

        // partial decrypt
        let mut grp = c.benchmark_group(benchmark_group_name("decrypt"));
        grp.throughput(Throughput::Bytes(len as u64));
        for size in committee_sizes {
            let committee = Keyset::new(0, NonZeroUsize::new(size).unwrap());
            let (pk, _, key_shares) =
                ShoupGennaro::<G, H, D>::keygen(rng, &committee).expect("generate key material");
            let plaintext = Plaintext::new(payload_bytes.to_vec());
            let aad = b"cred~abcdef".to_vec();
            let ciphertext =
                ShoupGennaro::<G, H, D>::encrypt(rng, &committee.id(), &pk, &plaintext, &aad)
                    .expect("encrypt message");
            grp.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
                b.iter(|| {
                    ShoupGennaro::<G, H, D>::decrypt(&key_shares[0], &ciphertext, &aad)
                        .expect("generate partial decryption share");
                });
            });
        }
        grp.finish();

        // combine
        let mut grp = c.benchmark_group(benchmark_group_name("combine"));
        grp.throughput(Throughput::Bytes(len as u64));
        for size in committee_sizes {
            let committee = Keyset::new(0, NonZeroUsize::new(size).unwrap());
            let (pk, comb_key, key_shares) =
                ShoupGennaro::<G, H, D>::keygen(rng, &committee).expect("generate key material");
            let plaintext = Plaintext::new(payload_bytes.to_vec());
            let aad = b"cred~abcdef".to_vec();
            let ciphertext =
                ShoupGennaro::<G, H, D>::encrypt(rng, &committee.id(), &pk, &plaintext, &aad)
                    .expect("encrypt message");
            let dec_shares: Vec<_> = key_shares
                .iter()
                .map(|s| ShoupGennaro::<G, H, D>::decrypt(s, &ciphertext, &aad))
                .filter_map(|res| res.ok())
                .collect::<Vec<_>>();
            let dec_shares_refs: Vec<&_> = dec_shares.iter().collect();
            grp.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
                b.iter(|| {
                    ShoupGennaro::<G, H, D>::combine(
                        &committee,
                        &comb_key,
                        dec_shares_refs.clone(),
                        &ciphertext,
                        &aad,
                    )
                    .expect("combine decryption shares");
                });
            });
        }
        grp.finish();
    }
}

fn shoup_gennaro_main(c: &mut Criterion) {
    shoup_gennaro::<ark_bn254::G2Projective, Sha256, DigestBridge<Sha256>>(c, "Bn254G1");
    shoup_gennaro::<ark_secp256k1::Projective, Sha256, DigestBridge<Sha256>>(c, "secp256k1");
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = shoup_gennaro_main);

criterion_main!(benches);

use std::{collections::BTreeMap, iter::repeat_with};

use ark_ec::CurveGroup;
use ark_std::{
    UniformRand,
    rand::{Rng, SeedableRng, rngs::StdRng},
};
use criterion::{Criterion, criterion_group, criterion_main};
use timeboost_crypto::mre::{self, LabeledDecryptionKey};
use timeboost_crypto::vess::ShoupVess;

const KB: usize = 1 << 10;

/// Helper function to create a test committee with specified parameters
fn create_test_committee(epoch: u64, size: usize) -> multisig::Committee {
    let keypairs: Vec<multisig::Keypair> =
        (0..size).map(|_| multisig::Keypair::generate()).collect();
    multisig::Committee::new(
        epoch,
        keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| (i as u8, kp.public_key())),
    )
}

fn shoup_vess<C: CurveGroup>(c: &mut Criterion, vess: ShoupVess<C>) {
    let rng = &mut StdRng::seed_from_u64(42);
    let committee_sizes = [13];
    let secret = C::ScalarField::rand(rng);

    for committee_size in committee_sizes {
        let benchmark_group_name = |op_name| format!("ShoupVESS_{committee_size}_{op_name}");

        // Create a test committee
        let committee = create_test_committee(0, committee_size);
        let n = committee.size().get();
        let aad = b"vess aad";

        // prepare their encryption keys for secure communication
        let recv_sks: Vec<mre::DecryptionKey<C>> = repeat_with(|| mre::DecryptionKey::rand(rng))
            .take(n)
            .collect();
        let recv_pks: BTreeMap<usize, mre::EncryptionKey<C>> = recv_sks
            .iter()
            .enumerate()
            .map(|(i, sk)| (i, mre::EncryptionKey::from(sk)))
            .collect();
        let labeled_sks: Vec<LabeledDecryptionKey<C>> = recv_sks
            .into_iter()
            .enumerate()
            .map(|(i, sk)| sk.label(i))
            .collect();

        // benchmark encrypt_shares
        c.bench_function(&benchmark_group_name("encrypt"), |b| {
            b.iter(|| {
                vess.encrypt_shares(&committee, recv_pks.values(), secret, aad)
                    .unwrap();
            })
        });

        // benchmark verify
        let (ct, comm) = vess
            .encrypt_shares(&committee, recv_pks.values(), secret, aad)
            .unwrap();
        println!(
            "{}: ciphertext: {} KB",
            benchmark_group_name("size"),
            ct.as_bytes().len() / KB
        );
        c.bench_function(&benchmark_group_name("verify"), |b| {
            b.iter(|| {
                vess.verify_shares(&committee, recv_pks.values(), &ct, &comm, aad)
                    .unwrap();
            })
        });

        // benchmark decrypt
        // select a random receiver to test its decryption
        let recv_idx = rng.gen_range(0..committee_size);
        let labeled_recv_sk = &labeled_sks[recv_idx];
        c.bench_function(&benchmark_group_name("decrypt"), |b| {
            b.iter(|| {
                vess.decrypt_share(&committee, labeled_recv_sk, &ct, aad)
                    .unwrap();
            })
        });
    }
}

fn vess_main(c: &mut Criterion) {
    shoup_vess(c, ShoupVess::<ark_bls12_381::G1Projective>::new_fast());
}

criterion_group!(name = benches; config = Criterion::default().sample_size(10); targets = vess_main);

criterion_main!(benches);

#![cfg(feature = "benchmark")]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bitvec::{bitvec, prelude::BitVec};
use committable::{Commitment, Committable};
use ed25519_compact as ed;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use timeboost_core::types::{Keypair, PublicKey, Signature};
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::certificate::Certificate;
use timeboost_core::types::round_number::RoundNumber;

fn simple_bench(mut f: impl FnMut() -> bool) -> Duration {
    const ITERATIONS: u32 = 100;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        assert!(f())
    }
    start.elapsed() / ITERATIONS
}

struct Accum<D: Committable> {
    commit: Option<Commitment<D>>,
    signers: (BitVec, Vec<Signature>),
}

impl<D: Committable + Clone> Accum<D> {
    fn new(committee: &StaticCommittee) -> Self {
        Self {
            commit: None,
            signers: (bitvec![0; committee.size().get()], Vec::new()),
        }
    }

    fn len(&self) -> usize {
        self.signers.0.count_ones()
    }

    fn add(&mut self, d: &D, k: &Keypair, committee: &StaticCommittee) -> Option<Certificate<D>> {
        if self.commit.is_none() {
            self.commit = Some(d.commit());
        }
        let commit = d.commit();
        if self.commit != Some(commit) {
            unreachable!()
        }
        let Some(index) = committee
            .committee()
            .iter()
            .position(|x| x == k.public_key())
        else {
            unreachable!()
        };

        let sig = k.sign(commit.as_ref());
        self.signers.0.set(index, true);
        self.signers.1.push(sig);

        if self.len() < committee.quorum_size().get() as usize {
            return None;
        }

        let pp = <PublicKey as SignatureKey>::public_parameter(
            committee.stake_table(),
            U256::from(committee.quorum_size().get()),
        );

        let sig = <PublicKey as SignatureKey>::assemble(&pp, &self.signers.0, &self.signers.1);
        Some(Certificate::new(d.clone(), sig))
    }
}

const SIZES: [usize; 9] = [1, 2, 3, 10, 20, 30, 60, 100, 150];

#[test]
fn bench_vote_accumulator() {
    for n in SIZES {
        let mut keys = (0..n).map(|_| Keypair::random()).collect::<Vec<_>>();
        let comm = StaticCommittee::new(keys.iter().map(|kp| *kp.public_key()).collect());

        let duration = simple_bench(|| {
            let mut accu = Accum::new(&comm);
            for k in &mut keys[..] {
                if let Some(cert) = accu.add(&RoundNumber::new(42), k, &comm) {
                    assert!(cert.is_valid_quorum(&comm));
                    return true;
                }
            }
            false
        });

        println!("{:3} -> {duration:0.2?}", comm.quorum_size())
    }
}

#[test]
fn bench_cert_is_valid() {
    for n in SIZES {
        let mut keys = (0..n).map(|_| Keypair::random()).collect::<Vec<_>>();
        let comm = StaticCommittee::new(keys.iter().map(|kp| *kp.public_key()).collect());

        let mut accu = Accum::new(&comm);
        for k in &mut keys[..] {
            if let Some(cert) = accu.add(&RoundNumber::new(42), k, &comm) {
                let duration = simple_bench(|| cert.is_valid_quorum(&comm));
                println!("{:3} -> {duration:0.2?}", comm.quorum_size());
                break
            }
        }
    }
}

struct SignatureSet<D: Committable> {
    commit: Option<Commitment<D>>,
    sigs: HashMap<usize, ed::Signature>,
}

impl<D: Committable> SignatureSet<D> {
    fn new() -> Self {
        Self {
            commit: None,
            sigs: HashMap::new(),
        }
    }

    fn len(&self) -> usize {
        self.sigs.len()
    }

    fn add(&mut self, d: &D, i: usize, k: &ed::KeyPair) {
        if self.commit.is_none() {
            self.commit = Some(d.commit());
        }
        let commit = d.commit();
        if self.commit != Some(commit) {
            unreachable!()
        }
        let sig = k.sk.sign(commit, Some(ed::Noise::default()));
        self.sigs.insert(i, sig);
    }

    fn is_valid(&self, q: usize, committee: &HashMap<usize, ed::PublicKey>) -> bool {
        let commit = self.commit.as_ref().unwrap();
        let n: usize = self
            .sigs
            .iter()
            .map(|(i, s)| committee[i].verify(&commit, s).is_ok() as usize)
            .sum();
        n >= 2 * q / 3 + 1
    }

    fn is_valid_par(&self, q: usize, committee: &HashMap<usize, ed::PublicKey>) -> bool {
        use rayon::prelude::*;

        let commit = self.commit.as_ref().unwrap();
        let n: usize = self
            .sigs
            .par_iter()
            .map(|(i, s)| committee[i].verify(&commit, s).is_ok() as usize)
            .sum();
        n >= 2 * q / 3 + 1
    }
}

#[test]
fn bench_signature_set() {
    for n in SIZES {
        let keys = (0..n).map(|i| (i, ed::KeyPair::generate())).collect::<HashMap<_, _>>();

        let duration = simple_bench(|| {
            let mut accu = SignatureSet::new();
            for (i, k) in &keys {
                accu.add(&RoundNumber::new(42), *i, &k);
                if accu.len() >= 2 * n / 3 + 1 {
                    return true;
                }
            }
            false
        });

        println!("{:3} -> {duration:0.2?}", 2 * n / 3 + 1)
    }
}

#[test]
fn bench_signature_set_is_valid() {
    for n in SIZES {
        let keys = (0..n).map(|i| (i, ed::KeyPair::generate())).collect::<HashMap<_, _>>();
        let pubs = keys.iter().map(|(i, k)| (*i, k.pk)).collect::<HashMap<_, _>>();

        let mut accu = SignatureSet::new();
        for (i, k) in &keys {
            accu.add(&RoundNumber::new(42), *i, &k);
            if accu.len() >= 2 * n / 3 + 1 {
                let duration = simple_bench(|| accu.is_valid(2 * n / 3 + 1, &pubs));
                println!("{:3} -> {duration:0.2?}", 2 * n / 3 + 1);
                break
            }
        }
    }
}

#[test]
fn bench_signature_set_is_valid_parallel() {
    for n in SIZES {
        let keys = (0..n).map(|i| (i, ed::KeyPair::generate())).collect::<HashMap<_, _>>();
        let pubs = keys.iter().map(|(i, k)| (*i, k.pk)).collect::<HashMap<_, _>>();

        let mut accu = SignatureSet::new();
        for (i, k) in &keys {
            accu.add(&RoundNumber::new(42), *i, &k);
            if accu.len() >= 2 * n / 3 + 1 {
                let duration = simple_bench(|| accu.is_valid_par(2 * n / 3 + 1, &pubs));
                println!("{:3} -> {duration:0.2?}", 2 * n / 3 + 1);
                break
            }
        }
    }
}


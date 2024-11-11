#![cfg(feature = "benchmark")]

use std::time::{Duration, Instant};

use bitvec::{bitvec, prelude::BitVec};
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::{Keypair, PublicKey, Signature};

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

impl<D: Committable> Accum<D> {
    fn new(committee: &StaticCommittee) -> Self {
        Self {
            commit: None,
            signers: (bitvec![0; committee.size().get()], Vec::new()),
        }
    }

    fn len(&self) -> usize {
        self.signers.0.count_ones()
    }

    fn add(&mut self, d: &D, k: &Keypair, committee: &StaticCommittee) {
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
    }

    pub fn is_valid(&self, committee: &StaticCommittee) -> bool {
        if self.len() < committee.quorum_size().get() as usize {
            return false;
        }
        let pp = <PublicKey as SignatureKey>::public_parameter(
            committee.stake_table(),
            U256::from(committee.quorum_size().get()),
        );

        let sig = <PublicKey as SignatureKey>::assemble(&pp, &self.signers.0, &self.signers.1);
        PublicKey::check(&pp, self.commit.as_ref().unwrap().as_ref(), &sig)
    }
}

#[test]
fn bench_vote_accumulator() {
    for n in [1, 2, 3, 10, 20, 30, 60, 100] {
        let mut keys = (0..n).map(|_| Keypair::random()).collect::<Vec<_>>();
        let comm = StaticCommittee::new(keys.iter().map(|kp| *kp.public_key()).collect());

        let duration = simple_bench(|| {
            let mut accu = Accum::new(&comm);
            for k in &mut keys[..] {
                accu.add(&RoundNumber::new(42), k, &comm);
                if accu.len() >= comm.quorum_size().get() as usize {
                    assert!(accu.is_valid(&comm));
                    return true;
                }
            }
            false
        });

        println!("{n:3} -> {duration:0.2?}")
    }
}

use committable::{Commitment, Committable};
use ed25519_compact as ed;
use std::collections::HashMap;
use timeboost_core::types::round_number::RoundNumber;

struct SignatureSet<D: Committable> {
    commit: Option<Commitment<D>>,
    sigs: HashMap<ed::PublicKey, ed::Signature>,
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

    fn add(&mut self, d: &D, k: &ed::KeyPair) {
        if self.commit.is_none() {
            self.commit = Some(d.commit());
        }
        let commit = d.commit();
        if self.commit != Some(commit) {
            unreachable!()
        }
        let sig = k.sk.sign(commit, Some(ed::Noise::default()));
        self.sigs.insert(k.pk.clone(), sig);
    }

    fn is_valid(&self, q: usize) -> bool {
        let commit = self.commit.as_ref().unwrap();
        let n: usize = self
            .sigs
            .iter()
            .map(|(k, s)| k.verify(&commit, s).is_ok() as usize)
            .sum();
        n >= 2 * q / 3 + 1
    }

    fn is_valid_par(&self, q: usize) -> bool {
        use rayon::prelude::*;

        let commit = self.commit.as_ref().unwrap();
        let n: usize = self
            .sigs
            .par_iter()
            .map(|(k, s)| k.verify(&commit, s).is_ok() as usize)
            .sum();
        n >= 2 * q / 3 + 1
    }
}

#[test]
fn bench_signature_set() {
    for n in [1, 2, 3, 10, 20, 30, 60, 100] {
        let mut keys = (0..n).map(|_| ed::KeyPair::generate()).collect::<Vec<_>>();

        let duration = simple_bench(|| {
            let mut accu = SignatureSet::new();
            for k in &mut keys[..] {
                accu.add(&RoundNumber::new(42), &k);
                if accu.len() >= 2 * n / 3 + 1 {
                    assert!(accu.is_valid(2 * n / 3 + 1));
                    return true;
                }
            }
            false
        });

        println!("{n:3} -> {duration:0.2?}")
    }
}

#[test]
fn bench_signature_set_parallel() {
    for n in [1, 2, 3, 10, 20, 30, 60, 100] {
        let mut keys = (0..n).map(|_| ed::KeyPair::generate()).collect::<Vec<_>>();

        let duration = simple_bench(|| {
            let mut accu = SignatureSet::new();
            for k in &mut keys[..] {
                accu.add(&RoundNumber::new(42), &k);
                if accu.len() >= 2 * n / 3 + 1 {
                    assert!(accu.is_valid_par(2 * n / 3 + 1));
                    return true;
                }
            }
            false
        });

        println!("{n:3} -> {duration:0.2?}")
    }
}

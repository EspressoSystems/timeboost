#![cfg(feature = "benchmark")]

use std::time::{Duration, Instant};

use committable::{Commitment, Committable, RawCommitmentBuilder};
use multisig::{Certificate, Committee, Keypair, Signed, Version, VoteAccumulator};
use serde::Serialize;

const VERSION: Version = Version::new(1);

const SIZES: [usize; 9] = [1, 2, 3, 10, 20, 30, 60, 100, 150];

fn simple_bench(mut f: impl FnMut() -> bool) -> Duration {
    const ITERATIONS: u32 = 100;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        assert!(f())
    }
    start.elapsed() / ITERATIONS
}

#[derive(Debug, Clone, Copy, Serialize)]
struct Message;

impl Committable for Message {
    fn commit(&self) -> Commitment<Self> {
        RawCommitmentBuilder::new("Message").finalize()
    }
}

#[test]
fn bench_vote_accumulator() {
    for n in SIZES {
        let mut keys = (0..n).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let comm = Committee::new(
            VERSION,
            keys.iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );
        let duration = simple_bench(|| {
            let mut accu = VoteAccumulator::<Message>::new(comm.latest());
            for k in &mut keys[..] {
                accu.add(Signed::new((VERSION, Message).into(), k, false))
                    .unwrap();
            }
            accu.certificate().is_some()
        });
        println!("{n:3} -> {duration:0.2?}")
    }
}

fn mk_cert(keys: &mut [Keypair], comm: Committee) -> Certificate<Message> {
    let mut accu = VoteAccumulator::<Message>::new(comm.latest());
    for k in &mut keys[..] {
        accu.add(Signed::new((VERSION, Message).into(), k, false))
            .unwrap();
    }
    accu.certificate().unwrap().clone()
}

#[test]
fn bench_certificate_is_valid() {
    for n in SIZES {
        let mut keys = (0..n).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let comm = Committee::new(
            1,
            keys.iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );
        let cert = mk_cert(&mut keys, comm.clone());
        let duration = simple_bench(|| cert.is_valid(&comm));
        println!("{n:3} -> {duration:0.2?}");
    }
}

#[test]
fn bench_certificate_is_valid_par() {
    for n in SIZES {
        let mut keys = (0..n).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let comm = Committee::new(
            1,
            keys.iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );
        let cert = mk_cert(&mut keys, comm.clone());
        let duration = simple_bench(|| cert.is_valid_par(&comm));
        println!("{n:3} -> {duration:0.2?}");
    }
}

#[test]
fn certificate_sizes() {
    for n in SIZES {
        let mut keys = (0..n).map(|_| Keypair::generate()).collect::<Vec<_>>();
        let comm = Committee::new(
            1,
            keys.iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );
        let cert = mk_cert(&mut keys, comm.clone());
        println!(
            "{n:3} -> {:5} bytes",
            bincode::serde::encode_to_vec(&cert, bincode::config::standard())
                .unwrap()
                .len()
        );
    }
}

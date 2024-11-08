#![cfg(feature = "benchmark")]

use std::time::{Duration, Instant};

use sailfish::consensus::VoteAccumulator;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::envelope::Envelope;
use timeboost_core::types::message::Timeout;
use timeboost_core::types::Keypair;

fn simple_bench(mut f: impl FnMut() -> bool) -> Duration {
    const ITERATIONS: u32 = 100;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        assert!(f())
    }
    start.elapsed() / ITERATIONS
}

#[test]
fn bench_vote_accumulator() {
    for n in [1, 2, 3, 10, 20, 30, 60, 100] {
        let mut keys = (0..n).map(|_| Keypair::random()).collect::<Vec<_>>();
        let comm = StaticCommittee::new(keys.iter().map(|kp| *kp.public_key()).collect());

        let duration = simple_bench(|| {
            let mut accu = VoteAccumulator::<Timeout>::new(comm.clone());
            for k in &mut keys[..] {
                match accu.add(Envelope::signed(Timeout::new(42), k)) {
                    Ok(None) => {}
                    Ok(Some(_)) => return true,
                    Err(_) => return false,
                }
            }
            false
        });

        println!("{n:3} -> {duration:0.2?}")
    }
}

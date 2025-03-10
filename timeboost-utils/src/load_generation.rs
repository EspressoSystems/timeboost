use arbitrary::Unstructured;
use rand::Rng;
use timeboost_types::{Address, PriorityBundle, Transaction};

pub fn make_tx() -> Transaction {
    let mut v = [0; 256];
    rand::fill(&mut v);
    let mut u = Unstructured::new(&v);

    if rand::rng().random_bool(0.1) {
        PriorityBundle::arbitrary(Address::zero(), 10, 512, &mut u).unwrap()
    } else {
        Transaction::arbitrary(512, &mut u).unwrap()
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

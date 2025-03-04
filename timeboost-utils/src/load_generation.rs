use arbitrary::{Arbitrary, Unstructured};
use timeboost_types::Transaction;

pub fn make_tx() -> Transaction {
    let mut v = [0; 16];
    rand::fill(&mut v);
    let mut u = Unstructured::new(&v);
    Transaction::arbitrary(&mut u).unwrap()
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

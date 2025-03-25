use rand::Rng;
use timeboost_types::{Bundle, BundleVariant, PriorityBundle};

pub fn make_tx() -> BundleVariant {
    let mut v = [0; 256];
    rand::fill(&mut v);
    let mut u = arbitrary::Unstructured::new(&v);
    if rand::rng().random_bool(0.1) {
        BundleVariant::Priority(PriorityBundle::arbitrary(&mut u).unwrap())
    } else {
        BundleVariant::Regular(Bundle::arbitrary(&mut u).unwrap())
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

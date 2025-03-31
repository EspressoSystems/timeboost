use arbitrary::Unstructured;
use rand::Rng;
use timeboost_types::{Bundle, BundleVariant, SignedPriorityBundle};

pub fn make_bundle() -> BundleVariant {
    let mut v = [0; 256];
    rand::fill(&mut v);
    let mut u = Unstructured::new(&v);
    if rand::rng().random_bool(0.1) {
        BundleVariant::Priority(SignedPriorityBundle::arbitrary(&mut u, 10).unwrap())
    } else {
        BundleVariant::Regular(Bundle::arbitrary(&mut u).unwrap())
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

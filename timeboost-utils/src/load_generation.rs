use alloy::rlp::Encodable;
use arbitrary::Arbitrary;
use rand::Rng;
use ssz::ssz_encode;
use timeboost_types::{
    Address, Bundle, BundleVariant, ChainId, Epoch, PriorityBundle, SeqNo, Signer, Transaction,
    Unsigned,
};

pub fn make_tx() -> BundleVariant {
    let mut v = [0; 256];
    rand::fill(&mut v);
    let mut unstructured = arbitrary::Unstructured::new(&v);
    let tx = Transaction::arbitrary(&mut unstructured).unwrap();
    let mut data = Vec::new();
    tx.encode(&mut data);
    let encoded_data = ssz_encode(&vec![&data]); // singleton bundle
    let signer = Signer::default();

    if rand::rng().random_bool(0.1) {
        let bundle = PriorityBundle::<Unsigned>::new(
            Bundle::new(ChainId::from(0), Epoch::from(10), encoded_data.into(), None),
            Address::zero(),
            SeqNo::from(3),
        );
        BundleVariant::Priority(bundle.sign(signer).expect("default signer"))
    } else {
        BundleVariant::Regular(Bundle::new(
            ChainId::from(0),
            Epoch::from(10),
            encoded_data.into(),
            None,
        ))
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

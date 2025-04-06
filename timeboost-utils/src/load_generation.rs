use arbitrary::{Arbitrary, Unstructured};
use ark_std::rand::{self, Rng};
use timeboost_crypto::{DecryptionScheme, traits::threshold_enc::ThresholdEncScheme};
use timeboost_types::{Address, Bundle, BundleVariant, PriorityBundle, SeqNo, Signer};

type EncKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;

pub fn make_bundle(_pubkey: &EncKey) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let max_seqno = 10;
    let bundle = Bundle::arbitrary(&mut u)?;

    if rng.gen_bool(0.1) {
        // priority
        let auction = Address::default();
        let seqno = SeqNo::from(u.int_in_range(1..=max_seqno)?);
        let signer = Signer::default();
        let priority = PriorityBundle::new(bundle, auction, seqno);
        let signed_priority = priority.sign(signer)?;
        Ok(BundleVariant::Priority(signed_priority))
    } else {
        // non-priority
        Ok(BundleVariant::Regular(bundle))
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

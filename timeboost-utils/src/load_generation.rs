use arbitrary::Arbitrary;
use ark_std::rand::rngs;
use rand::Rng;
use timeboost_crypto::{
    DecryptionScheme, KeysetId, Plaintext, traits::threshold_enc::ThresholdEncScheme,
};
use timeboost_types::{
    Address, Bundle, BundleVariant, DecryptionKey, PriorityBundle, SeqNo, Signer, Unsigned,
};

pub fn make_tx(dec_sk: DecryptionKey) -> anyhow::Result<BundleVariant> {
    let mut v = [0; 100];
    rand::fill(&mut v);
    let mut u = arbitrary::Unstructured::new(&v);
    let kid = KeysetId::from(1);
    let mut bundle = Bundle::arbitrary(&mut u).expect("generate bundle");
    if rand::rng().random_bool(0.1) {
        // encrypt bundle
        let mut rng = rngs::OsRng;
        let data = bundle.data();
        let plaintext = Plaintext::new(data.to_vec());
        let ciphertext = DecryptionScheme::encrypt(&mut rng, &kid, dec_sk.pubkey(), &plaintext)?;
        let encoded =
            bincode::serde::encode_to_vec(ciphertext, bincode::config::standard())?.into();
        bundle.set_data(encoded);
        bundle.set_kid(kid);
    }

    if rand::rng().random_bool(0.1) {
        // priority bundle
        let priority =
            PriorityBundle::<Unsigned>::new(bundle, Address::default(), SeqNo::arbitrary(&mut u)?);

        let signer = Signer::default();
        let signed_priority = priority.sign(signer)?;
        Ok(BundleVariant::Priority(signed_priority))
    } else {
        Ok(BundleVariant::Regular(bundle))
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis<N: Into<u64>>(tps: N) -> u64 {
    1000 / tps.into()
}

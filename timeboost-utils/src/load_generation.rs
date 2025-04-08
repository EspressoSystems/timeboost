use arbitrary::{Arbitrary, Unstructured};
use ark_std::rand::{self, Rng};
use bincode::error::EncodeError;
use bytes::{BufMut, Bytes, BytesMut};
use serde::Serialize;
use timeboost_crypto::{
    DecryptionScheme, KeysetId, Plaintext, traits::threshold_enc::ThresholdEncScheme,
};
use timeboost_types::{Address, Bundle, BundleVariant, PriorityBundle, SeqNo, Signer};

type EncKey = <DecryptionScheme as ThresholdEncScheme>::PublicKey;

pub fn make_bundle(pubkey: &EncKey) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let max_seqno = 10;
    let kid = KeysetId::from(1);
    let mut bundle = Bundle::arbitrary(&mut u)?;

    if rng.gen_bool(0.5) {
        // encrypt bundle
        let data = bundle.data();
        let plaintext = Plaintext::new(data.to_vec());
        let ciphertext = DecryptionScheme::encrypt(&mut rng, &kid, pubkey, &plaintext)?;
        let encoded = serialize(&ciphertext)?;
        bundle.set_data(encoded.into());
        bundle.set_kid(kid);
    }
    if rng.gen_bool(0.5) {
        // priority
        let auction = Address::default();
        let seqno = SeqNo::from(u.int_in_range(0..=max_seqno)?);
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

fn serialize<T: Serialize>(d: &T) -> Result<Bytes, EncodeError> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    Ok(b.into_inner().freeze())
}

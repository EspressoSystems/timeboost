use std::str::FromStr;

use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::TxSignerSync,
    primitives::{TxKind, U256},
    rlp::Encodable,
    signers::local::PrivateKeySigner,
};
use arbitrary::Unstructured;
use ark_std::rand::{self, Rng};
use bincode::error::EncodeError;
use bytes::{BufMut, Bytes, BytesMut};
use serde::Serialize;
use timeboost_crypto::{
    DecryptionScheme, Plaintext, prelude::ThresholdEncKeyCell,
    traits::threshold_enc::ThresholdEncScheme,
};
use timeboost_types::{Address, Bundle, BundleVariant, Epoch, PriorityBundle, SeqNo, Signer};

// Private key from pre funded dev account on test node
// https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
const DEV_ACCT_PRIV_KEY: &str = "b6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

pub fn make_bundle(pubkey: &ThresholdEncKeyCell) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let max_seqno = 10;
    let mut bundle = Bundle::arbitrary(&mut u)?;

    if let Some(pubkey) = &*pubkey.get_ref()
        && rng.gen_bool(0.5)
    {
        // encrypt bundle
        let data = bundle.data();
        let plaintext = Plaintext::new(data.to_vec());
        let ciphertext = DecryptionScheme::encrypt(&mut rng, pubkey, &plaintext, &vec![])?;
        let encoded = serialize(&ciphertext)?;
        bundle.set_encrypted_data(encoded.into());
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

pub fn make_dev_acct_bundle(
    pubkey: &ThresholdEncKeyCell,
    chain_id: u64,
    nonce: u64,
    to: alloy::primitives::Address,
    gas_limit: u64,
    max_base_fee: u128,
) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let max_seqno = 10;
    let mut bundle = create_dev_acct_txn_bundle(chain_id, nonce, to, gas_limit, max_base_fee)?;

    if let Some(pubkey) = &*pubkey.get_ref()
        && rng.gen_bool(0.5)
    {
        // encrypt bundle
        let data = bundle.data();
        let plaintext = Plaintext::new(data.to_vec());
        let ciphertext = DecryptionScheme::encrypt(&mut rng, pubkey, &plaintext, &vec![])?;
        let encoded = serialize(&ciphertext)?;
        bundle.set_encrypted_data(encoded.into());
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

pub fn create_dev_acct_txn_bundle(
    chain_id: u64,
    nonce: u64,
    to: alloy::primitives::Address,
    gas_limit: u64,
    max_fee_per_gas: u128,
) -> anyhow::Result<Bundle> {
    let mut tx = TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas,
        gas_limit,
        to: TxKind::Call(to),
        value: U256::from(1),
        ..Default::default()
    };

    // Private key from pre funded dev account on test node
    // https://docs.arbitrum.io/run-arbitrum-node/run-local-full-chain-simulation#default-endpoints-and-addresses
    let signer = PrivateKeySigner::from_str(DEV_ACCT_PRIV_KEY)?;
    let sig = signer.sign_transaction_sync(&mut tx)?;
    let signed_tx = tx.into_signed(sig);
    let env = TxEnvelope::Eip1559(signed_tx);
    let mut rlp = Vec::new();
    env.encode(&mut rlp);

    let encoded = ssz::ssz_encode(&vec![&rlp]);
    let b = Bundle::new(chain_id.into(), Epoch::now(), encoded.into(), false);

    Ok(b)
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

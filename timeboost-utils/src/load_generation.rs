use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::TxSignerSync,
    primitives::{TxKind, U256},
    rlp::Encodable,
    signers::local::PrivateKeySigner,
};
use arbitrary::{Arbitrary, Unstructured};
use ark_std::rand::{self, Rng};
use bincode::error::EncodeError;
use bytes::{BufMut, Bytes, BytesMut};
use serde::Serialize;
use timeboost_crypto::prelude::{Plaintext, ThresholdEncKey, ThresholdEncScheme, ThresholdScheme};
use timeboost_types::{
    Auction, Bundle, BundleVariant, ChainId, Epoch, PriorityBundle, SeqNo, Signer,
};
use tracing::warn;

pub struct TxInfo {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: alloy::primitives::Address,
    pub base_fee: u128,
    pub gas_limit: u64,
    pub signer: PrivateKeySigner,
}

pub fn make_txn(key: &ThresholdEncKey) -> anyhow::Result<TransactionVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let t = loop {
        let candidate = TxEnvelope::arbitrary(&mut u)?;
        if let TxEnvelope::Eip4844(ref eip4844) = candidate {
            if eip4844.tx().clone().try_into_4844_with_sidecar().is_ok() {
                // Avoid generating 4844 Tx with blobs of size 131 KB
                continue;
            }
        }
        break candidate;
    };

    let mut d = Vec::new();
    t.encode(&mut d);

    if rng.gen_bool(0.5) {
        // encrypt bundle
        let plaintext = Plaintext::new(d.clone());
        let aad = b"threshold".to_vec();
        let ciphertext = ThresholdScheme::encrypt(&mut rng, key, &plaintext, &aad)?;
        let tx = TransactionVariant::Encrypted(serialize(&ciphertext)?.to_vec());
        return Ok(tx);
    }
    // non-priority
    Ok(TransactionVariant::PlainText(d))
}

pub fn make_bundle(
    chain_id: ChainId,
    key: &ThresholdEncKey,
    auction: &Auction,
) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let max_seqno = 10;
    let mut bundle = Bundle::arbitrary(&mut u)?;
    bundle.set_chain_id(chain_id);

    if rng.gen_bool(0.5) {
        // encrypt bundle
        let data = bundle.data();
        let plaintext = Plaintext::new(data.to_vec());
        let aad = b"threshold".to_vec();
        let ciphertext = ThresholdScheme::encrypt(&mut rng, key, &plaintext, &aad)?;
        let encoded = serialize(&ciphertext)?;
        bundle.set_encrypted_data(encoded.into());
    }

    if rng.gen_bool(0.5) {
        // priority
        let auction_address = auction.contract();
        let controller = auction.controller(Epoch::now());
        let seqno = SeqNo::from(u.int_in_range(0..=max_seqno)?);
        let signer = Signer::default();
        if signer.address() == *controller {
            let priority = PriorityBundle::new(bundle, auction_address, seqno);
            let signed_priority = priority.sign(signer)?;
            return Ok(BundleVariant::Priority(signed_priority));
        }
        warn!("unable to produce priority tx");
    }
    Ok(BundleVariant::Regular(bundle))
}

#[derive(Clone)]
pub enum TransactionVariant {
    PlainText(Vec<u8>),
    Encrypted(Vec<u8>),
}

/// Helper function for when we only have a ThresholdEncKey directly
pub fn make_dev_acct_txn(
    pubkey: &ThresholdEncKey,
    txn: TxInfo,
    enc_ratio: f64,
) -> anyhow::Result<TransactionVariant> {
    let mut rng = rand::thread_rng();
    let tx = create_dev_acct_txn(txn)?;

    if rng.gen_bool(enc_ratio) {
        // encrypt bundle
        let plaintext = Plaintext::new(tx.to_vec());
        let aad = b"threshold".to_vec();
        let ciphertext = ThresholdScheme::encrypt(&mut rng, pubkey, &plaintext, &aad)?;
        let encoded = serialize(&ciphertext)?;
        return Ok(TransactionVariant::Encrypted(encoded.into()));
    }

    Ok(TransactionVariant::PlainText(tx))
}

/// Helper function for when we only have a ThresholdEncKey directly
pub fn make_dev_acct_bundle(
    pubkey: &ThresholdEncKey,
    auction: &Auction,
    txn: TxInfo,
    enc_ratio: f64,
    prio_ratio: f64,
) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let mut v = [0; 256];
    rng.fill(&mut v);
    let mut u = Unstructured::new(&v);

    let max_seqno = 10;
    let mut bundle = create_dev_acct_txn_bundle(txn)?;

    if rng.gen_bool(enc_ratio) {
        // encrypt bundle
        let data = bundle.data();
        let plaintext = Plaintext::new(data.to_vec());
        let aad = b"threshold".to_vec();
        let ciphertext = ThresholdScheme::encrypt(&mut rng, pubkey, &plaintext, &aad)?;
        let encoded = serialize(&ciphertext)?;
        bundle.set_encrypted_data(encoded.into());
    }

    if rng.gen_bool(prio_ratio) {
        // priority
        let auction_address = auction.contract();
        let controller = auction.controller(Epoch::now());
        let seqno = SeqNo::from(u.int_in_range(0..=max_seqno)?);
        let signer = Signer::default();
        if signer.address() == *controller {
            let priority = PriorityBundle::new(bundle, auction_address, seqno);
            let signed_priority = priority.sign(signer)?;
            return Ok(BundleVariant::Priority(signed_priority));
        }
        warn!("unable to produce priority tx");
    }
    Ok(BundleVariant::Regular(bundle))
}

pub fn create_dev_acct_txn_bundle(tx_info: TxInfo) -> anyhow::Result<Bundle> {
    let chain_id = tx_info.chain_id;
    let rlp = create_dev_acct_txn(tx_info)?;
    let encoded = ssz::ssz_encode(&vec![&rlp]);
    let b = Bundle::new(chain_id.into(), Epoch::now(), encoded.into(), false);

    Ok(b)
}

pub fn create_dev_acct_txn(tx_info: TxInfo) -> anyhow::Result<Vec<u8>> {
    let mut tx = TxEip1559 {
        chain_id: tx_info.chain_id,
        nonce: tx_info.nonce,
        max_fee_per_gas: tx_info.base_fee,
        gas_limit: tx_info.gas_limit,
        to: TxKind::Call(tx_info.to),
        value: U256::from(1),
        ..Default::default()
    };

    let sig = tx_info.signer.sign_transaction_sync(&mut tx)?;
    let signed_tx = tx.into_signed(sig);
    let env = TxEnvelope::Eip1559(signed_tx);
    let mut rlp = Vec::new();
    env.encode(&mut rlp);
    Ok(rlp)
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

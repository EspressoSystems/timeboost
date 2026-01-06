use alloy::{
    consensus::{SignableTransaction, TxEip1559, TxEnvelope},
    network::{TransactionBuilder, TxSignerSync},
    primitives::{Address, TxKind, U256},
    providers::{Provider, RootProvider},
    rlp::Encodable,
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use anyhow::Context;
use ark_std::rand::{self, Rng};
use bincode::error::EncodeError;
use bytes::{BufMut, Bytes, BytesMut};
use multisig::CommitteeId;
use serde::Serialize;
use timeboost_crypto::prelude::{Plaintext, ThresholdEncKey, ThresholdEncScheme, ThresholdScheme};
use timeboost_types::{
    Aad, Auction, Bundle, BundleVariant, ChainId, Epoch, PriorityBundle, SeqNo, Signer,
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

#[derive(Clone)]
pub enum TransactionVariant {
    PlainText(Vec<u8>),
    Encrypted(Vec<u8>),
}

pub fn create_tx(
    pubkey: Option<&ThresholdEncKey>,
    committee_id: CommitteeId,
    txn: TxInfo,
    enc_ratio: f64,
) -> anyhow::Result<TransactionVariant> {
    let mut rng = rand::thread_rng();
    let tx = build_signed(txn)?;

    if let Some(pubkey) = pubkey {
        if rng.gen_bool(enc_ratio) {
            // encrypt bundle
            let bytes = ssz::ssz_encode(&vec![tx]);
            let plaintext = Plaintext::new(bytes);
            let aad = Aad::Threshold(committee_id).to_bytes();
            let ciphertext = ThresholdScheme::encrypt(&mut rng, pubkey, &plaintext, &aad)?;
            let encoded = serialize(&ciphertext)?;
            return Ok(TransactionVariant::Encrypted(encoded.into()));
        }
    }

    Ok(TransactionVariant::PlainText(tx))
}

pub fn create_bundle(
    pubkey: Option<&ThresholdEncKey>,
    committee_id: CommitteeId,
    auction: &Auction,
    txn: TxInfo,
    enc_ratio: f64,
    prio_ratio: f64,
) -> anyhow::Result<BundleVariant> {
    let mut rng = rand::thread_rng();
    let max_seqno = 10;
    let mut bundle = create_singleton_bundle(txn)?;

    if let Some(pubkey) = pubkey {
        if rng.gen_bool(enc_ratio) {
            // encrypt bundle
            let data = bundle.data();
            let plaintext = Plaintext::new(data.to_vec());
            let aad = Aad::Threshold(committee_id).to_bytes();
            let ciphertext = ThresholdScheme::encrypt(&mut rng, pubkey, &plaintext, &aad)?;
            let encoded = serialize(&ciphertext)?;
            bundle.set_encrypted_data(encoded.into());
        }
    }

    if rng.gen_bool(prio_ratio) {
        // priority
        let auction_address = auction.contract();
        let controller = auction.controller(Epoch::now());
        let seqno = SeqNo::from(rng.gen_range(0..=max_seqno));
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

pub fn create_singleton_bundle(tx_info: TxInfo) -> anyhow::Result<Bundle> {
    let chain_id = tx_info.chain_id;
    let rlp = build_signed(tx_info)?;
    let encoded = ssz::ssz_encode(&vec![&rlp]);
    let b = Bundle::new(chain_id.into(), Epoch::now(), encoded.into(), false);

    Ok(b)
}

pub fn build_signed(tx_info: TxInfo) -> anyhow::Result<Vec<u8>> {
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

pub fn prepare_test(chain_id: ChainId, from: PrivateKeySigner, to: Address) -> TxInfo {
    TxInfo {
        chain_id: chain_id.into(),
        nonce: 0,
        to,
        base_fee: 5,
        gas_limit: 5,
        signer: from,
    }
}

pub async fn prepare(
    p: &RootProvider,
    chain_id: ChainId,
    from: PrivateKeySigner,
    to: Address,
) -> anyhow::Result<TxInfo> {
    let nonce = p.get_transaction_count(from.address()).await?;
    let tx = TransactionRequest::default()
        .with_chain_id(chain_id.into())
        .with_nonce(nonce)
        .with_from(from.address())
        .with_to(to)
        .with_value(U256::from(1));

    let gas_limit = p
        .estimate_gas(tx)
        .await
        .with_context(|| "failed to estimate gas")?;

    let base_fee = p
        .get_gas_price()
        .await
        .with_context(|| "failed to get gas price")?;

    Ok(TxInfo {
        chain_id: chain_id.into(),
        nonce,
        to,
        gas_limit,
        base_fee,
        signer: from,
    })
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis(tps: f64) -> u64 {
    (1000.0 / tps) as u64
}

fn serialize<T: Serialize>(d: &T) -> Result<Bytes, EncodeError> {
    let mut b = BytesMut::new().writer();
    bincode::serde::encode_into_std_write(d, &mut b, bincode::config::standard())?;
    Ok(b.into_inner().freeze())
}

use crate::types::{
    keyset::DecKeyInfo,
    seqno::SeqNo,
    transaction::{Address, Nonce, Transaction, TransactionData},
};
use rand::{Rng, RngCore};
use timeboost_crypto::{
    traits::threshold_enc::ThresholdEncScheme, Committee, DecryptionScheme, Plaintext,
};

pub const SIZE_512_B: usize = 512;

pub fn make_tx_data(n: usize, sz: usize) -> Vec<TransactionData> {
    let mut data = vec![0; sz];
    rand::rng().fill_bytes(&mut data);

    (0..n)
        .map(|i| {
            TransactionData::new(
                Nonce::now(SeqNo::from(i as u128)),
                Address::zero(),
                data.clone(),
                None,
            )
        })
        .collect()
}

pub fn make_encrypted_tx_data(n: usize, size: usize, dec_key: DecKeyInfo) -> Vec<TransactionData> {
    let mut rng = ark_std::test_rng();
    let text = b"The quick brown fox jumps over the lazy dog";
    let message = text.repeat(size / text.len());

    let committee = Committee {
        id: 0,
        size: n as u64,
    };

    (0..n)
        .map(|i| {
            let ciphertext = DecryptionScheme::encrypt(
                &mut rng,
                &committee,
                &dec_key.pubkey,
                &Plaintext::new(message.clone()),
            )
            .expect("encrypt plaintext message");
            let data = bincode::serialize(&ciphertext).expect("serialize ciphertext");

            TransactionData::new(
                Nonce::now(SeqNo::from(i as u128)),
                Address::zero(),
                data.clone(),
                Some(0u32),
            )
        })
        .collect()
}

pub fn make_tx(dec_key: DecKeyInfo) -> Transaction {
    let txns;
    // 10% change of encrypted data
    if rand::rng().random_bool(0.1) {
        txns = make_encrypted_tx_data(1, SIZE_512_B, dec_key);
    } else {
        txns = make_tx_data(1, SIZE_512_B);
    }
    // 10% chance of being a priority tx
    if rand::rng().random_bool(0.1) {
        // Get the txns
        Transaction::Priority {
            nonce: Nonce::now(SeqNo::from(0)),
            to: Address::zero(),
            txns,
        }
    } else {
        Transaction::Regular {
            // The index here is safe since we always generate a single txn.
            txn: txns[0].clone(),
        }
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis(tps: u32) -> u64 {
    1000 / tps as u64
}

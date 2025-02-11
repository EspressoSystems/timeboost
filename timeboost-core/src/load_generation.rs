use crate::types::{
    seqno::SeqNo,
    transaction::{Address, Nonce, Transaction, TransactionData},
};
use rand::{Rng, RngCore};

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
            )
        })
        .collect()
}

pub fn make_tx() -> Transaction {
    // 10% chance of being a priority tx
    if rand::rng().random_bool(0.1) {
        // Get the txns
        let txns = make_tx_data(1, SIZE_512_B);
        Transaction::Priority {
            nonce: Nonce::now(SeqNo::from(0)),
            to: Address::zero(),
            txns,
        }
    } else {
        Transaction::Regular {
            // The index here is safe since we always generate a single txn.
            txn: make_tx_data(1, SIZE_512_B).remove(0),
        }
    }
}

/// Transactions per second to milliseconds is 1000 / TPS
pub fn tps_to_millis(tps: u32) -> u64 {
    1000 / tps as u64
}

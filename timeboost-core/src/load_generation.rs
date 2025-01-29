use crate::types::{
    seqno::SeqNo,
    transaction::{Address, Nonce, Transaction, TransactionData},
};
use bytes::Bytes;
use rand::Rng;

pub const SIZE_512_B: usize = 512;

pub fn make_tx_data(n: usize, sz: usize) -> Vec<TransactionData> {
    // Make sz bytes of random data
    let data: Bytes = (0..sz).map(|_| rand::thread_rng().gen()).collect();

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
    if rand::thread_rng().gen_bool(0.1) {
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

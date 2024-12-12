use std::hash::{DefaultHasher, Hash, Hasher};

use timeboost_core::types::{
    time::Timestamp,
    transaction::{Address, Transaction},
};

use crate::sequencer::phase::inclusion::InclusionList;

use super::OrderingPhase;

pub struct CanonicalOrderingPhase;

impl CanonicalOrderingPhase {
    fn hash_seed_and_sender(&self, hasher: &mut DefaultHasher, seed: u64, sender: &Address) -> u64 {
        seed.hash(hasher);
        sender.hash(hasher);

        hasher.finish()
    }

    fn hash_contents(&self, hasher: &mut DefaultHasher, contents: &[u8]) -> u64 {
        hasher.write(contents);
        hasher.finish()
    }
}

impl OrderingPhase for CanonicalOrderingPhase {
    fn order(
        &self,
        decrypted_list: InclusionList,
    ) -> anyhow::Result<(Timestamp, Vec<Transaction>)> {
        let seed = decrypted_list.get_hash();
        let consensus_timestamp = decrypted_list.timestamp;
        let txns = decrypted_list.into_transactions();

        // Temporarily split the transactions into priority and non-priority.
        let (mut priority_txns, mut non_priority_txns): (Vec<_>, Vec<_>) =
            txns.into_iter().partition(|txn| txn.is_priority());

        // Among the priority transactions, sort them by sequence number.
        priority_txns.sort_by_key(|txn| txn.nonce().seqno());

        // Among the non-priority transactions, sort them by Hash(seed || sender), then nonce (increasing), then content hash.
        let mut hasher = DefaultHasher::new();
        non_priority_txns.sort_by(|a, b| {
            self.hash_seed_and_sender(&mut hasher, seed, a.to())
                .cmp(&self.hash_seed_and_sender(&mut hasher, seed, b.to()))
                .then_with(|| a.nonce().seqno().cmp(&b.nonce().seqno()))
                .then_with(|| {
                    // This is safe because we know that non-priority transactions have data.
                    let data_a = a.data().unwrap();
                    let data_b = b.data().unwrap();

                    self.hash_contents(&mut hasher, data_a.as_ref())
                        .cmp(&self.hash_contents(&mut hasher, data_b.as_ref()))
                })
        });

        // TODO: Delayed inbox transactions.

        // TODO: Await completion of prior ordering phase. (This will happen at the protocol level instead.)

        let ret = [priority_txns, non_priority_txns].concat();

        Ok((consensus_timestamp, ret))
    }
}

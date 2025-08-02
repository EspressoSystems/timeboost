use std::cmp::Ordering;

use multisig::PublicKey;
use ssz::decode_list_of_variable_length_items as ssz_decode;
use timeboost_types::{Bytes, InclusionList, Transaction};
use tracing::warn;

const MAX_BUNDLE_TXS: usize = 1024;
const MAX_TXS_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct Sorter {
    key: PublicKey,
}

impl Sorter {
    pub fn new(key: PublicKey) -> Self {
        Self { key }
    }

    pub fn sort(&mut self, list: InclusionList) -> Vec<Transaction> {
        let timestamp = list.timestamp();
        let seed = list.digest();

        let (priority, regular) = list.into_bundles();
        let mut ptx = Vec::new();
        let mut rtx = Vec::new();

        for (b, priority) in priority
            .iter()
            .map(|p| (p.bundle(), true))
            .chain(regular.iter().map(|r| (r, false)))
        {
            match ssz_decode::<Bytes, Vec<_>>(b.data(), Some(MAX_BUNDLE_TXS)) {
                Ok(txs) => {
                    for t in txs {
                        if t.len() > MAX_TXS_SIZE {
                            warn!(
                                node = %self.key,
                                max  = %MAX_TXS_SIZE,
                                "transaction exceeds max. allowed size"
                            );
                            continue;
                        }
                        match Transaction::decode(timestamp, &t) {
                            Ok(tx) => {
                                if priority {
                                    ptx.push(tx)
                                } else {
                                    rtx.push(tx)
                                }
                            }
                            Err(err) => {
                                warn!(node = %self.key, %err, "failed to decode transaction")
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(node = %self.key, ?err, "failed to ssz-decode bundle")
                }
            }
        }

        rtx.sort_unstable_by(|x, y| compare(&seed, x, y));
        ptx.extend(rtx);
        ptx
    }
}

#[rustfmt::skip]
fn compare(seed: &[u8], x: &Transaction, y: &Transaction) -> Ordering {
    use alloy::consensus::transaction::Transaction;

    let mut hx = blake3::Hasher::new();
    let mut hy = blake3::Hasher::new();

    hx.update(seed);
    hy.update(seed);

    hx.update(x.address().as_slice());
    hy.update(y.address().as_slice());

    hx.finalize().as_bytes().cmp(hy.finalize().as_bytes())
        .then_with(|| x.nonce().cmp(&y.nonce()))
        .then_with(|| x.hash().cmp(y.hash()))
}

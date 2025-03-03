use std::cmp::Ordering;

use ssz::decode_list_of_variable_length_items as ssz_decode;
use timeboost_types::{Bytes, InclusionList, Transaction};
use tracing::warn;

const MAX_BUNDLE_TXS: usize = 1024;
const MAX_TXS_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct Sorter {}

impl Sorter {
    pub fn new() -> Self {
        Self {}
    }

    pub fn sort(&mut self, list: InclusionList) -> impl Iterator<Item = Transaction> {
        let seed = list.digest();

        let (bundles, mut transactions) = list.into_transactions();

        let mut priority = Vec::new();

        for b in bundles {
            match ssz_decode::<Bytes, Vec<_>>(b.data(), Some(MAX_BUNDLE_TXS)) {
                Ok(txs) => {
                    for t in txs {
                        if t.len() > MAX_TXS_SIZE {
                            warn!("transaction exceeds max. allowed size {MAX_TXS_SIZE}");
                            continue;
                        }
                        match Transaction::decode(&t) {
                            Ok(trx) => priority.push(trx),
                            Err(err) => {
                                warn!(%err, "failed to decode transaction")
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(?err, "failed to ssz-decode priority bundle")
                }
            }
        }

        transactions.sort_unstable_by(|x, y| compare(&seed, x, y));

        priority.into_iter().chain(transactions)
    }
}

#[rustfmt::skip]
fn compare(seed: &[u8], x: &Transaction, y: &Transaction) -> Ordering {
    let mut hx = blake3::Hasher::new();
    let mut hy = blake3::Hasher::new();

    hx.update(seed);
    hy.update(seed);

    hx.update(x.from().as_deref().unwrap_or(&[]));
    hy.update(y.from().as_deref().unwrap_or(&[]));

    hx.finalize().as_bytes().cmp(hy.finalize().as_bytes())
        .then_with(|| x.nonce().cmp(&y.nonce())
        .then_with(|| x.digest().cmp(y.digest())))
}

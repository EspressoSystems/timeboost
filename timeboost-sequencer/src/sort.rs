use std::cmp::Ordering;

use ssz::decode_list_of_variable_length_items as ssz_decode;
use timeboost_types::{Bytes, InclusionList, SortedTransaction, Transaction};
use tracing::warn;

const MAX_BUNDLE_TXS: usize = 1024;
const MAX_TXS_SIZE: usize = 1024 * 1024;

#[derive(Debug)]
pub struct Sorter {}

impl Sorter {
    pub fn new() -> Self {
        Self {}
    }

    pub fn sort(&mut self, list: InclusionList) -> impl Iterator<Item = SortedTransaction> {
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
                            warn!("transaction exceeds max. allowed size {MAX_TXS_SIZE}");
                            continue;
                        }
                        match Transaction::decode(&t) {
                            Ok(tx) => {
                                let Ok(signer) = tx.tx().recover_signer() else {
                                    warn!("failed to recover signer");
                                    continue;
                                };
                                if priority {
                                    ptx.push(SortedTransaction::new(signer.into(), timestamp, tx))
                                } else {
                                    rtx.push(SortedTransaction::new(signer.into(), timestamp, tx))
                                }
                            }
                            Err(err) => {
                                warn!(%err, "failed to decode transaction")
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(?err, "failed to ssz-decode bundle")
                }
            }
        }

        rtx.sort_unstable_by(|x, y| compare(&seed, x, y));
        ptx.into_iter().chain(rtx)
    }
}

#[rustfmt::skip]
fn compare(seed: &[u8], x: &SortedTransaction, y: &SortedTransaction) -> Ordering {
    use alloy_consensus::transaction::Transaction;
    let mut hx = blake3::Hasher::new();
    let mut hy = blake3::Hasher::new();

    hx.update(seed);
    hy.update(seed);
    hx.update(x.address().as_slice());
    hy.update(y.address().as_slice());

    hx.finalize().as_bytes().cmp(hy.finalize().as_bytes())
        .then_with(|| x.tx().nonce().cmp(&y.tx().nonce()))
        .then_with(|| x.tx().hash().cmp(y.tx().hash()))
}

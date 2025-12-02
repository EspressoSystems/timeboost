use alloy::consensus::transaction::SignerRecoverable;
use multisig::PublicKey;
use ssz::decode_list_of_variable_length_items as ssz_decode;
use std::cmp::Ordering;
use timeboost_types::{Address, Bytes, InclusionList, Transaction};
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
                        match Transaction::decode(&t) {
                            Ok(tx) => {
                                if priority {
                                    ptx.push(tx)
                                } else {
                                    let Ok(recovered) = tx.recover_signer() else {
                                        warn!(node = %self.key, "failed to recover signer");
                                        continue;
                                    };
                                    rtx.push((recovered.into(), tx))
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
        ptx.extend(rtx.into_iter().map(|b| b.1));
        ptx
    }
}

#[rustfmt::skip]
fn compare(seed: &[u8], x: &(Address, Transaction), y: &(Address, Transaction)) -> Ordering {
    use alloy::consensus::transaction::Transaction;

    let mut hx = blake3::Hasher::new();
    let mut hy = blake3::Hasher::new();

    hx.update(seed);
    hy.update(seed);
    
    hx.update(x.0.as_slice());
    hy.update(y.0.as_slice());

    hx.finalize().as_bytes().cmp(hy.finalize().as_bytes())
        .then_with(|| x.1.nonce().cmp(&y.1.nonce()))
        .then_with(|| x.1.hash().cmp(y.1.hash()))
}

use cliquenet::Network;
use multisig::Committee;
use timeboost_core::types::{
    keyset::DecKeyInfo,
    round_number::RoundNumber,
    transaction::{Transaction, TransactionData},
};
use tokio::{
    spawn,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};
use tracing::{info, warn};

use crate::decrypter::Decrypter;

use super::{DecryptionPhase, InclusionList};

/// Implements the canonical decryption phase based on the spec.
pub struct CanonicalDecryptionPhase {
    enc_tx: Sender<(RoundNumber, Vec<TransactionData>)>,
    dec_rx: Receiver<(RoundNumber, Vec<TransactionData>)>,
    jh: JoinHandle<()>,
}

impl CanonicalDecryptionPhase {
    pub fn new(net: Network, committee: Committee, dec_key: DecKeyInfo) -> Self {
        // TODO: channel capacity should be max number of allowed txns.
        let (enc_tx, enc_rx) = mpsc::channel(1000);
        let (dec_tx, dec_rx) = mpsc::channel(1000);
        let decrypter = Decrypter::new(net, committee, dec_key);

        Self {
            enc_tx,
            dec_rx,
            jh: spawn(decrypter.go(enc_rx, dec_tx)),
        }
    }
}

impl Drop for CanonicalDecryptionPhase {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl DecryptionPhase for CanonicalDecryptionPhase {
    async fn decrypt(&mut self, inclusion_list: InclusionList) -> anyhow::Result<InclusionList> {
        // Implement the decryption logic here
        let r = inclusion_list.round_number;
        let mut txns = inclusion_list.txns.clone();
        if txns.is_empty() {
            return Ok(inclusion_list);
        }
        let mut encrypted_txns = vec![];
        // extract the encrypted txns from the list
        for (i, txn) in inclusion_list.txns.iter().enumerate() {
            match txn {
                Transaction::Priority {
                    nonce: _,
                    to: _,
                    txns,
                } => {
                    if txns[0].encrypt().is_some() {
                        encrypted_txns.push((i, txns[0].clone()));
                    }
                }
                Transaction::Regular { txn: txn1 } => {
                    if txn1.encrypt().is_some() {
                        encrypted_txns.push((i, txn1.clone()));
                    }
                }
            }
        }
        if encrypted_txns.is_empty() {
            return Ok(inclusion_list);
        }
        info!("we have {} encrypted txns", encrypted_txns.len());

        // submit batch to decrypter
        self.enc_tx
            .send((
                r,
                encrypted_txns
                    .iter()
                    .map(|(_, txn)| (*txn).clone())
                    .collect(),
            ))
            .await?;

        let dec_batch = self.dec_rx.recv().await;
        match dec_batch {
            Some(batch) => {
                for i in 0..encrypted_txns.len() {
                    let index = encrypted_txns[i].0;
                    // swap the encrypted tx with the decrypted tx
                    txns[index] = Transaction::Regular {
                        txn: batch.1[i].clone(),
                    };
                }
                let decrypted_inclusion_list = InclusionList {
                    txns,
                    ..inclusion_list
                };
                return Ok(decrypted_inclusion_list);
            }
            None => {
                warn!("failed to decrypt round: {}", r);
                Ok(inclusion_list)
            }
        }
    }
}

use std::collections::{BTreeMap, HashMap};

use bimap::BiMap;
use cliquenet::Network;
use multisig::Committee;
use timeboost_core::types::transaction::Transaction;
use tokio::{
    spawn,
    sync::mpsc::{self, Receiver, Sender},
    task::JoinHandle,
};

use crate::{decrypter::Decrypter, keyset::DecKeyInfo};

use super::{DecryptionPhase, InclusionList};

/// Implements the canonical decryption phase based on the spec.
pub struct CanonicalDecryptionPhase {
    enc_tx: Sender<Vec<Transaction>>,
    dec_rx: Receiver<Vec<Transaction>>,
    jh: JoinHandle<()>,
}

impl CanonicalDecryptionPhase {
    pub fn new(net: Network, committee: Committee, dec_key: DecKeyInfo) -> Self {
        // TODO: channal capacity should be max number of allowed txns.
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
        let mut encrypted_txns = vec![];
        // extract the encrypted txns from the list
        for (i, txn) in inclusion_list.txns.iter().enumerate() {
            // should be is_encrypted
            if txn.is_valid() {
                encrypted_txns.push((i, txn));
            }
        }

        // submit batch to decrypter
        self.enc_tx
            .send(
                encrypted_txns
                    .iter()
                    .map(|(_, txn)| (*txn).clone())
                    .collect(),
            )
            .await?;

        let dec_batch = self.dec_rx.recv().await.unwrap();

        for i in 0..encrypted_txns.len() {
            let index = encrypted_txns[i].0;
            // swap the encrypted tx with the decrypted tx
            txns[index] = dec_batch[i].clone();
        }
        let decrypted_inclusion_list = InclusionList {
            txns,
            ..inclusion_list
        };
        Ok(decrypted_inclusion_list)
    }
}

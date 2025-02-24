use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use bimap::BiMap;
use cliquenet::Network;
use multisig::Committee;
use sailfish::types::RoundNumber;
use serde::{Deserialize, Serialize};
use timeboost_core::types::transaction::Transaction;
use timeboost_crypto::{traits::threshold_enc::ThresholdEncScheme, DecryptionScheme, Plaintext};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, warn};

use crate::keyset::DecKeyInfo;

type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;
type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
//type KeyShare = <DecryptionScheme as ThresholdEncScheme>::KeyShare;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecShareInfo {
    pub round: RoundNumber,
    pub cid: Vec<u8>,
    pub share: DecShare,
}
/// Decrypter is responsible for:
/// 1. Sending decryption shares of encrypted items to other nodes.
/// 2. Receive decryption shares from other nodes.
/// 3a. (Upon) Receiving t+1 decryption shares for an item.
/// 3b. Attempt to decrypt the ciphertext associated with the item.
pub struct Decrypter {
    pub net: Network,
    pub committee: Committee,
    pub dec_key: DecKeyInfo,
    pub ciphertexts: BiMap<Vec<u8>, Ciphertext>,
    pub shares: Arc<tokio::sync::RwLock<BTreeMap<(RoundNumber, Vec<u8>), Vec<DecShareInfo>>>>,
}

impl Decrypter {
    pub fn new(net: Network, committee: Committee, dec_key: DecKeyInfo) -> Self {
        Self {
            net,
            committee,
            dec_key,
            ciphertexts: BiMap::new(),
            shares: Arc::new(tokio::sync::RwLock::new(BTreeMap::new())),
        }
    }
}

impl Decrypter {
    pub async fn go(
        mut self,
        mut enc_rx: Receiver<Vec<Transaction>>,
        dec_tx: Sender<Vec<Transaction>>,
    ) {
        loop {
            // single task to handle the decryption network
            tokio::select! {
                Ok((_pubkey, bytes)) = self.net.receive() => {
                    if let Ok(s) = bincode::deserialize::<DecShareInfo>(&bytes) {
                        self.shares.write().await
                            .entry((s.round.clone(), s.cid.clone()))
                            .or_insert_with(Vec::new)
                            .push(s.clone());
                        let decrypted_items = self.check_for_round(s.round);
                    } else {
                        warn!("failed to deserialize decryption share");
                        continue;
                    }
                },
                enc_txns = enc_rx.recv() => {
                    if let Some(enc_txns) = enc_txns {
                        self.submit_decrypt(RoundNumber::genesis(), enc_txns).await.unwrap();
                    }
                }
            }
        }
    }

    pub(crate) async fn submit_decrypt(
        &mut self,
        round: RoundNumber,
        encrypted_txns: Vec<Transaction>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for tx in encrypted_txns {
            if let Some(ciphertext_bytes) = tx.data() {
                let ciphertext = match bincode::deserialize::<Ciphertext>(ciphertext_bytes) {
                    Ok(ciphertext) => ciphertext,
                    Err(_) => {
                        warn!("failed to deserialize ciphertext");
                        continue;
                    }
                };
                match <DecryptionScheme as ThresholdEncScheme>::decrypt(
                    &self.dec_key.privkey,
                    &ciphertext,
                ) {
                    Ok(dec_share) => {
                        let share = DecShareInfo {
                            round,
                            cid: ciphertext.nonce().to_vec(),
                            share: dec_share,
                        };
                        self.shares
                            .write()
                            .await
                            .entry((round, ciphertext.nonce().to_vec()))
                            .or_insert_with(Vec::new)
                            .push(share.clone());

                        let _ = self.send(&share).await;
                    }
                    Err(_) => {
                        warn!("failed to decrypt ciphertext");
                        continue;
                    }
                }
            } else {
                error!("encrypted tx without data");
            }
        }
        Ok(())
    }

    async fn send(&self, share: &DecShareInfo) -> Result<(), Box<dyn std::error::Error>> {
        let share_bytes = bincode::serialize(&share)?;
        self.net
            .multicast(share_bytes.into())
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    async fn check_for_round(
        &self,
        round: RoundNumber,
    ) -> Option<Vec<(RoundNumber, Vec<u8>, Vec<u8>)>> {
        // Implement the logic for checking the round
        // This is a placeholder implementation

        let shares = self.shares.read().await;
        let round_entries: Vec<_> = shares.iter().filter(|(k, v)| k.0 == round).collect();
        let round_ready = round_entries
            .iter()
            .any(|(k, v)| v.len() <= usize::from(self.committee.threshold()));
        let first_key = round_entries.first().map(|e| e.0);

        if round_ready {
            if let Some(key) = first_key {
                let mut shares = self.shares.write().await;
                let round_shares = shares.split_off(key);
                let decrypted_items: Vec<(RoundNumber, Vec<u8>, Vec<u8>)> = round_shares
                    .into_iter()
                    .map(|(k, v)| {
                        let cid = v[0].cid.clone();
                        let committee = timeboost_crypto::Committee {
                            id: 0,
                            size: self.committee.size().get() as u64,
                        };
                        let dec_shares: Vec<_> = v.iter().map(|v| v.share.clone()).collect();
                        let item: Plaintext = DecryptionScheme::combine(
                            &committee,
                            &self.dec_key.combkey,
                            dec_shares.iter().collect::<Vec<_>>(),
                            self.ciphertexts.get_by_left(&cid).unwrap(),
                        )
                        .expect("unable to combine the shares");
                        (k.0, k.1, item.as_bytes().to_vec())
                    })
                    .collect();
                return Some(decrypted_items);
            }
        }

        None
    }
}

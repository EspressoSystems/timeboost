use core::str;
use std::{collections::BTreeMap, sync::Arc};

use bimap::BiMap;
use cliquenet::Network;
use multisig::Committee;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use timeboost_core::types::round_number::RoundNumber;
use timeboost_core::types::{
    keyset::DecKeyInfo,
    seqno::SeqNo,
    transaction::{Address, Nonce, TransactionData},
};

use timeboost_crypto::{traits::threshold_enc::ThresholdEncScheme, DecryptionScheme, Plaintext};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{info, warn};

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
    pub idx2nonce: BiMap<usize, Vec<u8>>,
    pub nonce2ct: BiMap<Vec<u8>, Ciphertext>,
    pub shares: Arc<Mutex<BTreeMap<(RoundNumber, Vec<u8>), Vec<DecShareInfo>>>>,
}

impl Decrypter {
    pub fn new(net: Network, committee: Committee, dec_key: DecKeyInfo) -> Self {
        Self {
            net,
            committee,
            dec_key,
            idx2nonce: BiMap::new(),
            nonce2ct: BiMap::new(),
            shares: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl Decrypter {
    pub async fn go(
        mut self,
        mut enc_rx: Receiver<(RoundNumber, Vec<TransactionData>)>,
        dec_tx: Sender<(RoundNumber, Vec<TransactionData>)>,
    ) {
        loop {
            // single task to handle the decryption network
            tokio::select! {
                Ok((pubkey, bytes)) = self.net.receive() => {
                    info!("received decryption share from: {}", pubkey);
                    if let Ok(s) = bincode::deserialize::<DecShareInfo>(&bytes) {
                        let round = s.clone().round;
                        let decrypted_items = self.handle_shares(s).await;
                        if let Some(decrypted_items) = decrypted_items {
                            info!("received enough shares to fully decrypt");
                            let _ = dec_tx.send((round, decrypted_items)).await;
                        } else {
                            continue;
                        }
                    } else {
                        warn!("failed to deserialize decryption share");
                        continue;
                    }
                },
                enc_txns = enc_rx.recv() => {
                    if let Some(enc_txns) = enc_txns {
                        info!("sending shares to fellow nodes: {}", enc_txns.1.len());
                        if let Err(e) = self.submit_decrypt(enc_txns.0, enc_txns.1).await {
                            warn!("failed to submit decrypt: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn submit_decrypt(
        &mut self,
        round: RoundNumber,
        encrypted_txns: Vec<TransactionData>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (idx, tx) in encrypted_txns.iter().enumerate() {
            let ciphertext = match bincode::deserialize::<Ciphertext>(tx.data()) {
                Ok(ciphertext) => ciphertext,
                Err(_) => {
                    warn!("failed to deserialize ciphertext");
                    continue;
                }
            };
            // mappings
            let nonce = ciphertext.nonce().to_vec();
            self.nonce2ct.insert(nonce.clone(), ciphertext.clone());
            self.idx2nonce.insert(idx, nonce.clone());
            info!("trying to decrypt share");
            match <DecryptionScheme as ThresholdEncScheme>::decrypt(
                &self.dec_key.privkey,
                &ciphertext,
            ) {
                Ok(dec_share) => {
                    let share = DecShareInfo {
                        round,
                        cid: nonce.clone(),
                        share: dec_share,
                    };
                    info!("successfully decrypted share");
                    {
                        self.shares
                            .lock()
                            .entry((round, nonce))
                            .or_insert_with(Vec::new)
                            .push(share.clone());
                    }
                    let _ = self.send(&share).await;
                }
                Err(_) => {
                    warn!("failed to create decryption share");
                    continue;
                }
            }
        }
        Ok(())
    }

    async fn send(&self, share: &DecShareInfo) -> Result<(), Box<dyn std::error::Error>> {
        let share_bytes = bincode::serialize(&share)?;
        info!("sending the actual shares");
        self.net
            .multicast(share_bytes.into())
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    async fn handle_shares(&self, share: DecShareInfo) -> Option<Vec<TransactionData>> {
        // we add the share to our map using round and nonce as key.
        {
            self.shares
                .lock()
                .entry((share.round.clone(), share.cid.clone()))
                .or_insert_with(Vec::new)
                .push(share.clone());
        }
        // we filter our shares on the given round.
        let (round_not_ready, first_key) = {
            let shares = self.shares.lock();

            let cloned_shares = shares.clone();
            let round_entries: Vec<_> = cloned_shares
                .into_iter()
                .filter(|(k, _v)| k.0 == share.round)
                .collect();

            // a round is "ready" when all ciphertexts for the round have enough shares.
            let round_not_ready = round_entries
                .iter()
                .any(|(_k, v)| v.len() <= usize::from(self.committee.threshold()));
            let first_key = round_entries.first().map(|e| e.0.clone());
            (round_not_ready, first_key)
        };
        info!("round not ready: {}", round_not_ready);
        if !round_not_ready {
            // then we can start combining decryption shares for each ciphertext
            if let Some(key) = first_key {
                info!("before write");

                let round_shares = self.shares.lock().split_off(&key);

                info!("after write");

                info!("the round shares: {}", round_shares.len());

                let mut decrypted_items: Vec<(usize, TransactionData)> = round_shares
                    .into_iter()
                    .map(|(_k, v)| {
                        let cid = v[0].cid.clone();
                        let committee = timeboost_crypto::Committee {
                            id: 0,
                            size: self.committee.size().get() as u64,
                        };
                        let dec_shares: Vec<_> = v.iter().map(|v| v.share.clone()).collect();
                        info!("number of shares: {}", dec_shares.len());
                        let idx = self.idx2nonce.get_by_right(&cid);
                        let idx = match idx {
                            Some(idx) => idx,
                            None => {
                                warn!("unable to find index for nonce");
                                return (
                                    0,
                                    TransactionData::new(
                                        Nonce::now(SeqNo::zero()),
                                        Address::zero(),
                                        vec![],
                                        Some(0),
                                    ),
                                );
                            }
                        };
                        match DecryptionScheme::combine(
                            &committee,
                            &self.dec_key.combkey,
                            dec_shares.iter().collect::<Vec<_>>(),
                            match self.nonce2ct.get_by_left(&cid) {
                                Some(c) => c,
                                None => {
                                    warn!("unable to find ciphertext for nonce");
                                    return (
                                        *idx,
                                        TransactionData::new(
                                            Nonce::now(SeqNo::zero()),
                                            Address::zero(),
                                            vec![],
                                            Some(0),
                                        ),
                                    );
                                }
                            },
                        ) {
                            Err(_) => {
                                warn!("failed to combine decryption shares");
                                return (
                                    *idx,
                                    TransactionData::new(
                                        Nonce::now(SeqNo::zero()),
                                        Address::zero(),
                                        vec![],
                                        Some(0),
                                    ),
                                );
                            }
                            Ok(item) => {
                                info!("combined the shares");
                                info!("PRINTING BYTES CODE:");
                                info!("{:?}", str::from_utf8(item.as_bytes()));
                                info!("found the index of the ciphertext");
                                (
                                    *idx,
                                    TransactionData::new(
                                        Nonce::now(SeqNo::zero()),
                                        Address::zero(),
                                        item.as_bytes().to_vec(),
                                        Some(0),
                                    ),
                                )
                            }
                        }
                    })
                    .collect();
                decrypted_items.sort_by_key(|tx| tx.0);
                return Some(decrypted_items.into_iter().map(|tx| tx.1).collect());
            }
        }

        None
    }
}

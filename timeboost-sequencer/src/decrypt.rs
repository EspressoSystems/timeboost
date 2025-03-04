use std::collections::BTreeMap;

use std::sync::Arc;

use bimap::BiMap;
use cliquenet::Network;
use parking_lot::Mutex;
use sailfish::types::RoundNumber;
use timeboost_crypto::traits::threshold_enc::ThresholdEncScheme;
use timeboost_crypto::{DecryptionScheme, Keyset, KeysetId, Nonce};
use timeboost_types::{
    DecShareKey, DecryptionKey, InclusionList, PriorityBundle, ShareInfo, Transaction,
};
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{error, warn};

type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;
type EncryptedData = Vec<(KeysetId, Vec<u8>)>;
type DecryptedData = Vec<Vec<u8>>;

const MAX_ROUNDS: usize = 100;

pub struct Decrypter {
    /// Incoming encrypted lists.
    incls: BTreeMap<RoundNumber, InclusionList>,
    /// Storing encrypted indicies.
    modified: BTreeMap<RoundNumber, (Vec<usize>, Vec<Transaction>)>,
    /// Map signaling decrypted lists.
    ready: BTreeMap<RoundNumber, Option<InclusionList>>,
    /// Send encrypted data.
    enc_tx: Sender<(RoundNumber, EncryptedData)>,
    /// Receive decrypted data.
    dec_rx: Receiver<(RoundNumber, DecryptedData)>,
    /// Worker task handle.
    jh: JoinHandle<()>,
}

impl Decrypter {
    pub fn new(net: Network, committee: Keyset, dec_sk: DecryptionKey) -> Self {
        let (enc_tx, enc_rx) = channel(MAX_ROUNDS);
        let (dec_tx, dec_rx) = channel(MAX_ROUNDS);
        let decrypter = Worker::new(net, committee, dec_sk);

        Self {
            ready: BTreeMap::new(),
            incls: BTreeMap::new(),
            modified: BTreeMap::new(),
            enc_tx,
            dec_rx,
            jh: spawn(decrypter.go(enc_rx, dec_tx)),
        }
    }

    // 1. extract encrypted txns from each inclusion list.
    // 2. send the encrypted data to the worker.
    pub async fn enqueue<I>(&mut self, incls: I)
    where
        I: IntoIterator<Item = InclusionList>,
    {
        for incl in incls {
            let mut encrypted_data = Vec::new();
            let round = incl.round();
            self.incls.insert(round, incl.clone());
            let (ptxs, txs) = incl.into_transactions();
            let mut modified_ptxs = Vec::new();
            let mut modified_txs = Vec::new();
            for (i, ptx) in ptxs.iter().enumerate() {
                if ptx.encrypted() {
                    encrypted_data.push((ptx.kid(), ptx.data().to_vec()));
                    modified_ptxs.push(i);
                }
            }
            for tx in txs.into_iter() {
                if tx.encrypted() {
                    encrypted_data.push((tx.kid(), tx.data().to_vec()));
                    modified_txs.push(tx);
                }
            }
            if let Err(e) = self.enc_tx.send((round, encrypted_data)).await {
                error!("failed to send encrypted data: {:?}", e);
            }
            self.modified.insert(round, (modified_ptxs, modified_txs));
            self.ready.insert(round, None);
        }
    }

    // 1. receive decrypted data for some round r.
    // 2. reassemble incl list and mark round r as "ready".
    // 3. if r is next round, then return list, otherwise, goto (1).
    pub async fn next(&mut self) -> Result<InclusionList, DecryptError> {
        while let Some((r, dec)) = self.dec_rx.recv().await {
            if let Some(incl) = self.incls.remove(&r) {
                // reassemble inclusion list for round r
                let mut decrypted_incl = incl.clone();
                let ptxs_len = incl.priority_bundles().len();
                let (modified_ptxs, modified_txs) = self
                    .modified
                    .remove(&r)
                    .expect("worker has incl list => was enqueued");

                let (mut ptxs, mut txs) = incl.into_transactions();
                for (i, m) in modified_ptxs.into_iter().enumerate() {
                    ptxs[m] = PriorityBundle::new_compute_hash(
                        ptxs[m].epoch(),
                        ptxs[m].seqno(),
                        dec[i].clone(),
                        ptxs[m].kid(),
                    );
                }

                for (i, tx) in modified_txs.into_iter().enumerate() {
                    // re-insert all decrypted txs (incl. deduplication)
                    txs.remove(&tx);
                    let dec_tx =
                        Transaction::new(tx.nonce(), tx.to(), dec[i + ptxs_len].clone(), tx.kid());
                    txs.insert(dec_tx);
                }

                decrypted_incl
                    .set_priority_bundles(ptxs)
                    .set_transactions(txs);

                self.ready.insert(r, Some(decrypted_incl));
            }

            // inclusion lists are processed in order; return if r is the immediate next round.
            if let Some(entry) = self.ready.first_entry() {
                if let Some(incl) = entry.get() {
                    return Ok(incl.clone());
                } else {
                    warn!(
                        "received decrypted txns for r={} but the next round is r={}",
                        r,
                        entry.key()
                    );
                }
            }
        }
        Err(DecryptError::Unknown)
    }
}

impl Drop for Decrypter {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

struct Worker {
    net: Network,
    committee: Keyset,
    dec_sk: DecryptionKey,
    idx2cid: BiMap<usize, Nonce>,
    cid2ct: BiMap<Nonce, Ciphertext>,
    shares: Arc<Mutex<BTreeMap<DecShareKey, Vec<DecShare>>>>,
}

impl Worker {
    pub fn new(net: Network, committee: Keyset, dec_sk: DecryptionKey) -> Self {
        Self {
            net,
            committee,
            dec_sk,
            idx2cid: BiMap::new(),
            cid2ct: BiMap::new(),
            shares: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn go(
        mut self,
        mut enc_rx: Receiver<(RoundNumber, EncryptedData)>,
        dec_tx: Sender<(RoundNumber, DecryptedData)>,
    ) {
        loop {
            tokio::select! {
                Ok((pubkey, bytes)) = self.net.receive() => {
                    if let Ok(s) = bincode::deserialize::<ShareInfo>(&bytes) {
                        if let Some((dec_round, dec_items)) = self.handle_shares(s).await {
                            let _ = dec_tx.send((dec_round, dec_items)).await;
                        } else {
                            continue;
                        }
                    } else {
                        warn!("failed to deserialize share from: {}", pubkey);
                        continue;
                    }
                },
                enc_txns = enc_rx.recv() => {
                    if let Some(enc_txns) = enc_txns {
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
        encrypted_item: Vec<(KeysetId, Vec<u8>)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut cids = vec![];
        let mut kids = vec![];
        let mut dec_shares = vec![];
        for (idx, item) in encrypted_item.iter().enumerate() {
            let (kid, item) = item;
            let ciphertext = match bincode::deserialize::<Ciphertext>(item) {
                Ok(ciphertext) => ciphertext,
                Err(_) => {
                    warn!("failed to deserialize ciphertext");
                    continue;
                }
            };
            // mappings
            let nonce = ciphertext.nonce();
            self.cid2ct.insert(nonce, ciphertext.clone());
            self.idx2cid.insert(idx, nonce);

            match <DecryptionScheme as ThresholdEncScheme>::decrypt(
                self.dec_sk.privkey(),
                &ciphertext,
            ) {
                Ok(dec_share) => {
                    let k = DecShareKey::new(round, nonce, *kid);
                    self.shares
                        .lock()
                        .entry(k)
                        .or_default()
                        .push(dec_share.clone());

                    cids.push(nonce);
                    kids.push(*kid);
                    dec_shares.push(dec_share);
                }
                Err(_) => {
                    warn!("failed to create decryption share");
                    continue;
                }
            }
        }

        let share_info = ShareInfo::new(round, kids, cids, dec_shares);
        let _ = self.send(&share_info).await;

        Ok(())
    }

    async fn send(&self, share: &ShareInfo) -> Result<(), Box<dyn std::error::Error>> {
        let share_bytes = bincode::serialize(&share)?;
        self.net
            .multicast(share_bytes.into())
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    async fn handle_shares(&mut self, share: ShareInfo) -> Option<(RoundNumber, Vec<Vec<u8>>)> {
        let round = share.round();
        self.insert_shares(share);
        self.check_shares(round).await
    }

    fn insert_shares(&self, share_info: ShareInfo) {
        let cids = share_info.cids();
        let shares = share_info.dec_shares();
        let kids = share_info.kids();

        if cids.len() != shares.len() || cids.len() != kids.len() {
            error!("invalid share info format");
        }
        // add the shares to the map using round, keyset id and nonce as key.
        for i in 0..cids.len() {
            let cid = cids[i];
            let s = shares[i].clone();

            let k = DecShareKey::new(share_info.round(), cid, kids[i]);
            self.shares.lock().entry(k).or_default().push(s);
        }
    }

    async fn check_shares(&mut self, round: RoundNumber) -> Option<(RoundNumber, Vec<Vec<u8>>)> {
        let ready = self
            .shares
            .lock()
            .iter()
            .filter(|(k, _)| k.round() == round)
            .all(|(_, v)| usize::from(self.committee.threshold()) < v.len());

        if ready {
            let mut shares = self.shares.lock();
            let mut to_remove = vec![];
            let round_entries: Vec<_> = shares.iter().filter(|(k, _)| k.round() == round).collect();
            let mut decrypted: Vec<Vec<u8>> = Vec::with_capacity(round_entries.len());

            // combine decryption shares for each ciphertext
            for (k, shares) in round_entries {
                let cid = k.cid();
                // TODO: make sure that the correct keyset is used for combining.
                let ciphertext = match self.cid2ct.get_by_left(cid) {
                    Some(c) => c,
                    None => {
                        warn!("received sufficient shares but not the actual ciphertext");
                        return None;
                    }
                };

                let idx = match self.idx2cid.get_by_right(cid) {
                    Some(idx) => idx,
                    None => {
                        error!("cipertext is present but corresponding id is missing");
                        return None;
                    }
                };

                let decrypted_data = match DecryptionScheme::combine(
                    &self.committee,
                    self.dec_sk.combkey(),
                    shares.iter().collect::<Vec<_>>(),
                    ciphertext,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("unable to combine received shares {:?}", e);
                        return None;
                    }
                };
                to_remove.push(*cid);
                decrypted[*idx] = decrypted_data.as_bytes().to_vec();
            }

            // clean up
            shares.retain(|k, _| k.round() != round);
            for cid in to_remove {
                self.idx2cid.remove_by_right(&cid);
                self.cid2ct.remove_by_left(&cid);
            }

            Some((round, decrypted))
        } else {
            // ciphertexts are not ready to be decrypted.
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {
    #[error("unknown decryption error")]
    Unknown,
}

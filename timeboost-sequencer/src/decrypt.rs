use std::collections::BTreeMap;

use bimap::BiMap;
use cliquenet::Network;
use sailfish::types::RoundNumber;
use timeboost_crypto::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};
use timeboost_crypto::{DecryptionScheme, Keyset, KeysetId, Nonce};
use timeboost_types::{
    DecShareKey, DecryptionKey, InclusionList, PriorityBundle, ShareInfo, Transaction,
};
use tokio::spawn;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

type DecShare = <DecryptionScheme as ThresholdEncScheme>::DecShare;
type Ciphertext = <DecryptionScheme as ThresholdEncScheme>::Ciphertext;

const MAX_ROUNDS: usize = 100;

/// Status of the inclusion list
enum Status {
    Encrypted(InclusionList),
    Decrypted(InclusionList),
}

impl From<Status> for InclusionList {
    fn from(status: Status) -> Self {
        match status {
            Status::Encrypted(incl) | Status::Decrypted(incl) => incl,
        }
    }
}

/// Encrypted item (Decrypter -> Worker)
struct EncryptedItem(KeysetId, Vec<u8>);

/// Decrypted item (Worker -> Decrypter)
struct DecryptedItem(Vec<u8>);

pub struct Decrypter {
    /// Incoming (encrypted) incl lists.
    incls: BTreeMap<RoundNumber, Status>,
    /// Store encrypted items info.
    modified: BTreeMap<RoundNumber, (Vec<usize>, Vec<Transaction>)>,
    /// Send encrypted data.
    enc_tx: Sender<(RoundNumber, Vec<EncryptedItem>)>,
    /// Send decrypted data.
    dec_tx: Sender<(RoundNumber, Vec<DecryptedItem>)>,
    /// Receive decrypted data.
    dec_rx: Receiver<(RoundNumber, Vec<DecryptedItem>)>,
    /// Worker task handle.
    jh: JoinHandle<()>,
}

impl Decrypter {
    pub fn new(net: Network, keyset: Keyset, dec_sk: DecryptionKey) -> Self {
        let (enc_tx, enc_rx) = channel(MAX_ROUNDS);
        let (dec_tx, dec_rx) = channel(MAX_ROUNDS);
        let decrypter = Worker::new(net, keyset, dec_sk);

        Self {
            enc_tx,
            dec_tx: dec_tx.clone(),
            dec_rx,
            incls: BTreeMap::new(),
            modified: BTreeMap::new(),
            jh: spawn(decrypter.go(enc_rx, dec_tx)),
        }
    }

    /// Identifies encrypted txns in inclusion lists and sends the
    /// encrypted data to the worker for hatching.
    pub async fn enqueue<I>(&mut self, incls: I) -> Result<(), DecryptError>
    where
        I: IntoIterator<Item = InclusionList>,
    {
        for incl in incls {
            let round = incl.round();
            let (encrypted_ptx_idx, encrypted_ptx_data): (Vec<_>, Vec<_>) = incl
                .priority_bundles()
                .iter()
                .enumerate()
                .filter(|(_, ptx)| ptx.encrypted())
                .map(|(i, ptx)| (i, EncryptedItem(ptx.kid(), ptx.data().to_vec())))
                .unzip();

            let (encrypted_tx, encrypted_tx_data): (Vec<_>, Vec<_>) = incl
                .transactions()
                .iter()
                .filter(|tx| tx.encrypted())
                .map(|tx| (tx.clone(), EncryptedItem(tx.kid(), tx.data().to_vec())))
                .unzip();

            let encrypted_data: Vec<EncryptedItem> = encrypted_ptx_data
                .into_iter()
                .chain(encrypted_tx_data)
                .collect();

            if encrypted_data.is_empty() {
                // short-circuit if no encrypted txns
                self.incls.insert(round, Status::Decrypted(incl));
                self.dec_tx
                    .send((round, vec![]))
                    .await
                    .map_err(|_| DecryptError::Shutdown)?;
            } else {
                self.enc_tx
                    .send((round, encrypted_data))
                    .await
                    .map_err(|_| DecryptError::Shutdown)?;
                // bookkeeping for reassembling inclusion list.
                self.incls.insert(round, Status::Encrypted(incl));
                self.modified
                    .insert(round, (encrypted_ptx_idx, encrypted_tx));
            }
        }
        Ok(())
    }

    /// Produces decrypted inclusion lists in round-order by:
    ///
    ///  1. receive decrypted (hatched) data for round r.
    ///  2. reassemble incl list and mark round as "decrypted".
    ///  3. if r is next round, then return list, otherwise, goto (1).
    ///
    pub async fn next(&mut self) -> Result<InclusionList, DecryptError> {
        while let Some((r, dec)) = self.dec_rx.recv().await {
            if let Some(status) = self.incls.get_mut(&r) {
                match status {
                    Status::Encrypted(incl) => {
                        // reassemble inclusion list for round r
                        assemble_incl(r, incl, dec, &mut self.modified)?;
                    }
                    Status::Decrypted(_) => {}
                }
            };

            // inclusion lists are processed in order; return only if r is decrypted.
            if let Some(entry) = self.incls.first_entry() {
                match entry.get() {
                    Status::Decrypted(incl) => return Ok(incl.clone()),
                    Status::Encrypted(_) => {
                        debug!(
                            "received decrypted txns for r={} but the next round is r={}",
                            r,
                            entry.key()
                        );
                    }
                }
            }
        }
        Err(DecryptError::Shutdown)
    }
}

fn assemble_incl(
    r: RoundNumber,
    incl: &mut InclusionList,
    dec: Vec<DecryptedItem>,
    modified: &mut BTreeMap<RoundNumber, (Vec<usize>, Vec<Transaction>)>,
) -> Result<(), DecryptError> {
    let (modified_ptxs, modified_txs) = modified
        .remove(&r)
        .expect("encrypted incl => modified entry");
    let (mut ptxs, mut txs) = incl.to_owned().into_transactions();
    if modified_ptxs.len() + modified_txs.len() != dec.len() {
        return Err(DecryptError::State);
    }
    modified_ptxs
        .into_iter()
        .enumerate()
        .map(|(i, m)| {
            if let Some(ptx) = ptxs.get_mut(m) {
                *ptx = PriorityBundle::new_with_hash(
                    ptx.epoch(),
                    ptx.seqno(),
                    dec.get(i).ok_or(DecryptError::State)?.0.clone(),
                    ptx.kid(),
                );
                Ok::<(), DecryptError>(())
            } else {
                Err(DecryptError::State)
            }
        })
        .collect::<Result<Vec<_>, DecryptError>>()?;

    modified_txs
        .into_iter()
        .enumerate()
        .map(|(i, tx)| {
            if let Some(tx) = txs.take(&tx) {
                let data = dec
                    .get(i + ptxs.len())
                    .ok_or(DecryptError::InvalidMessage)?
                    .0
                    .clone();
                let dec_tx = Transaction::new(tx.nonce(), tx.to(), data, tx.kid());
                txs.insert(dec_tx);
                Ok(())
            } else {
                Err(DecryptError::State)
            }
        })
        .collect::<Result<Vec<_>, DecryptError>>()?;

    Ok(())
}

impl Drop for Decrypter {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

type Incubator = BTreeMap<DecShareKey, Vec<DecShare>>;

/// Worker is responsible for "hatching" ciphertexts.
///
/// When ciphertexts in a round have received t+1 decryption shares
/// the shares can be combined to decrypt the ciphertext (hatching).
struct Worker {
    net: Network,
    committee: Keyset,
    dec_sk: DecryptionKey,
    idx2cid: BiMap<usize, Nonce>,
    cid2ct: BiMap<Nonce, Ciphertext>,
    shares: Incubator,
}

impl Worker {
    pub fn new(net: Network, committee: Keyset, dec_sk: DecryptionKey) -> Self {
        Self {
            net,
            committee,
            dec_sk,
            idx2cid: BiMap::new(),
            cid2ct: BiMap::new(),
            shares: Incubator::default(),
        }
    }

    pub async fn go(
        mut self,
        mut enc_rx: Receiver<(RoundNumber, Vec<EncryptedItem>)>,
        dec_tx: Sender<(RoundNumber, Vec<DecryptedItem>)>,
    ) {
        loop {
            let r;
            tokio::select! {
                // received batch of decryption shares from remote node.
                Ok((pubkey, bytes)) = self.net.receive() => {
                    if let Ok((s, _)) = bincode::serde::decode_from_slice::<ShareInfo, _>(&bytes, bincode::config::legacy()) {
                        r = s.round();
                        if let Err(e) = self.insert_shares(s) {
                            warn!("failed to insert shares from remote: {:?}", e);
                            continue;
                        }

                    } else {
                        warn!("failed to deserialize share from: {}", pubkey);
                        continue;
                    }
                }

                // received batch of encrypted data from local inclusion list.
                Some((round, enc_data)) = enc_rx.recv() => {
                    r = round;
                    match self.decrypt(round, enc_data).await {
                        Ok(s) => {
                            if let Err(e) = self.broadcast(&s).await {
                                warn!("failed to send share info: {:?}", e);
                            }
                            if let Err(e) = self.insert_shares(s) {
                                warn!("failed to insert local shares: {:?}", e);
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!("failed to decrypt data: {:?}", e);
                            continue;
                        }
                    }
                }
            }

            // check if ciphertexts hatched
            match self.hatch(r) {
                Ok(Some((dec_round, dec_items))) => {
                    if let Err(e) = dec_tx.send((dec_round, dec_items)).await {
                        error!("failed to send decrypted data: {:?}", e);
                        return;
                    }
                }
                Err(e) => match e {
                    DecryptError::MissingCiphertext(cid) => {
                        debug!("missing ciphertext for cid: {:?}", cid);
                    }
                    DecryptError::MissingIndex(cid) => {
                        warn!("missing index mapping for cid: {:?}", cid);
                    }
                    _ => {
                        warn!("failed to decrypt shares for round {}: {:?}", r, e);
                    }
                },
                _ => {}
            }
        }
    }

    async fn decrypt(
        &mut self,
        round: RoundNumber,
        encrypted_items: Vec<EncryptedItem>,
    ) -> Result<ShareInfo, DecryptError> {
        let mut cids = vec![];
        let mut kids = vec![];
        let mut dec_shares = vec![];

        for (idx, EncryptedItem(kid, data)) in encrypted_items.iter().enumerate() {
            let (ciphertext, _) =
                bincode::serde::decode_from_slice::<Ciphertext, _>(data, bincode::config::legacy())
                    .map_err(DecryptError::BincodeDecode)?;
            // mappings
            let cid = ciphertext.nonce();
            self.cid2ct.insert(cid, ciphertext.clone());
            self.idx2cid.insert(idx, cid);

            let dec_share = <DecryptionScheme as ThresholdEncScheme>::decrypt(
                self.dec_sk.privkey(),
                &ciphertext,
            )
            .map_err(DecryptError::Decryption)?;

            cids.push(cid);
            kids.push(*kid);
            dec_shares.push(dec_share);
        }

        Ok(ShareInfo::new(round, kids, cids, dec_shares))
    }

    async fn broadcast(&self, share: &ShareInfo) -> Result<(), DecryptError> {
        let share_bytes = bincode::serde::encode_to_vec(share, bincode::config::legacy())
            .map_err(DecryptError::BincodeEncode)?;
        self.net
            .multicast(share_bytes.into())
            .await
            .map_err(DecryptError::net)
    }

    fn insert_shares(&mut self, share_info: ShareInfo) -> Result<(), DecryptError> {
        let kids = share_info.kids();
        let cids = share_info.cids();
        let shares = share_info.dec_shares();

        // add the shares to the map using round, keyset id and nonce as key.
        (0..cids.len()).try_for_each(|i| {
            let kid = *kids.get(i).ok_or(DecryptError::InvalidMessage)?;
            let cid = cids.get(i).ok_or(DecryptError::InvalidMessage)?;
            let s = shares
                .get(i)
                .ok_or(DecryptError::InvalidMessage)?
                .to_owned();
            let k = DecShareKey::new(share_info.round(), *cid, kid);
            self.shares.entry(k).or_default().push(s);
            Ok(())
        })
    }

    fn hatch(
        &mut self,
        round: RoundNumber,
    ) -> Result<Option<(RoundNumber, Vec<DecryptedItem>)>, DecryptError> {
        // TODO: avoid linear scan if remote nodes batch same number of shares.
        let hatched = self
            .shares
            .iter()
            .filter(|(k, _)| k.round() == round)
            .all(|(_, v)| self.committee.threshold().get() < v.len());

        if !hatched {
            // ciphertexts are not ready to be decrypted.
            return Ok(None);
        }

        // combine decryption shares for each ciphertext
        let decrypted: BTreeMap<_, _> = self
            .shares
            .iter()
            .filter(|(k, _)| k.round() == round)
            .map(|(k, shares)| {
                // TODO: make sure that the correct keyset is used for combining.
                let ciphertext = self
                    .cid2ct
                    .remove_by_left(k.cid())
                    .ok_or(DecryptError::MissingCiphertext(*k.cid()))?
                    .1;

                let idx = self
                    .idx2cid
                    .remove_by_right(k.cid())
                    .ok_or(DecryptError::MissingIndex(*k.cid()))?
                    .1;

                let decrypted_data = DecryptionScheme::combine(
                    &self.committee,
                    self.dec_sk.combkey(),
                    shares.iter().collect::<Vec<_>>(),
                    &ciphertext,
                )
                .map_err(DecryptError::Decryption)?;
                Ok((idx, DecryptedItem(decrypted_data.into())))
            })
            .collect::<Result<_, DecryptError>>()?;

        self.shares.retain(|k, _| k.round() != round);
        Ok(Some((round, decrypted.into_values().collect())))
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecryptError {
    #[error("network error: {0}")]
    Net(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("bincode encode error: {0}")]
    BincodeEncode(#[from] bincode::error::EncodeError),

    #[error("bincode decode error: {0}")]
    BincodeDecode(#[from] bincode::error::DecodeError),

    #[error("decryption error: {0}")]
    Decryption(#[from] ThresholdEncError),

    #[error("decrypter has shut down")]
    Shutdown,

    #[error("missing ciphertext for cid: {:?}", .0)]
    MissingCiphertext(Nonce),

    #[error("missing index mapping for cid: {:?}", .0)]
    MissingIndex(Nonce),

    #[error("invalid message")]
    InvalidMessage,

    #[error("inconsistent state")]
    State,
}

impl DecryptError {
    pub(crate) fn net<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::Net(Box::new(e))
    }
}

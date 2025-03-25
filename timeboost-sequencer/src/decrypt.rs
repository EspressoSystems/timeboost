use bimap::BiMap;
use cliquenet::Network;
use multisig::PublicKey;
use sailfish::types::RoundNumber;
use std::collections::{BTreeMap, BTreeSet};
use timeboost_crypto::traits::threshold_enc::{ThresholdEncError, ThresholdEncScheme};
use timeboost_crypto::{DecryptionScheme, Keyset, KeysetId, Nonce};
use timeboost_types::{Bytes, DecShareKey, DecryptionKey, InclusionList, ShareInfo};
use tokio::spawn;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

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
struct EncryptedItem(KeysetId, Bytes);

/// Decrypted item (Worker -> Decrypter)
struct DecryptedItem(Bytes);

pub struct Decrypter {
    /// Incoming (encrypted) incl lists.
    incls: BTreeMap<RoundNumber, Status>,
    /// Store encrypted items info.
    modified: BTreeMap<RoundNumber, (Vec<usize>, Vec<usize>)>,
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
    pub fn new(label: PublicKey, net: Network, keyset: Keyset, dec_sk: DecryptionKey) -> Self {
        let (enc_tx, enc_rx) = channel(MAX_ROUNDS);
        let (dec_tx, dec_rx) = channel(MAX_ROUNDS);
        let decrypter = Worker::new(net, keyset, dec_sk);

        Self {
            enc_tx,
            dec_tx: dec_tx.clone(),
            dec_rx,
            incls: BTreeMap::new(),
            modified: BTreeMap::new(),
            jh: spawn(decrypter.go(label, enc_rx, dec_tx)),
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
            let (encrypted_pb_idx, encrypted_pb_data): (Vec<_>, Vec<_>) = incl
                .priority_bundles()
                .iter()
                .enumerate()
                .filter_map(|(i, priority)| {
                    priority
                        .bundle()
                        .kid()
                        .map(|kid| (i, EncryptedItem(kid, priority.bundle().data().clone())))
                })
                .unzip();

            let (encrypted_rb_idx, encrypted_rb_data): (Vec<_>, Vec<_>) = incl
                .regular_bundles()
                .iter()
                .enumerate()
                .filter_map(|(i, bundle)| {
                    bundle
                        .kid()
                        .map(|kid| (i, EncryptedItem(kid, bundle.data().clone())))
                })
                .unzip();

            let encrypted_data: Vec<EncryptedItem> = encrypted_pb_data
                .into_iter()
                .chain(encrypted_rb_data)
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
                    .insert(round, (encrypted_pb_idx, encrypted_rb_idx));
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
                        let dec_incl = assemble_incl(r, incl.to_owned(), dec, &mut self.modified)?;
                        *status = Status::Decrypted(dec_incl);
                    }
                    Status::Decrypted(_) => {}
                }
            };

            // inclusion lists are processed in order; return if next round is decrypted.
            if let Some(entry) = self.incls.first_entry() {
                match entry.get() {
                    Status::Decrypted(_) => {
                        let incl = entry.remove().into();
                        return Ok(incl);
                    }
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
    incl: InclusionList,
    dec: Vec<DecryptedItem>,
    modified: &mut BTreeMap<RoundNumber, (Vec<usize>, Vec<usize>)>,
) -> Result<InclusionList, DecryptError> {
    let (modified_priority_bundles, modified_regular_bundles) = modified
        .remove(&r)
        .expect("encrypted incl => modified entry");
    let mut new_incl =
        InclusionList::new(incl.round(), incl.timestamp(), incl.delayed_inbox_index());
    let (mut priority_bundles, regular_bundles) = incl.into_bundles();
    if modified_priority_bundles.len() + modified_regular_bundles.len() != dec.len() {
        return Err(DecryptError::State);
    }

    for (i, m) in modified_priority_bundles.into_iter().enumerate() {
        let bundle = priority_bundles
            .get_mut(m)
            .ok_or(DecryptError::InvalidMessage)?;
        bundle.set_data(dec.get(i).ok_or(DecryptError::State)?.0.clone());
    }

    let mut encrypted_bundles = vec![];
    for m in modified_regular_bundles.iter() {
        let encrypted_tx = regular_bundles
            .get(*m)
            .ok_or(DecryptError::InvalidMessage)?;
        encrypted_bundles.push(encrypted_tx.clone());
    }

    let mut new_bundles = BTreeSet::from_iter(regular_bundles);
    for (i, tx) in encrypted_bundles.into_iter().enumerate() {
        let mut decrypted_bundles = new_bundles.take(&tx).ok_or(DecryptError::InvalidMessage)?;
        let data = dec
            .get(i + priority_bundles.len())
            .ok_or(DecryptError::InvalidMessage)?
            .0
            .clone();
        decrypted_bundles.set_data(data);
        new_bundles.insert(decrypted_bundles);
    }

    new_incl
        .set_priority_bundles(priority_bundles)
        .set_regular_bundles(new_bundles);

    Ok(new_incl)
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
        label: PublicKey,
        mut enc_rx: Receiver<(RoundNumber, Vec<EncryptedItem>)>,
        dec_tx: Sender<(RoundNumber, Vec<DecryptedItem>)>,
    ) {
        loop {
            let r;
            trace!(
                node   = %label,
                round  = %self.shares.keys().next().map(|k| k.round()).unwrap_or(RoundNumber::genesis()),
                shares = %self.shares.len(),
                cids   = %self.cid2ct.len(),
            );
            tokio::select! {
                // received batch of decryption shares from remote node.
                Ok((remote_pk, bytes)) = self.net.receive() => {
                    if remote_pk == label {
                        continue;
                    }
                    if let Ok((s, _)) = bincode::serde::decode_from_slice::<ShareInfo, _>(&bytes, bincode::config::standard()) {
                        r = s.round();
                        if let Err(e) = self.insert_shares(s) {
                            warn!("failed to insert shares from remote: {:?}", e);
                            continue;
                        }

                    } else {
                        warn!("failed to deserialize shares from: {}", remote_pk);
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
            let (ciphertext, _) = bincode::serde::decode_from_slice::<Ciphertext, _>(
                data,
                bincode::config::standard(),
            )
            .map_err(DecryptError::BincodeDecode)?;

            // establish mappings
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
        let share_bytes = bincode::serde::encode_to_vec(share, bincode::config::standard())
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
        // add shares to the map using round, keyset id and nonce as key.
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
        let hatched = self
            .shares
            .iter()
            .filter(|(k, _)| k.round() == round)
            .all(|(_, v)| self.committee.threshold().get() < v.len());

        if !hatched {
            // ciphertexts are not ready to be decrypted.
            return Ok(None);
        }
        let mut to_remove = vec![];
        // combine decryption shares for each ciphertext
        let decrypted: BTreeMap<_, _> = self
            .shares
            .iter()
            .filter(|(k, _)| k.round() == round)
            .map(|(k, shares)| {
                let ciphertext = self
                    .cid2ct
                    .get_by_left(k.cid())
                    .ok_or(DecryptError::MissingCiphertext(*k.cid()))?;

                let idx = *self
                    .idx2cid
                    .get_by_right(k.cid())
                    .ok_or(DecryptError::MissingCiphertext(*k.cid()))?;

                let decrypted_data = DecryptionScheme::combine(
                    &self.committee,
                    self.dec_sk.combkey(),
                    shares.iter().collect::<Vec<_>>(),
                    ciphertext,
                )
                .map_err(DecryptError::Decryption)?;
                to_remove.push(*k.cid());
                Ok((
                    idx,
                    DecryptedItem(Bytes::from(<Vec<u8>>::from(decrypted_data))),
                ))
            })
            .collect::<Result<_, DecryptError>>()?;

        // clean up
        self.shares.retain(|k, _| k.round() != round);
        for cid in to_remove {
            self.idx2cid
                .remove_by_right(&cid)
                .ok_or(DecryptError::MissingIndex(cid))?;
            self.cid2ct
                .remove_by_left(&cid)
                .ok_or(DecryptError::MissingCiphertext(cid))?;
        }

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

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        num::NonZeroUsize,
        time::Duration,
    };
    use timeboost_utils::types::logging;

    use ark_std::test_rng;
    use cliquenet::{Network, NetworkMetrics};
    use multisig::SecretKey;
    use sailfish::types::RoundNumber;
    use timeboost_crypto::{
        DecryptionScheme, Keyset, Plaintext, PublicKey, traits::threshold_enc::ThresholdEncScheme,
    };
    use timeboost_types::{
        Address, Bundle, ChainId, DecryptionKey, Epoch, InclusionList, PriorityBundle, SeqNo,
        Signer, Timestamp, Unsigned,
    };
    use tracing::warn;

    use crate::decrypt::Decrypter;

    #[tokio::test]
    async fn test_with_encrypted_data() {
        logging::init_logging();
        let num_nodes = 5;
        let keyset = timeboost_crypto::Keyset::new(1, NonZeroUsize::new(num_nodes).unwrap());
        let encryption_key: PublicKey<_> =
            decode_bincode("kjGsCSgKRoBte3ohUroYzckRZCTknNbF44EagVmYGGp1YK");

        let mut decrypters = build_decrypters(keyset.clone()).await;

        // Craft a ciphertext for decryption
        let ptx_message = b"The quick brown fox jumps over the lazy dog".to_vec();
        let tx_message = b"The slow brown fox jumps over the lazy dog".to_vec();
        let ptx_plaintext = Plaintext::new(ptx_message.clone());
        let tx_plaintext = Plaintext::new(tx_message.clone());
        let ptx_ciphertext =
            DecryptionScheme::encrypt(&mut test_rng(), &keyset, &encryption_key, &ptx_plaintext)
                .unwrap();
        let tx_ciphertext =
            DecryptionScheme::encrypt(&mut test_rng(), &keyset, &encryption_key, &tx_plaintext)
                .unwrap();
        let ptx_ciphertext_bytes =
            bincode::serde::encode_to_vec(&ptx_ciphertext, bincode::config::standard())
                .expect("Failed to encode ciphertext");
        let tx_ciphertext_bytes =
            bincode::serde::encode_to_vec(&tx_ciphertext, bincode::config::standard())
                .expect("Failed to encode ciphertext");

        // Create inclusion lists with encrypted transactions
        let mut incl_list = InclusionList::new(RoundNumber::new(42), Timestamp::now(), 0.into());
        let keyset_id = keyset.id();
        let chain_id = ChainId::from(0);
        let epoch = Epoch::from(42);
        let auction = Address::default();
        let seqno = SeqNo::from(10);
        let signer = Signer::default();
        let bundle = PriorityBundle::<Unsigned>::new(
            Bundle::new(
                chain_id,
                epoch,
                ptx_ciphertext_bytes.into(),
                Some(keyset_id),
            ),
            auction,
            seqno,
        );
        let signed_bundle = bundle.sign(signer).expect("default signer");
        incl_list.set_priority_bundles(vec![signed_bundle]);
        incl_list.set_regular_bundles(vec![Bundle::new(
            chain_id,
            epoch,
            tx_ciphertext_bytes.into(),
            Some(keyset_id),
        )]);

        // Enqueue inclusion lists to each decrypter
        for d in decrypters.iter_mut() {
            if let Err(e) = d.enqueue(vec![incl_list.clone()]).await {
                warn!("failed to enqueue inclusion list: {:?}", e);
            }
        }

        // Collect decrypted inclusion lists
        let mut decrypted_lists = Vec::new();
        for d in decrypters.iter_mut() {
            let incl = d.next().await.unwrap();
            decrypted_lists.push(incl);
        }

        // Verify that all decrypted inclusion lists are correct
        for d in decrypted_lists {
            assert_eq!(d.round(), RoundNumber::new(42));
            assert_eq!(d.priority_bundles().len(), 1);
            assert_eq!(d.regular_bundles().len(), 1);
            let decrypted_ptx_data = d.priority_bundles()[0].bundle().data();
            let decrypted_tx_data = d.regular_bundles()[0].data();
            assert_eq!(decrypted_ptx_data.to_vec(), ptx_message);
            assert_eq!(decrypted_tx_data.to_vec(), tx_message);
        }
    }

    async fn build_decrypters(keyset: Keyset) -> Vec<Decrypter> {
        let signature_private_keys = [
            "24f9BtAxuZziE4BWMYA6FvyBuedxU9SVsgsoVcyw3aEWagH8eXsV6zi2jLnSvRVjpZkf79HDJNicXSF6FpRWkCXg",
            "2gtHurFq5yeJ8HGD5mHUPqniHbpEE83ELLpPqhxEvKhPJFcjMnUwdH2YsdhngMmQTqHo9B1Qna6uM13ug2Pir97k",
            "4Y7yyg11MBYJaeD2UWCh5cto8wizJoUCqFm7YjMbY3hXyWSWVPgi7y1D9e7D78a1NcWdE4k59D6vK9f6eCpzVkbQ",
            "zrjZDknq9nPhiBXKeG2PeotwxAayYkv2UFmxc2UsCGHsdu5vCsjqxn8ko2Rh2fWts76u6eCJYjDgKEaveutVhjW",
            "jW98dJM94zuvhRCA1bGLiPjakePTc1CYPP2V5iCswfayZiYujGYdSoE1MYDa61dHCyzPdEvGNBDmnFHS6jf83Km",
        ];
        let decryption_private_keys = [
            "jMbTDiLo8tgyERv92mGrCAe1s3KnnnyqhQeSYte6vUhZy1",
            "jysmvvvwSHu872gmxkejPP8RxUDpSpKChnkPMVeXyRibwN",
            "kCioHtYdX7pUVXJLceFFKx7j4czcqDjjS52FYbvy2AuyQV",
            "jVEU8hbv7uUntaDt4GgDxUKgoCu8UCXugx1coMeiVfn31L",
            "jUzpdPzgxn2zpaLXaHJiWJ2jbbD3scsP8YqscA1uZGhPfZ",
        ];

        let encryption_key = "kjGsCSgKRoBte3ohUroYzckRZCTknNbF44EagVmYGGp1YK";
        let comb_key = "AuMP7yjmQH98sUnn7gcP7UUEZ1zNNbzESuNFkizXXHLeyyeH89Ky6F3M5xQ5kDXHyBAuza2CJmyXG9r1n38dW5GYj3asqB1TJzxmCDpmQo7eGjQEgcfEhz521k91kymL7u14EaGriN43WfzDBvcvWjNq93tjTUpRtv4kBycAujLxsWUoaCZBFDVcYMrLAoNXAaCMZHNerseE5V9vqMmgDXRqXZZZtJFv6kgARqmqH";

        let signature_keys: Vec<_> = signature_private_keys
            .iter()
            .map(|s| SecretKey::try_from(&decode_bs58(s)[..]).expect("into secret key"))
            .collect();

        let decryption_keys: Vec<DecryptionKey> = decryption_private_keys
            .iter()
            .map(|k| {
                DecryptionKey::new(
                    decode_bincode(encryption_key),
                    decode_bincode(comb_key),
                    decode_bincode(k),
                )
            })
            .collect();

        let peers: Vec<_> = signature_keys
            .iter()
            .map(|k| {
                let port = portpicker::pick_unused_port().expect("find open port");
                (
                    k.public_key(),
                    SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                )
            })
            .collect();

        // Create decrypters for each node
        let mut decrypters = Vec::new();
        for i in 0..usize::from(keyset.size()) {
            let sig_key = signature_keys[i].clone();
            let (_, addr) = peers[i];

            let network = Network::create(
                addr,
                sig_key.clone().into(),
                peers.clone(),
                NetworkMetrics::default(),
            )
            .await
            .expect("starting network");

            let decrypter = Decrypter::new(
                sig_key.public_key(),
                network,
                keyset.clone(),
                decryption_keys[i].clone(),
            );
            decrypters.push(decrypter);
        }
        // wait for network
        let _ = tokio::time::sleep(Duration::from_secs(1)).await;
        decrypters
    }

    fn decode_bs58(encoded: &str) -> Vec<u8> {
        bs58::decode(encoded).into_vec().unwrap()
    }

    fn decode_bincode<T: serde::de::DeserializeOwned>(encoded: &str) -> T {
        bincode::serde::decode_from_slice(&decode_bs58(encoded), bincode::config::standard())
            .unwrap()
            .0
    }
}

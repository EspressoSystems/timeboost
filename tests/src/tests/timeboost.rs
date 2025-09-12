mod block_order;
mod handover;
mod test_timeboost_startup;
mod timeboost_handover;
mod transaction_order;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};

use alloy::eips::{BlockNumberOrTag, Encodable2718};
use bytes::Bytes;
use cliquenet::{Address, AddressableCommittee};
use metrics::NoMetrics;
use multisig::Keypair;
use multisig::{Committee, x25519};
use parking_lot::Mutex;
use sailfish_types::{RoundNumber, UNKNOWN_COMMITTEE_ID};
use test_utils::ports::alloc_ports;
use timeboost::builder::CertifierConfig;
use timeboost::config::{ChainConfig, ParentChain};
use timeboost::crypto::prelude::DkgDecKey;
use timeboost::sequencer::{Sequencer, SequencerConfig};
use timeboost::types::{BlockNumber, BundleVariant, KeyStore, ThresholdKeyCell, Transaction};
use timeboost_utils::load_generation::make_bundle;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tracing::warn;
use url::Url;

async fn make_configs<R>(
    size: NonZeroUsize,
    recover_index: R,
) -> (
    Vec<ThresholdKeyCell>,
    Vec<(SequencerConfig, CertifierConfig)>,
)
where
    R: Into<Option<usize>>,
{
    let mut parts = Vec::new();
    for _ in 0..size.into() {
        let [p1, p2, p3] = alloc_ports(3).await.unwrap().try_into().unwrap();
        let a1 = Address::from((Ipv4Addr::LOCALHOST, p1));
        let a2 = Address::from((Ipv4Addr::LOCALHOST, p2));
        let a3 = Address::from((Ipv4Addr::LOCALHOST, p3));
        parts.push((
            Keypair::generate(),
            x25519::Keypair::generate().unwrap(),
            DkgDecKey::generate(),
            a1,
            a2,
            a3,
        ))
    }

    let committee = Committee::new(
        UNKNOWN_COMMITTEE_ID,
        parts
            .iter()
            .enumerate()
            .map(|(i, (kp, ..))| (i as u8, kp.public_key())),
    );

    let sailfish_committee = AddressableCommittee::new(
        committee.clone(),
        parts
            .iter()
            .map(|(kp, xp, _, sa, ..)| (kp.public_key(), xp.public_key(), sa.clone())),
    );

    let decrypt_committee = AddressableCommittee::new(
        committee.clone(),
        parts
            .iter()
            .map(|(kp, xp, _, _, da, ..)| (kp.public_key(), xp.public_key(), da.clone())),
    );

    let produce_committee = AddressableCommittee::new(
        committee.clone(),
        parts
            .iter()
            .map(|(kp, xp, _, _, _, pa, ..)| (kp.public_key(), xp.public_key(), pa.clone())),
    );

    let key_store = KeyStore::new(
        committee.clone(),
        parts
            .iter()
            .enumerate()
            .map(|(i, (_, _, sk, ..))| (i as u8, sk.into())),
    );

    let mut cfgs = Vec::new();
    let mut enc_keys = Vec::new();
    let recover_index = recover_index.into();

    for (i, (kpair, xpair, dkg_sk, sa, da, pa)) in parts.into_iter().enumerate() {
        let enc_key = ThresholdKeyCell::new();
        let conf = SequencerConfig::builder()
            .sign_keypair(kpair.clone())
            .dh_keypair(xpair.clone())
            .dkg_key(dkg_sk)
            .sailfish_addr(sa)
            .decrypt_addr(da)
            .sailfish_committee(sailfish_committee.clone())
            .decrypt_committee((decrypt_committee.clone(), key_store.clone()))
            .recover(recover_index.map(|r| r == i).unwrap_or(false))
            .leash_len(100)
            .threshold_dec_key(enc_key.clone())
            .chain_config(
                ChainConfig::builder()
                    .namespace(10101)
                    .parent(
                        ParentChain::builder()
                            .id(1)
                            .rpc_url(
                                "https://theserversroom.com/ethereum/54cmzzhcj1o/"
                                    .parse::<Url>()
                                    .expect("valid url"),
                            )
                            .ws_url(
                                "wss://theserversroom.com/ethereumws/54cmzzhcj1o/"
                                    .parse::<Url>()
                                    .expect("valid url"),
                            )
                            .ibox_contract(alloy::primitives::Address::default())
                            .key_manager_contract(alloy::primitives::Address::default())
                            .block_tag(BlockNumberOrTag::Finalized)
                            .build(),
                    )
                    .build(),
            )
            .build();
        let pcf = CertifierConfig::builder()
            .sign_keypair(kpair)
            .dh_keypair(xpair)
            .address(pa)
            .recover(recover_index.map(|r| r == i).unwrap_or(false))
            .committee(produce_committee.clone())
            .build();
        enc_keys.push(enc_key);
        cfgs.push((conf, pcf));
    }

    (enc_keys, cfgs)
}

/// Generate random bundles at a fixed frequency.
async fn gen_bundles(enc_key: ThresholdKeyCell, tx: broadcast::Sender<BundleVariant>) {
    loop {
        let Ok(b) = make_bundle(enc_key.read().await.pubkey()) else {
            warn!("Failed to generate bundle");
            continue;
        };
        if tx.send(b).is_err() {
            warn!("Failed to broadcast bundle");
            return;
        }
        sleep(Duration::from_millis(10)).await
    }
}

fn hash(tx: &[Transaction]) -> Bytes {
    let mut h = blake3::Hasher::new();
    for t in tx {
        h.update(&t.encoded_2718());
    }
    Bytes::copy_from_slice(h.finalize().as_bytes())
}

/// Map round numbers to block numbers.
///
/// Block numbers need to be consistent, consecutive and strictly monotonic.
/// The round numbers of our sequencer output may contain gaps. To provide
/// block numbers with the required properties we have here one monotonic
/// counter and record which block number is used for a round number.
/// Subsequent lookups will then get a consistent result.
struct Round2Block {
    counter: AtomicU64,
    block_numbers: Mutex<HashMap<RoundNumber, BlockNumber>>,
}

impl Round2Block {
    fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
            block_numbers: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, r: RoundNumber) -> BlockNumber {
        let mut map = self.block_numbers.lock();
        *map.entry(r)
            .or_insert_with(|| self.counter.fetch_add(1, Ordering::Relaxed).into())
    }
}

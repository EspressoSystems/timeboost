use std::cmp::min;
use std::collections::HashMap;
use std::iter::repeat_with;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::Arc;

use alloy::eips::BlockNumberOrTag;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Certificate, Committee, CommitteeId, Keypair, x25519};
use sailfish::types::{ConsensusTime, RoundNumber, Timestamp};
use timeboost::builder::Certifier;
use timeboost::config::{CERTIFIER_PORT_OFFSET, ChainConfig, DECRYPTER_PORT_OFFSET};
use timeboost::crypto::prelude::DkgDecKey;
use timeboost::sequencer::{Output, SequencerConfig};
use timeboost::types::{Block, BlockInfo, BundleVariant, KeyStore, ThresholdKeyCell};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::tests::timeboost::{Round2Block, hash};

use super::*;

#[derive(Debug, Clone)]
enum Cmd {
    NextCommittee(ConsensusTime, AddressableCommittee, KeyStore),
    Bundle(BundleVariant),
}

/// Run a handover test between the current and the next set of nodes.
async fn run_handover(
    curr: Vec<(ThresholdKeyCell, SequencerConfig, CertifierConfig)>,
    next: Vec<(ThresholdKeyCell, SequencerConfig, CertifierConfig)>,
) {
    const NEXT_COMMITTEE_DELAY: u64 = 15;
    const NUM_OF_BLOCKS_PER_EPOCH: usize = 50;

    let tasks = TaskTracker::new();
    let (bcast, _) = broadcast::channel(1024);
    let finish = CancellationToken::new();
    let round2block = Arc::new(Round2Block::new());

    let a1 = curr[0].1.sailfish_committee().clone();
    let a2 = next[0].1.sailfish_committee().clone();
    let c1 = a1.committee().id();
    let c2 = a2.committee().id();
    let d2 = next[0].1.decrypt_committee().clone();

    let num = a1.committee().size();
    let quorum = a1.committee().one_honest_threshold();
    let diff = a1.diff(&a2).count();

    assert!(diff > 0);
    assert_ne!(c1, c2);

    let mut out1 = Vec::new();

    // run committee 1 (current):
    for (_, seq_conf, cert_conf) in &curr {
        let sc = seq_conf.clone();
        let cc = cert_conf.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let finish = finish.clone();
        let mut cmd = bcast.subscribe();
        let label = sc.sign_keypair().public_key();
        let r2b = round2block.clone();

        tasks.spawn(async move {
            let mut s = Sequencer::new(sc, &NoMetrics).await.unwrap();
            let mut c = Certifier::new(cc, &NoMetrics).await.unwrap();
            let mut r: Option<RoundNumber> = None;
            let c_handle = c.handle();

            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(Cmd::NextCommittee(t, a, k)) => {
                            s.set_next_committee(t, a.clone(), k).await.unwrap();
                            c.set_next_committee(a.clone()).await.unwrap();
                        }
                        Ok(Cmd::Bundle(bundle)) => {
                            s.add_bundle(bundle).await.unwrap();
                        }
                        Err(RecvError::Lagged(e)) => {
                           warn!("lagging behind: {e}");
                        }
                        Err(err) => panic!("command channel error: {err}")
                    },
                    out = s.next() => match out {
                            Ok(o) => {
                                match o {
                                    Output::Transactions { round, timestamp: _, transactions, delayed_inbox_index: _ } => {
                                        if Some(round) == r {
                                            continue
                                        }
                                        r = Some(round);
                                        let i = r2b.get(round);
                                        let b = Block::new(i, *round, hash(&transactions));
                                        c_handle.enqueue(b).await.unwrap()
                                    }
                                    Output::UseCommittee(round) => {
                                        c.use_committee(round).await.unwrap();
                                    },
                                }
                            }
                            Err(_) => {
                                error!(node = %s.public_key(), "no sequencer output");
                                continue;
                            },
                    },
                    blk = c.next_block() => {
                        let b = blk.expect("block");
                        debug!(node = %s.public_key(), hash = %b.data().hash(), "block received");
                        let c: Certificate<BlockInfo> = b.into();
                        tx.send(c.into_data()).unwrap()
                    },
                    _ = finish.cancelled() => {
                        info!(node = %s.public_key(), "done");
                        return
                    }
                }
            }
        });
        out1.push((label, rx))
    }

    // wait for all decryption keys in current to be ready
    for (key, _, _) in &curr {
        key.read().await;
    }

    // generate bundles
    tasks.spawn({
        let (key, _, _) = &curr[0];
        let key = key.clone();
        let bcast = bcast.clone();
        async move {
            let (tx, mut rx) = tokio::sync::broadcast::channel(200);
            tokio::spawn(gen_bundles(key, tx));
            while let Ok(bundle) = rx.recv().await {
                if let Err(e) = bcast.send(Cmd::Bundle(bundle)) {
                    warn!("Failed to send bundle: {}", e);
                    break;
                }
            }
        }
    });

    // wait for the current to become active
    tokio::time::sleep(Duration::from_secs(5)).await;

    // inform about upcoming committee change
    let t = ConsensusTime(Timestamp::now() + NEXT_COMMITTEE_DELAY);
    bcast.send(Cmd::NextCommittee(t, a2, d2.1)).unwrap();

    let mut out2 = Vec::new();

    // run committee 2 (next):
    for (_, seq_conf, cert_conf) in &next {
        let ours = seq_conf.sign_keypair().public_key();

        if curr
            .iter()
            .any(|(_, s, _)| s.sign_keypair().public_key() == ours)
        {
            continue;
        }
        let (tx, rx) = mpsc::unbounded_channel();
        let seq_conf = seq_conf.clone();
        let cert_conf = cert_conf.clone();
        let finish = finish.clone();
        let mut cmd = bcast.subscribe();
        let label = seq_conf.sign_keypair().public_key();
        let r2b = round2block.clone();

        tasks.spawn(async move {
          let mut s = Sequencer::new(seq_conf, &NoMetrics)
                .await
                .unwrap();
            let mut c = Certifier::new(cert_conf, &NoMetrics)
                .await
                .unwrap();
            let mut r: Option<sailfish_types::RoundNumber> = None;
            let c_handle = c.handle();

            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(Cmd::NextCommittee(t, a, k)) => {
                            s.set_next_committee(t, a.clone(), k).await.unwrap();
                            c.set_next_committee(a.clone()).await.unwrap();
                        }
                        Ok(Cmd::Bundle(bundle)) => {
                            s.add_bundle(bundle).await.unwrap();
                        }
                        Err(RecvError::Lagged(e)) => {
                           warn!("lagging behind: {e}");
                        }
                        Err(err) => panic!("command channel error: {err}")
                    },
                    out = s.next() => match out {
                            Ok(o) => {
                                match o {
                                    Output::Transactions { round, timestamp: _, transactions, delayed_inbox_index: _ } => {
                                        if Some(round) == r {
                                            continue
                                        }
                                        r = Some(round);
                                        let i = r2b.get(round);
                                        let b = Block::new(i, *round, hash(&transactions));
                                        c_handle.enqueue(b).await.unwrap()
                                    }
                                    Output::UseCommittee(round) => {
                                        c.use_committee(round).await.unwrap();
                                    },
                                }
                            }
                            Err(_) => {
                                error!(node = %s.public_key(), "no sequencer output");
                                continue;
                            },
                    },
                    blk = c.next_block() => {
                        let b = blk.expect("block");
                        debug!(node = %s.public_key(), hash = %b.data().hash(), "block received");
                        let c: Certificate<BlockInfo> = b.into();
                        tx.send(c.into_data()).unwrap()
                    },
                    _ = finish.cancelled() => {
                        info!(node = %s.public_key(), "done");
                        return
                    }
                }
            }
        });
        out2.push((label, rx))
    }

    let mut map: HashMap<BlockInfo, usize> = HashMap::new();

    for b in 0..NUM_OF_BLOCKS_PER_EPOCH {
        map.clear();
        info!(block = %b);
        for (node, r) in &mut out1 {
            debug!(%node, block = %b, "awaiting ...");
            let info = r.recv().await.unwrap();
            *map.entry(info).or_default() += 1
        }
        if map.values().any(|n| *n >= quorum.get() && *n <= num.get()) {
            continue;
        }
        for (info, n) in map {
            eprintln!("{}: {} = {n}", info.hash(), info.round().num())
        }
        panic!("outputs do not match")
    }

    for b in 0..NUM_OF_BLOCKS_PER_EPOCH {
        map.clear();
        info!(block = %b);
        for (node, r) in &mut out2 {
            debug!(%node, block = %b, "awaiting ...");
            let info = r.recv().await.unwrap();
            *map.entry(info).or_default() += 1
        }
        if map
            .values()
            .any(|n| *n >= min(diff, quorum.get()) && *n <= num.get())
        {
            // votes only collected from new nodes in next
            continue;
        }
        for (info, n) in map {
            eprintln!("{}: {} = {n}", info.hash(), info.round().num())
        }
        panic!("outputs do not match")
    }

    finish.cancel();
}

/// Create sequencer configs.
async fn mk_configs(
    id: CommitteeId,
    prev: &[(ThresholdKeyCell, SequencerConfig, CertifierConfig)],
    keep: usize,
    add: NonZeroUsize,
    set_prev: bool,
) -> Vec<(ThresholdKeyCell, SequencerConfig, CertifierConfig)> {
    let sign_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.1.sign_keypair().clone())
        .chain(repeat_with(Keypair::generate).take(add.get()))
        .collect::<Vec<_>>();

    let dh_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.1.dh_keypair().clone())
        .chain(repeat_with(|| x25519::Keypair::generate().unwrap()).take(add.get()))
        .collect::<Vec<_>>();

    let dkg_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.1.dkg_key().clone())
        .chain(repeat_with(DkgDecKey::generate).take(add.get()))
        .collect::<Vec<_>>();

    let mut sf_addrs = prev
        .iter()
        .take(keep)
        .map(|c| c.1.sailfish_address().clone())
        .collect::<Vec<_>>();

    sf_addrs.extend(
        alloc_ports(add.get() as u16)
            .await
            .unwrap()
            .into_iter()
            .map(|p| Address::from((Ipv4Addr::LOCALHOST, p))),
    );

    let de_addrs = sf_addrs
        .iter()
        .cloned()
        .map(|addr| addr.with_offset(DECRYPTER_PORT_OFFSET))
        .collect::<Vec<_>>();

    let cert_addrs = sf_addrs
        .iter()
        .cloned()
        .map(|addr| addr.with_offset(CERTIFIER_PORT_OFFSET))
        .collect::<Vec<_>>();

    let committee = Committee::new(
        id,
        sign_keys
            .iter()
            .enumerate()
            .map(|(i, kp)| (i as u8, kp.public_key())),
    );

    let sf_committee = AddressableCommittee::new(
        committee.clone(),
        sign_keys
            .iter()
            .zip(&dh_keys)
            .zip(&sf_addrs)
            .map(|((k, x), a)| (k.public_key(), x.public_key(), a.clone())),
    );

    let de_committee = AddressableCommittee::new(
        committee.clone(),
        sign_keys
            .iter()
            .zip(&dh_keys)
            .zip(&de_addrs)
            .map(|((k, x), a)| (k.public_key(), x.public_key(), a.clone())),
    );

    let prod_committee = AddressableCommittee::new(
        committee.clone(),
        sign_keys
            .iter()
            .zip(&dh_keys)
            .zip(&cert_addrs)
            .map(|((k, x), a)| (k.public_key(), x.public_key(), a.clone())),
    );

    let key_store = KeyStore::new(
        committee.clone(),
        dkg_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (i as u8, sk.into())),
    );

    let mut nodes = Vec::new();

    for (i, kpair) in sign_keys.into_iter().enumerate() {
        let xpair = &dh_keys[i];
        let dkg_sk = &dkg_keys[i];
        let sa = &sf_addrs[i];
        let da = &de_addrs[i];
        let pa = &cert_addrs[i];
        let enc_key = ThresholdKeyCell::new();
        let conf = SequencerConfig::builder()
            .sign_keypair(kpair.clone())
            .dh_keypair(xpair.clone())
            .dkg_key(dkg_sk.clone())
            .sailfish_addr(sa.clone())
            .decrypt_addr(da.clone())
            .sailfish_committee(sf_committee.clone())
            .decrypt_committee((de_committee.clone(), key_store.clone()))
            .maybe_previous_sailfish_committee(
                set_prev.then(|| prev[0].1.sailfish_committee().clone()),
            )
            .maybe_previous_decrypt_committee(
                set_prev.then(|| prev[0].1.decrypt_committee().clone()),
            )
            .recover(false)
            .leash_len(1000)
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
            .dh_keypair(xpair.clone())
            .address(pa.clone())
            .recover(false)
            .committee(prod_committee.clone())
            .build();
        nodes.push((enc_key, conf, pcf));
    }

    nodes
}

struct TestConfig {
    committee_id: CommitteeId,
    prev_configs: Vec<(ThresholdKeyCell, SequencerConfig, CertifierConfig)>,
    keep: usize,
    add: NonZeroUsize,
    set_prev: bool,
}

impl TestConfig {
    fn new(committee_id: u64) -> Self {
        Self {
            committee_id: committee_id.into(),
            prev_configs: Vec::new(),
            keep: 0,
            add: NonZeroUsize::new(5).unwrap(),
            set_prev: false,
        }
    }

    fn with_prev_configs(
        mut self,
        prev: &[(ThresholdKeyCell, SequencerConfig, CertifierConfig)],
    ) -> Self {
        self.prev_configs = prev.to_vec();
        self
    }

    fn keep_nodes(mut self, keep: usize) -> Self {
        self.keep = keep;
        self
    }

    fn add_nodes(mut self, add: NonZeroUsize) -> Self {
        self.add = add;
        self
    }

    fn set_previous_committee(mut self, set: bool) -> Self {
        self.set_prev = set;
        self
    }

    async fn build(self) -> Vec<(ThresholdKeyCell, SequencerConfig, CertifierConfig)> {
        mk_configs(
            self.committee_id,
            &self.prev_configs,
            self.keep,
            self.add,
            self.set_prev,
        )
        .await
    }
}

#[tokio::test]
async fn handover_0_to_5() {
    init_logging();

    let c1 = TestConfig::new(0).build().await;
    let c2 = TestConfig::new(1)
        .with_prev_configs(&c1)
        .keep_nodes(0)
        .add_nodes(NonZeroUsize::new(5).unwrap())
        .set_previous_committee(true)
        .build()
        .await;

    run_handover(c1, c2).await;
}

#[tokio::test]
async fn handover_1_to_4() {
    init_logging();

    let c1 = TestConfig::new(0).build().await;
    let c2 = TestConfig::new(1)
        .with_prev_configs(&c1)
        .keep_nodes(1)
        .add_nodes(NonZeroUsize::new(4).unwrap())
        .set_previous_committee(true)
        .build()
        .await;

    run_handover(c1, c2).await;
}

#[tokio::test]
async fn handover_2_to_3() {
    init_logging();

    let c1 = TestConfig::new(0).build().await;
    let c2 = TestConfig::new(1)
        .with_prev_configs(&c1)
        .keep_nodes(2)
        .add_nodes(NonZeroUsize::new(3).unwrap())
        .set_previous_committee(true)
        .build()
        .await;

    run_handover(c1, c2).await;
}

#[tokio::test]
async fn handover_3_to_2() {
    init_logging();

    let c1 = TestConfig::new(0).build().await;
    let c2 = TestConfig::new(1)
        .with_prev_configs(&c1)
        .keep_nodes(3)
        .add_nodes(NonZeroUsize::new(2).unwrap())
        .set_previous_committee(true)
        .build()
        .await;
    run_handover(c1, c2).await;
}

#[tokio::test]
async fn handover_4_to_1() {
    init_logging();

    let c1 = TestConfig::new(0).build().await;
    let c2 = TestConfig::new(1)
        .with_prev_configs(&c1)
        .keep_nodes(4)
        .add_nodes(NonZeroUsize::new(1).unwrap())
        .set_previous_committee(true)
        .build()
        .await;
    run_handover(c1, c2).await;
}

#[tokio::test]
async fn handover_3_to_5() {
    init_logging();
    let c1 = TestConfig::new(0).build().await;
    let c2 = TestConfig::new(1)
        .with_prev_configs(&c1)
        .keep_nodes(3)
        .add_nodes(NonZeroUsize::new(5).unwrap())
        .set_previous_committee(true)
        .build()
        .await;
    run_handover(c1, c2).await;
}

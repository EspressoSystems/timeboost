use alloy::eips::BlockNumberOrTag;
use cliquenet::{Address, AddressableCommittee};
use metrics::NoMetrics;
use multisig::{Certificate, Committee, CommitteeId, Keypair, x25519};
use sailfish::types::{ConsensusTime, Timestamp};
use std::collections::HashMap;
use std::iter::{once, repeat_with};
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use timeboost::builder::{Certifier, CertifierConfig};
use timeboost::config::{ChainConfig, ParentChain};
use timeboost::crypto::prelude::DkgDecKey;
use timeboost::sequencer::{Output, Sequencer, SequencerConfig};
use timeboost::types::{Block, BlockInfo, BundleVariant, DecryptionKeyCell, KeyStore};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::tests::timeboost::{Round2Block, hash};

use super::gen_bundles;

#[derive(Debug, Clone)]
enum Cmd {
    NextCommittee(ConsensusTime, AddressableCommittee, KeyStore),
    Bundle(BundleVariant),
}

/// Create sequencer configs.
///
/// A (possible empty) slice of previous configs can be given, of which some
/// subset can be kept. A given number of additional configs are created.
/// Finally, the `set_prev` flag indicates if the previous committee should be
/// set on the configs.
fn mk_configs(
    id: CommitteeId,
    prev: &[(SequencerConfig, CertifierConfig)],
    keep: usize,
    add: NonZeroUsize,
    set_prev: bool,
) -> (
    Vec<DecryptionKeyCell>,
    Vec<(SequencerConfig, CertifierConfig)>,
) {
    let sign_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.0.sign_keypair().clone())
        .chain(repeat_with(Keypair::generate).take(add.get()))
        .collect::<Vec<_>>();

    let dh_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.0.dh_keypair().clone())
        .chain(repeat_with(|| x25519::Keypair::generate().unwrap()).take(add.get()))
        .collect::<Vec<_>>();

    let sf_addrs = prev
        .iter()
        .take(keep)
        .map(|c| c.0.sailfish_address().clone())
        .chain(
            repeat_with(|| {
                let p = portpicker::pick_unused_port().unwrap();
                Address::from((Ipv4Addr::LOCALHOST, p))
            })
            .take(add.get()),
        )
        .collect::<Vec<_>>();

    let de_addrs = prev
        .iter()
        .take(keep)
        .map(|c| c.0.decrypt_address().clone())
        .chain(
            repeat_with(|| {
                let p = portpicker::pick_unused_port().unwrap();
                Address::from((Ipv4Addr::LOCALHOST, p))
            })
            .take(add.get()),
        )
        .collect::<Vec<_>>();

    let cert_addrs = prev
        .iter()
        .take(keep)
        .map(|c| c.1.address().clone())
        .chain(
            repeat_with(|| {
                let p = portpicker::pick_unused_port().unwrap();
                Address::from((Ipv4Addr::LOCALHOST, p))
            })
            .take(add.get()),
        )
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

    let dkg_keys = (0..sign_keys.len())
        .map(|_| DkgDecKey::generate())
        .collect::<Vec<_>>();

    let key_store = KeyStore::new(
        committee.clone(),
        dkg_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (i as u8, sk.into())),
    );

    let mut cfgs = Vec::new();
    let mut enc_keys = Vec::new();

    for (i, kpair) in sign_keys.into_iter().enumerate() {
        let xpair = &dh_keys[i];
        let dkg_sk = &dkg_keys[i];
        let sa = &sf_addrs[i];
        let da = &de_addrs[i];
        let pa = &cert_addrs[i];
        let enc_key = DecryptionKeyCell::new();
        let conf = SequencerConfig::builder()
            .sign_keypair(kpair.clone())
            .dh_keypair(xpair.clone())
            .dkg_key(dkg_sk.clone())
            .sailfish_addr(sa.clone())
            .decrypt_addr(da.clone())
            .sailfish_committee(sf_committee.clone())
            .decrypt_committee((de_committee.clone(), key_store.clone()))
            .maybe_previous_sailfish_committee(
                set_prev.then(|| prev[0].0.sailfish_committee().clone()),
            )
            .maybe_previous_decrypt_committee(
                set_prev.then(|| prev[0].0.decrypt_committee().clone()),
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
        enc_keys.push(enc_key);
        cfgs.push((conf, pcf));
    }

    (enc_keys, cfgs)
}

/// Run a handover test between a current and a next set of nodes.
async fn run_handover(
    curr: (
        Vec<DecryptionKeyCell>,
        Vec<(SequencerConfig, CertifierConfig)>,
    ),
    next: (
        Vec<DecryptionKeyCell>,
        Vec<(SequencerConfig, CertifierConfig)>,
    ),
) {
    const NEXT_COMMITTEE_DELAY: u64 = 15;
    const NUM_OF_BLOCKS: usize = 50;

    let num = NonZeroUsize::new(5).unwrap();
    let quorum = 4;

    let mut out1 = Vec::new();
    let tasks = TaskTracker::new();
    let (bcast, _) = broadcast::channel(100);
    let finish = CancellationToken::new();
    let round2block = Arc::new(Round2Block::new());

    let a1 = curr.1[0].0.sailfish_committee().clone();
    let a2 = next.1[0].0.sailfish_committee().clone();
    let c1 = a1.committee().id();
    let c2 = a2.committee().id();
    let d2 = next.1[0].0.decrypt_committee().clone();

    assert_ne!(c1, c2);

    // Run committee 1:
    for (seq_conf, cert_conf) in &curr.1 {
        // Clone the configs so they are owned and can be moved into the async block
        let seq_conf = seq_conf.clone();
        let cert_conf = cert_conf.clone();
        let (tx, rx) = mpsc::unbounded_channel();
        let finish = finish.clone();
        let mut cmd = bcast.subscribe();
        let label = seq_conf.sign_keypair().public_key();
        let r2b = round2block.clone();

        tasks.spawn(async move {
            let mut s = Sequencer::new(seq_conf, &NoMetrics).await.unwrap();
            let mut c = Certifier::new(cert_conf, &NoMetrics).await.unwrap();
            let mut r: Option<sailfish_types::RoundNumber> = None;
            let handle = c.handle();

            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(Cmd::NextCommittee(t, a, k)) => {
                            s.set_next_committee(t, a, k).await.unwrap();
                        }
                        Ok(Cmd::Bundle(bundle)) => {
                            s.add_bundles(once(bundle));
                        }
                        Err(err) => panic!("Command channel error: {err}")
                    },
                    out = s.next() => {
                        let Output::Transactions { round, transactions, .. } = out.unwrap() else {
                            error!(node = %s.public_key(), "no sequencer output");
                            continue
                        };
                        // We require unique round numbers.
                        if Some(round) == r {
                            continue
                        }
                        r = Some(round);
                        let i = r2b.get(round);
                        let b = Block::new(i, *round, hash(&transactions));
                        handle.enqueue(b).await.unwrap()
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

    // Start transaction generation
    // Wait for all decryption keys in curr_enc_keys to be ready
    for key in &curr.0 {
        key.read().await;
    }

    tasks.spawn({
        let key = curr.0[0].clone();
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

    // Inform about upcoming committee change:
    let t = ConsensusTime(Timestamp::now() + NEXT_COMMITTEE_DELAY);
    bcast.send(Cmd::NextCommittee(t, a2, d2.1)).unwrap();

    let mut out2 = Vec::new();

    // Run committee 2:
    for (seq_conf, cert_conf) in &next.1 {
        let ours = seq_conf.sign_keypair().public_key();

        if curr
            .1
            .iter()
            .any(|(s, _)| s.sign_keypair().public_key() == ours)
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
            let mut s = Sequencer::new(seq_conf, &NoMetrics).await.unwrap();
            let mut c = Certifier::new(cert_conf, &NoMetrics).await.unwrap();
            let mut r: Option<sailfish_types::RoundNumber> = None;
            let handle = c.handle();

            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(Cmd::NextCommittee(t, a, k)) => {
                            s.set_next_committee(t, a, k).await.unwrap();
                        }
                        Ok(Cmd::Bundle(bundle)) => {
                            s.add_bundles(once(bundle));
                        }
                        Err(err) => panic!("Command channel error: {err}")
                    },
                    out = s.next() => {
                        let Output::Transactions { round, transactions, .. } = out.unwrap() else {
                            error!(node = %s.public_key(), "no sequencer output");
                            continue
                        };
                        if Some(round) == r {
                            continue
                        }
                        r = Some(round);
                        let i = r2b.get(round);
                        let b = Block::new(i, *round, hash(&transactions));
                        handle.enqueue(b).await.unwrap()
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

    for b in 0..NUM_OF_BLOCKS {
        map.clear();
        info!(block = %b);
        for (node, r) in &mut out1 {
            debug!(%node, block = %b, "awaiting ...");
            let info = r.recv().await.unwrap();
            *map.entry(info).or_default() += 1
        }
        if map.values().any(|n| *n >= quorum && *n <= num.get()) {
            continue;
        }
        for (info, n) in map {
            eprintln!("{}: {} = {n}", info.hash(), info.round().num())
        }
        panic!("outputs do not match")
    }

    for b in 0..NUM_OF_BLOCKS {
        map.clear();
        info!(block = %b);
        for (node, r) in &mut out2 {
            debug!(%node, block = %b, "awaiting ...");
            let info = r.recv().await.unwrap();
            *map.entry(info).or_default() += 1
        }
        if map.values().any(|n| *n >= quorum && *n <= num.get()) {
            continue;
        }
        for (info, n) in map {
            eprintln!("{}: {} = {n}", info.hash(), info.round().num())
        }
        panic!("outputs do not match")
    }

    finish.cancel();
}

#[tokio::test]
async fn handover_0_to_5() {
    init_logging();

    let c1 = mk_configs(0.into(), &[], 0, NonZeroUsize::new(5).unwrap(), false);

    let c2 = mk_configs(
        1.into(),
        c1.1.as_slice(),
        0,
        NonZeroUsize::new(5).unwrap(),
        true,
    );
    run_handover(c1, c2).await;
}

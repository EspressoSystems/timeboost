use std::future::pending;
use std::iter::repeat_with;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use cliquenet::{Address, AddressableCommittee, Network, NetworkMetrics, Overlay};
use futures::FutureExt;
use futures::stream::{self, StreamExt};
use metrics::NoMetrics;
use multisig::{Committee, CommitteeId, Keypair, x25519};
use sailfish::consensus::Consensus;
use sailfish::rbc::Rbc;
use sailfish::types::{ConsensusTime, RoundNumber, Timestamp};
use sailfish::{Coordinator, Event};
use timeboost_crypto::prelude::{DkgDecKey, ThresholdEncKeyCell};
use timeboost_sequencer::SequencerConfig;
use timeboost_types::{ChainConfig, DkgKeyStore};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio::time::sleep;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::info;
use url::Url;

#[derive(Debug, Clone)]
enum Cmd {
    NextCommittee(ConsensusTime, AddressableCommittee),
}

/// Create sequencer configs.
///
/// A (possible empty) slice of previous configs can be given, of which some
/// subset can be kept. A given number of additional configs are created.
/// Finally, the `set_prev` flag indicates if the previous committee should be
/// set on the configs.
///
/// NB that the decryption parts are currently not used.
fn mk_configs<C>(
    id: C,
    prev: &[SequencerConfig],
    keep: usize,
    add: NonZeroUsize,
    set_prev: bool,
) -> impl Iterator<Item = SequencerConfig>
where
    C: Into<CommitteeId>,
{
    let sign_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.sign_keypair().clone())
        .chain(repeat_with(Keypair::generate).take(add.get()))
        .collect::<Vec<_>>();

    let dh_keys = prev
        .iter()
        .take(keep)
        .map(|c| c.dh_keypair().clone())
        .chain(repeat_with(|| x25519::Keypair::generate().unwrap()).take(add.get()))
        .collect::<Vec<_>>();

    let sf_addrs = prev
        .iter()
        .take(keep)
        .map(|c| c.sailfish_address().clone())
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
        .map(|c| c.decrypt_address().clone())
        .chain(
            repeat_with(|| {
                let p = portpicker::pick_unused_port().unwrap();
                Address::from((Ipv4Addr::LOCALHOST, p))
            })
            .take(add.get()),
        )
        .collect::<Vec<_>>();

    let committee = Committee::new(
        id.into(),
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

    let dkg_keys = (0..sign_keys.len())
        .map(|_| DkgDecKey::generate())
        .collect::<Vec<_>>();

    let dkg_keystore = DkgKeyStore::new(
        committee.clone(),
        dkg_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (i as u8, sk.into())),
    );

    let enc_key = ThresholdEncKeyCell::new();

    sign_keys
        .into_iter()
        .zip(dh_keys)
        .zip(sf_addrs)
        .zip(de_addrs)
        .zip(dkg_keys)
        .map(move |((((k, x), sa), da), dkg_key)| {
            SequencerConfig::builder()
                .sign_keypair(k)
                .dh_keypair(x)
                .dkg_key(dkg_key)
                .dkg_keystore(dkg_keystore.clone())
                .sailfish_addr(sa)
                .decrypt_addr(da)
                .sailfish_committee(sf_committee.clone())
                .decrypt_committee(de_committee.clone())
                .maybe_previous_sailfish_committee(
                    set_prev.then(|| prev[0].sailfish_committee().clone()),
                )
                .recover(false)
                .leash_len(100)
                .threshold_enc_key(enc_key.clone())
                .chain_config(ChainConfig::new(
                    1,
                    "https://theserversroom.com/ethereum/54cmzzhcj1o/"
                        .parse::<Url>()
                        .expect("valid url"),
                    "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f"
                        .parse::<alloy::primitives::Address>()
                        .expect("valid contract"),
                    BlockNumberOrTag::Finalized,
                ))
                .build()
        })
}

/// Create a Sailfish node with the given config.
///
/// NB that the decryption parts of the config are not used yet.
async fn mk_node(cfg: &SequencerConfig) -> Coordinator<Timestamp, Rbc<Timestamp>> {
    let met = NetworkMetrics::new(
        "sailfish",
        &NoMetrics,
        cfg.sailfish_committee().parties().copied(),
    );

    let mut net = Network::create(
        "sailfish",
        cfg.sailfish_address().clone(),
        cfg.sign_keypair().public_key(),
        cfg.dh_keypair().clone(),
        cfg.sailfish_committee().entries(),
        met,
    )
    .await
    .unwrap();

    if let Some(prev) = &cfg.previous_sailfish_committee() {
        let old = prev.diff(cfg.sailfish_committee());
        net.add(old.collect()).await.unwrap()
    }

    let rbc = Rbc::new(
        5 * cfg.sailfish_committee().committee().size().get(),
        Overlay::new(net),
        cfg.rbc_config(),
    );

    let mut cons = Consensus::new(
        cfg.sign_keypair().clone(),
        cfg.sailfish_committee().committee().clone(),
        repeat_with(Timestamp::now),
    );

    if let Some(prev) = &cfg.previous_sailfish_committee() {
        cons.set_handover_committee(prev.committee().clone())
    }

    Coordinator::new(rbc, cons, cfg.previous_sailfish_committee().is_some())
}

/// Run a handover test between a current and a next set of nodes.
async fn run_handover(curr: &[SequencerConfig], next: &[SequencerConfig]) {
    const NEXT_COMMITTEE_DELAY: u64 = 5;

    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);

    let a1 = curr[0].sailfish_committee().clone();
    let a2 = next[0].sailfish_committee().clone();
    let c1 = a1.committee().id();
    let c2 = a2.committee().id();

    assert_ne!(c1, c2);

    let mut nodes = Vec::new();
    for cfg in curr {
        nodes.push((cfg.clone(), mk_node(cfg).await))
    }

    let mut outputs = Vec::new();

    // Run committee 1:
    for (cfg, mut n) in nodes {
        let mut cmd = bcast.subscribe();
        let (tx, rx) = mpsc::unbounded_channel();
        tasks.spawn(async move {
            for a in n.init() {
                n.execute(a).await.unwrap();
            }
            let mut delayed_cmd = pending().boxed();
            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(cmd) => {
                            let d = Duration::from_secs(rand::random_range(0 .. NEXT_COMMITTEE_DELAY));
                            delayed_cmd = (async move { sleep(d).await; cmd }).fuse().boxed()
                        }
                        Err(err) => panic!("{err}")
                    },
                    cmd = &mut delayed_cmd => match cmd {
                        Cmd::NextCommittee(t, a) => {
                            n.set_next_committee(t, a.committee().clone(), a.clone()).await.unwrap();
                            if a.committee().contains_key(&n.public_key()) {
                                let d = repeat_with(Timestamp::now);
                                let k = cfg.sign_keypair().clone();
                                let c = Consensus::new(k, a.committee().clone(), d);
                                assert!(n.set_next_consensus(c).is_empty())
                            }
                        }
                    },
                    act = n.next() => {
                        for a in act.unwrap() {
                            if let Some(Event::Deliver(p)) = n.execute(a).await.unwrap() {
                                tx.send((p.round(), p.source(), p.into_data())).unwrap()
                            }
                        }
                    }
                }
            }
        });
        outputs.push(UnboundedReceiverStream::new(rx))
    }

    // Inform about upcoming committee change:
    let t = ConsensusTime(Timestamp::now() + NEXT_COMMITTEE_DELAY);
    bcast.send(Cmd::NextCommittee(t, a2)).unwrap();

    let d = Duration::from_secs(rand::random_range(0..NEXT_COMMITTEE_DELAY));
    sleep(d).await;

    let mut add_nodes = Vec::new();
    for cfg in next {
        let ours = cfg.sign_keypair().public_key();
        if curr.iter().any(|c| c.sign_keypair().public_key() == ours) {
            continue;
        }
        add_nodes.push(mk_node(cfg).await)
    }

    // Run committee 2:
    for mut n in add_nodes {
        let mut cmd = bcast.subscribe();
        let (tx, rx) = mpsc::unbounded_channel();
        tasks.spawn(async move {
            for a in n.init() {
                n.execute(a).await.unwrap();
            }
            loop {
                select! {
                    _ = cmd.recv() => unreachable!(),
                    x = n.next() => {
                        for a in x.unwrap() {
                            if let Some(Event::Deliver(p)) = n.execute(a).await.unwrap() {
                                tx.send((p.round(), p.source(), p.into_data())).unwrap()
                            }
                        }
                    }
                }
            }
        });
        outputs.push(UnboundedReceiverStream::new(rx))
    }

    let mut outputs = stream::select_all(outputs);
    let mut c1_round = RoundNumber::genesis();
    let mut c2_round = RoundNumber::genesis();

    while let Some((r, s, _)) = outputs.next().await {
        info!(%r, %s);
        if r.committee() == c1 {
            assert!(c2_round.is_genesis());
            c1_round = r.num();
        }
        if r.committee() == c2 {
            c2_round = r.num()
        }
        if c2_round > 100.into() {
            assert!(!c1_round.is_genesis());
            break;
        }
    }
}

#[tokio::test]
async fn handover_0_to_5() {
    init_logging();

    let c1 = mk_configs(0, &[], 0, NonZeroUsize::new(5).unwrap(), false).collect::<Vec<_>>();
    let c2 = mk_configs(1, &c1, 0, NonZeroUsize::new(5).unwrap(), true).collect::<Vec<_>>();
    run_handover(&c1, &c2).await;
}

#[tokio::test]
async fn handover_1_to_4() {
    init_logging();

    let c1 = mk_configs(0, &[], 0, NonZeroUsize::new(5).unwrap(), false).collect::<Vec<_>>();
    let c2 = mk_configs(1, &c1, 1, NonZeroUsize::new(4).unwrap(), true).collect::<Vec<_>>();
    run_handover(&c1, &c2).await;
}

#[tokio::test]
async fn handover_2_to_3() {
    init_logging();

    let c1 = mk_configs(0, &[], 0, NonZeroUsize::new(5).unwrap(), false).collect::<Vec<_>>();
    let c2 = mk_configs(1, &c1, 2, NonZeroUsize::new(3).unwrap(), true).collect::<Vec<_>>();
    run_handover(&c1, &c2).await;
}

#[tokio::test]
async fn handover_3_to_2() {
    init_logging();

    let c1 = mk_configs(0, &[], 0, NonZeroUsize::new(5).unwrap(), false).collect::<Vec<_>>();
    let c2 = mk_configs(1, &c1, 3, NonZeroUsize::new(2).unwrap(), true).collect::<Vec<_>>();
    run_handover(&c1, &c2).await;
}

#[tokio::test]
async fn handover_4_to_1() {
    init_logging();

    let c1 = mk_configs(0, &[], 0, NonZeroUsize::new(5).unwrap(), false).collect::<Vec<_>>();
    let c2 = mk_configs(1, &c1, 4, NonZeroUsize::new(1).unwrap(), true).collect::<Vec<_>>();
    run_handover(&c1, &c2).await;
}

#[tokio::test]
async fn handover_3_to_5() {
    init_logging();

    let c1 = mk_configs(0, &[], 0, NonZeroUsize::new(5).unwrap(), false).collect::<Vec<_>>();
    let c2 = mk_configs(1, &c1, 3, NonZeroUsize::new(5).unwrap(), true).collect::<Vec<_>>();
    run_handover(&c1, &c2).await;
}

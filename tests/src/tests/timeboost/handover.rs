use std::iter::repeat_with;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;

use cliquenet::{Address, AddressableCommittee, Network, NetworkMetrics, Overlay};
use futures::stream::{self, StreamExt};
use metrics::NoMetrics;
use multisig::{Committee, CommitteeId, Keypair, x25519};
use sailfish::consensus::Consensus;
use sailfish::rbc::{Rbc, RbcConfig};
use sailfish::types::{CommitteeVec, ConsensusTime, RoundNumber, Timestamp};
use sailfish::{Coordinator, Event};
use timeboost_utils::types::logging::init_logging;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tokio_stream::wrappers::UnboundedReceiverStream;

#[derive(Debug, Clone)]
enum Cmd {
    NextCommittee(ConsensusTime, AddressableCommittee),
}

async fn mk_nodes<C>(
    c: C,
    n: usize,
    join: bool,
    prev: Option<AddressableCommittee>,
) -> (
    AddressableCommittee,
    Vec<Coordinator<Timestamp, Rbc<Timestamp>>>,
)
where
    C: Into<CommitteeId>,
{
    // Sign keypairs:
    let kpairs = (0..n).map(|_| Keypair::generate()).collect::<Vec<_>>();

    // DH keypairs:
    let xpairs = (0..n)
        .map(|_| x25519::Keypair::generate().unwrap())
        .collect::<Vec<_>>();

    // Addresses:
    let addresses = (0..n)
        .map(|_| Address::from((Ipv4Addr::LOCALHOST, portpicker::pick_unused_port().unwrap())))
        .collect::<Vec<_>>();

    // The committee:
    let committee = Committee::new(
        c,
        kpairs
            .iter()
            .enumerate()
            .map(|(i, kp)| (i as u8, kp.public_key())),
    );

    let addressable = AddressableCommittee::new(
        committee.clone(),
        kpairs
            .iter()
            .zip(&xpairs)
            .zip(&addresses)
            .map(|((k, x), a)| (k.public_key(), x.public_key(), a.clone())),
    );

    let mut vec = CommitteeVec::new();

    let old = if let Some(prev) = &prev {
        vec.add(prev.committee().clone());
        prev.difference(&addressable).collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    vec.add(committee.clone());

    let mut result = Vec::new();
    for ((a, k), x) in addresses.iter().zip(&kpairs).zip(&xpairs) {
        let group = kpairs
            .iter()
            .zip(&xpairs)
            .zip(&addresses)
            .map(|((k, x), a)| (k.public_key(), x.public_key(), a.clone()));
        let met = NetworkMetrics::new("sf", &NoMetrics, kpairs.iter().map(|k| k.public_key()));
        let mut net = Network::create("sf", a.clone(), k.clone(), x.clone(), group, met)
            .await
            .unwrap();
        net.add(old.clone()).await.unwrap();
        let mut cons = Consensus::new(k.clone(), committee.clone(), repeat_with(Timestamp::now));
        if let Some(prev) = &prev {
            cons.set_handover_committee(prev.committee().clone())
        };
        let cfg = RbcConfig::new(k.clone(), committee.id(), vec.clone()).recover(false);
        let rbc = Rbc::new(3 * n, Overlay::new(net), cfg);
        let coord = Coordinator::new(rbc, cons, join);
        result.push(coord)
    }

    (addressable, result)
}

#[tokio::test]
async fn handover() {
    init_logging();

    let num = NonZeroUsize::new(5).unwrap();

    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);

    let committee1 = CommitteeId::new(1);
    let (a1, nodes) = mk_nodes(committee1, num.get(), false, None).await;

    let mut outputs = Vec::new();

    // Run committee 1:
    for mut n in nodes {
        let mut cmd = bcast.subscribe();
        let (tx, rx) = mpsc::unbounded_channel();
        tasks.spawn(async move {
            for a in n.init() {
                n.execute(a).await.unwrap();
            }
            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(Cmd::NextCommittee(t, a)) => {
                            n.set_next_committee(t, a.committee().clone(), a).await.unwrap()
                        }
                        Err(err) => panic!("{err}")
                    },
                    act = n.next() => {
                        for a in act.unwrap() {
                            if let Some(Event::Deliver(p)) = n.execute(a).await.unwrap() {
                                tx.send((committee1, p.round(), p.source(), p.into_data())).unwrap()
                            }
                        }
                    }
                }
            }
        });
        outputs.push(UnboundedReceiverStream::new(rx))
    }

    let committee2 = CommitteeId::new(2);
    let (a2, nodes) = mk_nodes(committee2, num.get(), true, Some(a1)).await;

    // Inform about upcoming committee change:
    let t = ConsensusTime(Timestamp::now() + 5);
    bcast.send(Cmd::NextCommittee(t, a2)).unwrap();

    // Run committee 2:
    for mut n in nodes {
        let mut cmd = bcast.subscribe();
        let (tx, rx) = mpsc::unbounded_channel();
        tasks.spawn(async move {
            for a in n.init() {
                n.execute(a).await.unwrap();
            }
            loop {
                select! {
                    cmd = cmd.recv() => match cmd {
                        Ok(Cmd::NextCommittee(t, a)) => {
                            n.set_next_committee(t, a.committee().clone(), a).await.unwrap()
                        }
                        Err(err) => panic!("{err}")
                    },
                    act = n.next() => {
                        for a in act.unwrap() {
                            if let Some(Event::Deliver(p)) = n.execute(a).await.unwrap() {
                                tx.send((committee2, p.round(), p.source(), p.into_data())).unwrap()
                            }
                        }
                    }
                }
            }
        });
        outputs.push(UnboundedReceiverStream::new(rx))
    }

    let mut outputs = stream::select_all(outputs);
    let mut committee_1_round = RoundNumber::genesis();
    let mut committee_2_round = RoundNumber::genesis();

    while let Some((c, r, ..)) = outputs.next().await {
        if c == committee1 {
            assert!(committee_2_round.is_genesis());
            committee_1_round = r;
        }
        if c == committee2 {
            committee_2_round = r
        }
        if committee_2_round > 100.into() {
            assert!(!committee_1_round.is_genesis());
            break;
        }
    }
}

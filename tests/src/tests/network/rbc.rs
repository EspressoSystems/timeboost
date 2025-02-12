use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use multisig::{Committee, Keypair, PublicKey};
use sailfish::consensus::Consensus;
use sailfish::coordinator::Coordinator;
use sailfish::rbc::{self, Rbc};
use timeboost_core::types::event::SailfishEventType;
use timeboost_core::types::NodeId;
use timeboost_networking::{Network, NetworkMetrics};
use timeboost_utils::types::logging::init_logging;
use tokio::time::timeout;

type Peers<const N: usize> = [(PublicKey, SocketAddr); N];

fn fresh_keys(n: usize) -> (Vec<Keypair>, Committee) {
    let ks: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
    let co = Committee::new(
        ks.iter()
            .enumerate()
            .map(|(i, kp)| (i as u8, kp.public_key())),
    );
    (ks, co)
}

fn ports(n: usize) -> Vec<u16> {
    (0..n)
        .map(|_| portpicker::pick_unused_port().expect("open port"))
        .collect()
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::from([a, b, c, d])
}

/// Adds a sailfish host to the simulation.
///
/// The host consists of `Coordinator` and `Consensus` with
/// `Rbc<TurmoilComm>` as its network communication layer.
fn mk_host<T, const N: usize>(
    id: T,
    addr: SocketAddr,
    sim: &mut turmoil::Sim,
    k: Keypair,
    c: Committee,
    peers: Peers<N>,
) where
    T: Into<NodeId>,
{
    let id = id.into();
    sim.host(addr.ip(), move || {
        let k = k.clone();
        let c = c.clone();
        async move {
            let comm = Network::create_turmoil(
                (Ipv4Addr::UNSPECIFIED, addr.port()).into(),
                k.clone(),
                peers,
                NetworkMetrics::default(),
            )
            .await?;
            let rbc = Rbc::new(comm, rbc::Config::new(k.clone(), c.clone()));
            let cons = Consensus::new(id, k, c);
            let mut coor = Coordinator::new(id, rbc, cons);
            let mut actions = coor.start().await?;
            loop {
                for a in actions {
                    coor.execute(a).await?;
                }
                actions = coor.next().await?
            }
        }
    });
}

#[test]
#[rustfmt::skip]
fn small_committee() {
    init_logging();

    let mut sim = turmoil::Builder::new()
        .enable_random_order()
        .fail_rate(0.05)
        .simulation_duration(Duration::from_secs(500))
        .build();

    let n = 3;
    let (ks, committee) = fresh_keys(n);
    let ports = ports(n);

    let peers = [
        (ks[0].public_key(), ([192,168,0,1], ports[0]).into()),
        (ks[1].public_key(), ([192,168,0,2], ports[1]).into()),
        (ks[2].public_key(), ([192,168,0,3], ports[2]).into()),
    ];

    mk_host(1, ([192,168,0,1], ports[0]).into(), &mut sim, ks[0].clone(), committee.clone(), peers);
    mk_host(2, ([192,168,0,2], ports[1]).into(), &mut sim, ks[1].clone(), committee.clone(), peers);

    let k = ks[2].clone();
    let c = committee.clone();

    sim.client(ip4(192,168,0,3), async move {
        let addr = (Ipv4Addr::UNSPECIFIED, ports[2]).into();
        let comm = Network::create_turmoil(addr, k.clone(), peers, NetworkMetrics::default()).await?;
        let rbc = Rbc::new(comm, rbc::Config::new(k.clone(), c.clone()));
        let cons = Consensus::new(3, k, c);
        let mut coor = Coordinator::new(3, rbc, cons);
        let mut actions = coor.start().await?;
        loop {
            for a in actions {
                if let Some(event) = coor.execute(a).await? {
                    if let SailfishEventType::Committed { round, .. } = event.event {
                        if round >= 3.into() {
                            return Ok(());
                        }
                    }
                }
            }
            actions = coor.next().await?
        }
    });

    sim.run().unwrap()
}

#[test]
#[rustfmt::skip]
fn medium_committee() {
    init_logging();

    let mut sim = turmoil::Builder::new()
        .enable_random_order()
        .fail_rate(0.01)
        .simulation_duration(Duration::from_secs(500))
        .build();

    let n = 5;
    let (ks, committee) = fresh_keys(n);
    let ports = ports(n);

    let peers = [
        (ks[0].public_key(), ([192,168,0,1], ports[0]).into()),
        (ks[1].public_key(), ([192,168,0,2], ports[1]).into()),
        (ks[2].public_key(), ([192,168,0,3], ports[2]).into()),
        (ks[3].public_key(), ([192,168,0,4], ports[3]).into()),
        (ks[4].public_key(), ([192,168,0,5], ports[4]).into()),
    ];

    mk_host(1, ([192,168,0,1], ports[0]).into(), &mut sim, ks[0].clone(), committee.clone(), peers);
    mk_host(2, ([192,168,0,2], ports[1]).into(), &mut sim, ks[1].clone(), committee.clone(), peers);
    mk_host(3, ([192,168,0,3], ports[2]).into(), &mut sim, ks[2].clone(), committee.clone(), peers);
    mk_host(4, ([192,168,0,4], ports[3]).into(), &mut sim, ks[3].clone(), committee.clone(), peers);

    let k = ks[4].clone();
    let c = committee.clone();

    sim.client(ip4(192,168,0,5), async move {
        let addr = (Ipv4Addr::UNSPECIFIED, ports[4]).into();
        let comm = Network::create_turmoil(addr, k.clone(), peers, NetworkMetrics::default()).await?;
        let rbc = Rbc::new(comm, rbc::Config::new(k.clone(), c.clone()));
        let cons = Consensus::new(5, k, c);
        let mut coor = Coordinator::new(5, rbc, cons);
        let mut actions = coor.start().await?;
        loop {
            for a in actions {
                if let Some(event) = coor.execute(a).await? {
                    if let SailfishEventType::Committed { round, .. } = event.event {
                        if round >= 3.into() {
                            return Ok(());
                        }
                    }
                }
            }
            actions = coor.next().await?
        }
    });

    sim.run().unwrap()
}

#[test]
#[ignore]
#[rustfmt::skip]
fn medium_committee_partition_network() {
    init_logging();

    let mut sim = turmoil::Builder::new()
        .enable_random_order()
        .simulation_duration(Duration::from_secs(500))
        .build();

    let n = 5;
    let (ks, committee) = fresh_keys(n);
    let ports = ports(n);

    let peers = [
        (ks[0].public_key(), ([192,168,0,1], ports[0]).into()),
        (ks[1].public_key(), ([192,168,0,2], ports[1]).into()),
        (ks[2].public_key(), ([192,168,0,3], ports[2]).into()),
        (ks[3].public_key(), ([192,168,0,4], ports[3]).into()),
        (ks[4].public_key(), ([192,168,0,5], ports[4]).into()),
    ];

    mk_host(1, ([192,168,0,1], ports[0]).into(), &mut sim, ks[0].clone(), committee.clone(), peers);
    mk_host(2, ([192,168,0,2], ports[1]).into(), &mut sim, ks[1].clone(), committee.clone(), peers);
    mk_host(3, ([192,168,0,3], ports[2]).into(), &mut sim, ks[2].clone(), committee.clone(), peers);
    mk_host(4, ([192,168,0,4], ports[3]).into(), &mut sim, ks[3].clone(), committee.clone(), peers);

    let k = ks[4].clone();
    let c = committee.clone();

    sim.client(ip4(192,168,0,5), async move {
        let addr = (Ipv4Addr::UNSPECIFIED, ports[4]).into();
        let comm = Network::create_turmoil(addr, k.clone(), peers, NetworkMetrics::default()).await?;
        let rbc = Rbc::new(comm, rbc::Config::new(k.clone(), c.clone()));
        let cons = Consensus::new(5, k, c);
        let mut coor = Coordinator::new(5, rbc, cons);
        let mut actions = coor.start().await?;
        loop {

            for a in actions.clone() {
                if let Some(event) = coor.execute(a).await? {
                    if let SailfishEventType::Committed { round, .. } = event.event {
                        let r = *round;
                        if r == 3 {
                            turmoil::partition(ip4(192,168,0,5), ip4(192,168,0,1));
                            turmoil::partition(ip4(192,168,0,5), ip4(192,168,0,2));
                            turmoil::partition(ip4(192,168,0,5), ip4(192,168,0,3));
                            turmoil::partition(ip4(192,168,0,5), ip4(192,168,0,4));
                        }
                        if r >= 20 {
                            return Ok(());
                        }
                    }
                }
            }

            // For when we partition the network we wont receive messages from all nodes, so just timeout
            actions.clear();
            let result = timeout(Duration::from_secs(7), async {
                coor.next().await
            }).await;
            match result {
                Ok(r) => {
                    if let Ok(a) = r {
                        actions = a
                    }
                }
                Err(_) => {
                    // Once we have timed out bring back the network
                    turmoil::repair(ip4(192,168,0,5), ip4(192,168,0,1));
                    turmoil::repair(ip4(192,168,0,5), ip4(192,168,0,2));
                    turmoil::repair(ip4(192,168,0,5), ip4(192,168,0,3));
                    turmoil::repair(ip4(192,168,0,5), ip4(192,168,0,4));
                }
            }

        }
    });

    sim.run().unwrap()
}

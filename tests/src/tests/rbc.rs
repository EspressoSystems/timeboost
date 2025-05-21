use std::net::Ipv4Addr;
use std::time::Duration;

use cliquenet::{Address, Network, NetworkMetrics, Overlay};
use multisig::{Committee, CommitteeSeq, Keypair, PublicKey};
use sailfish::Coordinator;
use sailfish::rbc::{Rbc, RbcConfig};
use sailfish_types::RoundNumber;
use timeboost_utils::types::logging::init_logging;
use tokio::time::timeout;

use crate::prelude::*;

type Peers<const N: usize> = [(PublicKey, Address); N];

fn fresh_keys(n: usize) -> (Vec<Keypair>, CommitteeSeq<RoundNumber>) {
    let ks: Vec<Keypair> = (0..n).map(|_| Keypair::generate()).collect();
    let co = Committee::new(
        ks.iter()
            .enumerate()
            .map(|(i, kp)| (i as u8, kp.public_key())),
    );
    (ks, (RoundNumber::genesis().., co).into())
}

fn ports(n: usize) -> Vec<u16> {
    (0..n)
        .map(|_| portpicker::pick_unused_port().expect("open port"))
        .collect()
}

// Local abbreviation.
const UNSPECIFIED: Ipv4Addr = Ipv4Addr::UNSPECIFIED;

/// Adds a sailfish host to the simulation.
///
/// The host consists of `Coordinator` and `Consensus` with
/// `Rbc<TurmoilComm>` as its network communication layer.
fn mk_host<A, const N: usize>(
    name: &str,
    addr: A,
    sim: &mut turmoil::Sim,
    k: Keypair,
    c: CommitteeSeq<RoundNumber>,
    peers: Peers<N>,
) where
    A: Into<Address>,
{
    let addr = addr.into();
    sim.host(name, move || {
        let k = k.clone();
        let c = c.clone();
        let a = addr.clone();
        let p = peers.clone();
        async move {
            let comm =
                Network::create_turmoil("test", a, k.clone(), p, NetworkMetrics::default()).await?;
            let cfg = RbcConfig::new(k.clone(), c.clone()).recover(false);
            let rbc = Rbc::new(Overlay::new(comm), cfg);
            let cons = Consensus::new(k, c, EmptyBlocks);
            let mut coor = Coordinator::new(rbc, cons);
            loop {
                for a in coor.next().await? {
                    coor.execute(a).await?;
                }
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
        .simulation_duration(Duration::from_secs(5000))
        .tcp_capacity(256)
        .build();

    let n = 3;
    let (ks, committee) = fresh_keys(n);
    let ports = ports(n);

    let peers = [
        (ks[0].public_key(), ("A", ports[0]).into()),
        (ks[1].public_key(), ("B", ports[1]).into()),
        (ks[2].public_key(), ("C", ports[2]).into()),
    ];

    mk_host("A", (UNSPECIFIED, ports[0]), &mut sim, ks[0].clone(), committee.clone(), peers.clone());
    mk_host("B", (UNSPECIFIED, ports[1]), &mut sim, ks[1].clone(), committee.clone(), peers.clone());

    let k = ks[2].clone();
    let c = committee.clone();

    sim.client("C", async move {
        let addr = (UNSPECIFIED, ports[2]);
        let comm = Network::create_turmoil("C", addr, k.clone(), peers, NetworkMetrics::default()).await?;
        let cfg = RbcConfig::new(k.clone(), c.clone()).recover(false);
        let rbc = Rbc::new(Overlay::new(comm), cfg);
        let cons = Consensus::new(k, c, EmptyBlocks);
        let mut coor = Coordinator::new(rbc, cons);
        loop {
            for a in coor.next().await? {
                if let Action::Deliver(data) = a {
                    if data.round() >= 3.into() {
                        return Ok(());
                    }
                } else {
                    coor.execute(a).await?
                }
            }
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
        .tcp_capacity(256)
        .build();

    let n = 5;
    let (ks, committee) = fresh_keys(n);
    let ports = ports(n);

    let peers = [
        (ks[0].public_key(), ("A", ports[0]).into()),
        (ks[1].public_key(), ("B", ports[1]).into()),
        (ks[2].public_key(), ("C", ports[2]).into()),
        (ks[3].public_key(), ("D", ports[3]).into()),
        (ks[4].public_key(), ("E", ports[4]).into()),
    ];

    mk_host("A", (UNSPECIFIED, ports[0]), &mut sim, ks[0].clone(), committee.clone(), peers.clone());
    mk_host("B", (UNSPECIFIED, ports[1]), &mut sim, ks[1].clone(), committee.clone(), peers.clone());
    mk_host("C", (UNSPECIFIED, ports[2]), &mut sim, ks[2].clone(), committee.clone(), peers.clone());
    mk_host("D", (UNSPECIFIED, ports[3]), &mut sim, ks[3].clone(), committee.clone(), peers.clone());

    let k = ks[4].clone();
    let c = committee.clone();

    sim.client("E", async move {
        let addr = (UNSPECIFIED, ports[4]);
        let comm = Network::create_turmoil("E", addr, k.clone(), peers, NetworkMetrics::default()).await?;
        let cfg = RbcConfig::new(k.clone(), c.clone()).recover(false);
        let rbc = Rbc::new(Overlay::new(comm), cfg);
        let cons = Consensus::new(k, c, EmptyBlocks);
        let mut coor = Coordinator::new(rbc, cons);
        loop {
            for a in coor.next().await? {
                if let Action::Deliver(data) = a {
                    if data.round() >= 3.into() {
                        return Ok(());
                    }
                } else {
                    coor.execute(a).await?
                }
            }
        }
    });

    sim.run().unwrap()
}

#[test]
#[rustfmt::skip]
fn medium_committee_partition_network() {
    init_logging();

    let mut sim = turmoil::Builder::new()
        .enable_random_order()
        .simulation_duration(Duration::from_secs(500))
        .tcp_capacity(256)
        .build();

    let n = 5;
    let (ks, committee) = fresh_keys(n);
    let ports = ports(n);

    let peers = [
        (ks[0].public_key(), ("A", ports[0]).into()),
        (ks[1].public_key(), ("B", ports[1]).into()),
        (ks[2].public_key(), ("C", ports[2]).into()),
        (ks[3].public_key(), ("D", ports[3]).into()),
        (ks[4].public_key(), ("E", ports[4]).into()),
    ];

    mk_host("A", (UNSPECIFIED, ports[0]), &mut sim, ks[0].clone(), committee.clone(), peers.clone());
    mk_host("B", (UNSPECIFIED, ports[1]), &mut sim, ks[1].clone(), committee.clone(), peers.clone());
    mk_host("C", (UNSPECIFIED, ports[2]), &mut sim, ks[2].clone(), committee.clone(), peers.clone());
    mk_host("D", (UNSPECIFIED, ports[3]), &mut sim, ks[3].clone(), committee.clone(), peers.clone());

    let k = ks[4].clone();
    let c = committee.clone();

    sim.client("E", async move {
        let addr = (UNSPECIFIED, ports[4]);
        let comm = Network::create_turmoil("E", addr, k.clone(), peers, NetworkMetrics::default()).await?;
        let cfg = RbcConfig::new(k.clone(), c.clone()).recover(false);
        let rbc = Rbc::new(Overlay::new(comm), cfg);
        let cons = Consensus::new(k, c, EmptyBlocks);
        let mut coor = Coordinator::new(rbc, cons);
        let mut actions = coor.next().await?;
        loop {

            for a in actions.clone() {
                if let Action::Deliver(data) = a {
                    if data.round() == 3.into() {
                        turmoil::partition("E", "A");
                        turmoil::partition("E", "B");
                        turmoil::partition("E", "C");
                        turmoil::partition("E", "D");
                    }
                    if data.round() >= 20.into() {
                        return Ok(());
                    }
                } else {
                    coor.execute(a).await?
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
                    turmoil::repair("E", "A");
                    turmoil::repair("E", "B");
                    turmoil::repair("E", "C");
                    turmoil::repair("E", "D");
                }
            }

        }
    });

    sim.run().unwrap()
}

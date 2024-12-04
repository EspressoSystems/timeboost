use std::time::Duration;

use sailfish::consensus::Consensus;
use sailfish::coordinator::Coordinator;
use sailfish::rbc::Rbc;
use timeboost_core::logging::init_logging;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::event::SailfishEventType;
use timeboost_core::types::Keypair;

use crate::rbc::TurmoilComm;

fn fresh_keys(n: u64) -> (Vec<Keypair>, StaticCommittee) {
    let ks: Vec<Keypair> = (0..n).map(Keypair::zero).collect();
    let co = StaticCommittee::new(ks.iter().map(|kp| *kp.public_key()).collect());
    (ks, co)
}

#[test]
fn smoke() {
    init_logging();

    let mut sim = turmoil::Builder::new()
        .min_message_latency(Duration::from_millis(10))
        .max_message_latency(Duration::from_secs(7))
        .enable_random_order()
        .fail_rate(0.5)
        .repair_rate(0.75)
        .simulation_duration(Duration::from_secs(500))
        .build();

    let (ks, committee) = fresh_keys(3);

    let peers = [
        (*ks[0].public_key(), ("A", 9000)),
        (*ks[1].public_key(), ("B", 9001)),
        (*ks[2].public_key(), ("C", 9002)),
    ];

    let key_a = ks[0].clone();
    let committee_a = committee.clone();

    sim.host("A", move || {
        let key_a = key_a.clone();
        let committee_a = committee_a.clone();
        async move {
            let comm = TurmoilComm::create("0.0.0.0:9000", peers).await?;
            let rbc = Rbc::new(comm, key_a.clone(), committee_a.clone());
            let cons = Consensus::new(1, key_a, committee_a);
            let mut coor = Coordinator::new(1, rbc, cons);
            let mut actions = coor.start().await?;
            loop {
                for a in actions {
                    coor.execute(a).await?;
                }
                actions = coor.next().await?
            }
        }
    });

    let key_b = ks[1].clone();
    let committee_b = committee.clone();

    sim.host("B", move || {
        let key_b = key_b.clone();
        let committee_b = committee_b.clone();
        async move {
            let comm = TurmoilComm::create("0.0.0.0:9001", peers).await?;
            let rbc = Rbc::new(comm, key_b.clone(), committee_b.clone());
            let cons = Consensus::new(2, key_b, committee_b);
            let mut coor = Coordinator::new(2, rbc, cons);
            let mut actions = coor.start().await?;
            loop {
                for a in actions {
                    coor.execute(a).await?;
                }
                actions = coor.next().await?
            }
        }
    });

    let key_c = ks[2].clone();
    let committee_c = committee.clone();

    sim.client("C", async move {
        let comm = TurmoilComm::create("0.0.0.0:9002", peers).await?;
        let rbc = Rbc::new(comm, key_c.clone(), committee_c.clone());
        let cons = Consensus::new(3, key_c, committee_c);
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

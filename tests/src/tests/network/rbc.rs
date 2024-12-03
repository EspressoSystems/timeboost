use sailfish::rbc::Rbc;
use timeboost_core::traits::comm::Comm;
use timeboost_core::types::committee::StaticCommittee;
use timeboost_core::types::Keypair;

use crate::rbc::TurmoilComm;

fn fresh_keys(n: u64) -> (Vec<Keypair>, StaticCommittee) {
    let ks: Vec<Keypair> = (0..n).map(Keypair::zero).collect();
    let co = StaticCommittee::new(ks.iter().map(|kp| *kp.public_key()).collect());
    (ks, co)
}

#[tokio::test]
async fn smoke() {
    let mut sim = turmoil::Builder::new().build();

    let (ks, committee) = fresh_keys(3);

    let peers = [
        (*ks[0].public_key(), ("A", 9000)),
        (*ks[1].public_key(), ("B", 9001)),
        (*ks[2].public_key(), ("C", 9002)),
    ];

    let peers = peers.clone();
    let key_a = ks[0].clone();
    let committee_a = committee.clone();

    sim.host("A", move || {
        let key_a = key_a.clone();
        let committee_a = committee_a.clone();
        async move {
            let comm = TurmoilComm::create("0.0.0.0:9000", peers).await?;
            let mut rbc = Rbc::new(comm, key_a, committee_a);
            while let Ok(msg) = rbc.receive().await {}
            Ok(())
        }
    });

    let peers = peers.clone();
    let key_b = ks[1].clone();
    let committee_b = committee.clone();

    sim.host("B", move || {
        let key_b = key_b.clone();
        let committee_b = committee_b.clone();
        async move {
            let comm = TurmoilComm::create("0.0.0.0:9001", peers).await?;
            let mut rbc = Rbc::new(comm, key_b, committee_b);
            while let Ok(msg) = rbc.receive().await {}
            Ok(())
        }
    });

    let peers = peers.clone();
    let key_c = ks[2].clone();
    let committee_c = committee.clone();

    sim.client("C", async move {
        let comm = TurmoilComm::create("0.0.0.0:9002", peers).await?;
        let mut rbc = Rbc::new(comm, key_c, committee_c);
        Ok(())
    });
}

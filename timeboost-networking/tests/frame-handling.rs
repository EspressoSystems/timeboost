use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;
use multisig::{Keypair, PublicKey};
use portpicker::pick_unused_port;
use rand::{Rng, RngCore};
use timeboost_networking::{metrics::NetworkMetrics, Network};
use tokio::time::{timeout, Duration};

/// Send and receive messages of various sizes between 1 byte and 5 MiB.
#[tokio::test]
async fn multiple_frames() {
    let party_a = Keypair::generate();
    let party_b = Keypair::generate();

    let all_parties: [(PublicKey, SocketAddr); 2] = [
        (
            party_a.public_key(),
            (Ipv4Addr::LOCALHOST, pick_unused_port().unwrap()).into(),
        ),
        (
            party_b.public_key(),
            (Ipv4Addr::LOCALHOST, pick_unused_port().unwrap()).into(),
        ),
    ];

    let mut net_a = Network::create(
        all_parties[0].1,
        party_a,
        all_parties,
        NetworkMetrics::default(),
    )
    .await
    .unwrap();
    let mut net_b = Network::create(
        all_parties[1].1,
        party_b,
        all_parties,
        NetworkMetrics::default(),
    )
    .await
    .unwrap();

    let sender = all_parties[0].0;

    for _ in 0..100 {
        send_recv(sender, &mut net_a, &mut net_b, gen_message()).await
    }
}

/// Generate a vector with random data and random length (within bounds).
fn gen_message() -> Bytes {
    let mut g = rand::rng();
    let mut v = vec![0; g.random_range(1..5 * 1024 * 1024)];
    g.fill_bytes(&mut v);
    v.into()
}

/// Multicast a message and receive them in both networks.
///
/// Since `Network` is essentially unreliable, this will retry multicasting
/// until the expected message has been received by both parties.
async fn send_recv(sender: PublicKey, net_a: &mut Network, net_b: &mut Network, data: Bytes) {
    'main: loop {
        net_a.multicast(data.clone()).await.unwrap();

        for net in [&mut *net_a, net_b] {
            if let Ok(Ok((k, x))) = timeout(Duration::from_millis(5), net.receive()).await {
                assert_eq!(k, sender);
                if x != data {
                    continue 'main;
                }
            } else {
                continue 'main;
            }
        }

        return;
    }
}

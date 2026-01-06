use std::net::{Ipv4Addr, SocketAddr};

use bytes::BytesMut;
use cliquenet::{NetConf, Network, Overlay, overlay::Data};
use multisig::{Keypair, PublicKey, x25519};
use rand::{Rng, RngCore};
use tokio::time::{Duration, timeout};

/// Send and receive messages of various sizes between 1 byte and 5 MiB.
#[tokio::test]
async fn multiple_frames() {
    let party_a_sign = Keypair::generate();
    let party_b_sign = Keypair::generate();

    let party_a_dh = x25519::Keypair::generate().unwrap();
    let party_b_dh = x25519::Keypair::generate().unwrap();

    let all_parties: [(PublicKey, x25519::PublicKey, SocketAddr); 2] = [
        (
            party_a_sign.public_key(),
            party_a_dh.public_key(),
            (Ipv4Addr::LOCALHOST, 50000).into(),
        ),
        (
            party_b_sign.public_key(),
            party_b_dh.public_key(),
            (Ipv4Addr::LOCALHOST, 51000).into(),
        ),
    ];

    let mut net_a = Overlay::new(
        Network::create(
            NetConf::builder()
                .name("frames")
                .label(party_a_sign.public_key())
                .keypair(party_a_dh)
                .bind(all_parties[0].2.into())
                .parties(all_parties.into_iter().map(|(k, x, s)| (k, x, s.into())))
                .build(),
        )
        .await
        .unwrap(),
    );
    let mut net_b = Overlay::new(
        Network::create(
            NetConf::builder()
                .name("frames")
                .label(party_b_sign.public_key())
                .keypair(party_b_dh)
                .bind(all_parties[1].2.into())
                .parties(all_parties.into_iter().map(|(k, x, s)| (k, x, s.into())))
                .build(),
        )
        .await
        .unwrap(),
    );

    let sender = all_parties[0].0;

    for _ in 0..100 {
        send_recv(sender, &mut net_a, &mut net_b, gen_message()).await
    }
}

/// Generate a vector with random data and random length (within bounds).
fn gen_message() -> Data {
    let mut g = rand::rng();
    let mut v = vec![0; g.random_range(1..5 * 1024 * 1024)];
    g.fill_bytes(&mut v);
    Data::try_from(BytesMut::from(&v[..])).unwrap()
}

/// Multicast a message and receive them in both networks.
///
/// Since `Network` is essentially unordered, this will retry multicasting
/// until the expected message has been received by both parties.
async fn send_recv(sender: PublicKey, net_a: &mut Overlay, net_b: &mut Overlay, data: Data) {
    'main: loop {
        net_a.broadcast(0, data.clone()).await.unwrap();

        for net in [&mut *net_a, net_b] {
            if let Ok(Ok((k, x))) = timeout(Duration::from_millis(5), net.receive()).await {
                assert_eq!(k, sender);
                if *x != *data {
                    continue 'main;
                }
            } else {
                continue 'main;
            }
        }

        return;
    }
}

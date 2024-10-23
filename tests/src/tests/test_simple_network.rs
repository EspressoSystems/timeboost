use sailfish::types::message::Message;
use tokio::task::JoinSet;
use tracing::debug;

use crate::net::Event;
use crate::{net, Group};

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn test_simple_network() {
    let num_nodes = 5;
    let nodes = Group::new(num_nodes);
    let mut net = net::Star::new();

    let mut coordinators = JoinSet::new();

    for n in nodes.fish {
        let ch = net.join(n.public_key().clone());
        let co = n.init(ch, (*nodes.staked_nodes).clone());
        coordinators.spawn(co.go());
    }

    loop {
        match net.recv().await {
            Event::Unicast { src, dest, data } => {
                let msg = Message::decode(&data).unwrap();
                debug!(%src, %dest, %msg, "unicast");
                net.send(dest, data).unwrap()
            }
            Event::Multicast { src, data } => {
                let msg = Message::decode(&data).unwrap();
                debug!(%src, %msg, "multicast");
                net.broadcast(data)
            }
        }
    }
}

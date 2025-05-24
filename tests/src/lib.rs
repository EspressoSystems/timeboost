use std::net::{Ipv4Addr, SocketAddr};

use multisig::{Committee, Keypair, PublicKey, x25519};
use timeboost_utils::{unsafe_zero_dh_keypair, unsafe_zero_keypair};

#[cfg(test)]
mod tests;

#[allow(unused)]
pub(crate) mod prelude {
    use committable::{Commitment, Committable, RawCommitmentBuilder};
    use serde::{Deserialize, Serialize};

    pub use sailfish::types::DataSource;
    pub use timeboost::types::Timestamp;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SailfishBlock(Timestamp);

    impl SailfishBlock {
        pub fn timestamp(&self) -> Timestamp {
            self.0
        }
    }

    impl Committable for SailfishBlock {
        fn commit(&self) -> Commitment<Self> {
            RawCommitmentBuilder::new("SailfishBlock")
                .u64_field("timestamp", *self.0)
                .finalize()
        }
    }

    pub type Action = sailfish::types::Action<SailfishBlock>;
    pub type Message = sailfish::types::Message<SailfishBlock>;
    pub type Vertex = sailfish::types::Vertex<SailfishBlock>;
    pub type Consensus = sailfish::consensus::Consensus<SailfishBlock>;
    pub type Dag = sailfish::consensus::Dag<SailfishBlock>;

    pub struct EmptyBlocks;

    impl DataSource for EmptyBlocks {
        type Data = SailfishBlock;

        fn next(&mut self, _: sailfish::types::RoundNumber) -> Self::Data {
            SailfishBlock(Timestamp::now())
        }
    }
}

pub struct Group {
    pub size: usize,
    pub peers: Vec<(PublicKey, x25519::PublicKey, SocketAddr)>,
    pub committee: Committee,
    pub sign_keypairs: Vec<Keypair>,
    pub dh_keypairs: Vec<x25519::Keypair>,
}

impl Group {
    pub fn new(size: usize) -> Self {
        let sign_keypairs = (0..size as u64)
            .map(unsafe_zero_keypair)
            .collect::<Vec<_>>();
        let dh_keypairs = (0..size as u64)
            .map(unsafe_zero_dh_keypair)
            .collect::<Vec<_>>();
        let mut addrs = vec![];
        let mut pubks = vec![];

        for (i, kpr) in sign_keypairs.iter().enumerate() {
            pubks.push((i as u8, kpr.public_key()));
            let port = portpicker::pick_unused_port().expect("could not find an open port");
            addrs.push(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        }

        let peers = pubks
            .iter()
            .zip(addrs.clone())
            .zip(&dh_keypairs)
            .map(|((pk, addr), dh)| (pk.1, dh.public_key(), addr));

        Self {
            size,
            peers: peers.collect(),
            committee: Committee::new(pubks),
            sign_keypairs,
            dh_keypairs,
        }
    }
}

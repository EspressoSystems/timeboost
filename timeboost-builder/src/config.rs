use cliquenet as net;
use multisig::{Keypair, PublicKey, x25519};

#[derive(Debug)]
pub struct BlockProducerConfig {
    pub(crate) sign_keypair: Keypair,
    pub(crate) dh_keypair: x25519::Keypair,
    pub(crate) peers: Vec<(PublicKey, x25519::PublicKey, net::Address)>,
    pub(crate) bind: net::Address,
}

impl BlockProducerConfig {
    pub fn new<A>(kp: Keypair, xp: x25519::Keypair, bind: A) -> Self
    where
        A: Into<net::Address>,
    {
        Self {
            sign_keypair: kp,
            dh_keypair: xp,
            peers: Vec::new(),
            bind: bind.into(),
        }
    }

    pub fn with_peers<I, A>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (PublicKey, x25519::PublicKey, A)>,
        A: Into<net::Address>,
    {
        self.peers = it.into_iter().map(|(k, x, a)| (k, x, a.into())).collect();
        self
    }
}

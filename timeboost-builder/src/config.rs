use cliquenet as net;
use multisig::{Keypair, PublicKey};

#[derive(Debug)]
pub struct BlockProducerConfig {
    pub(crate) keypair: Keypair,
    pub(crate) peers: Vec<(PublicKey, net::Address)>,
    pub(crate) bind: net::Address,
}

impl BlockProducerConfig {
    pub fn new<A>(keyp: Keypair, bind: A) -> Self
    where
        A: Into<net::Address>,
    {
        Self {
            keypair: keyp,
            peers: Vec::new(),
            bind: bind.into(),
        }
    }

    pub fn with_peers<I, A>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = (PublicKey, A)>,
        A: Into<net::Address>,
    {
        self.peers = it.into_iter().map(|(k, a)| (k, a.into())).collect();
        self
    }
}

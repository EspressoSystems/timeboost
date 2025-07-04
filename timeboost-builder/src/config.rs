use bon::Builder;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Keypair, x25519};

#[derive(Debug, Clone, Builder)]
pub struct BlockProducerConfig {
    pub(crate) sign_keypair: Keypair,
    pub(crate) dh_keypair: x25519::Keypair,
    pub(crate) committee: AddressableCommittee,
    pub(crate) address: Address,
    pub(crate) retain: usize,
}

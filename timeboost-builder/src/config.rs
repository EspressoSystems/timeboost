use bon::Builder;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Keypair, PublicKey, x25519};

#[derive(Debug, Clone, Builder)]
pub struct CertifierConfig {
    pub(crate) sign_keypair: Keypair,
    pub(crate) dh_keypair: x25519::Keypair,
    pub(crate) committee: AddressableCommittee,
    pub(crate) address: Address,
    #[builder(default = true)]
    pub(crate) recover: bool,
}

#[derive(Debug, Clone, Builder)]
pub struct SubmitterConfig {
    pub(crate) pubkey: PublicKey,
    pub(crate) robusta: robusta::Config,
}

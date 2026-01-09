use bon::Builder;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Committee, Keypair, PublicKey, x25519};
use robusta::espresso_types::NamespaceId;

#[derive(Debug, Clone, Builder)]
pub struct CertifierConfig {
    pub(crate) sign_keypair: Keypair,
    pub(crate) dh_keypair: x25519::Keypair,
    pub(crate) committee: AddressableCommittee,
    pub(crate) previous_committee: Option<AddressableCommittee>,
    pub(crate) address: Address,
}

impl CertifierConfig {
    pub fn address(&self) -> &Address {
        &self.address
    }
}

#[derive(Debug, Clone, Builder)]
pub struct SubmitterConfig {
    pub(crate) pubkey: PublicKey,
    #[builder(into)]
    pub(crate) namespace: NamespaceId,
    pub(crate) robusta: (robusta::Config, Vec<robusta::Config>),
    pub(crate) committee: Committee,
    pub(crate) prev_committee: Option<Committee>,
    pub(crate) max_transaction_size: usize,
}

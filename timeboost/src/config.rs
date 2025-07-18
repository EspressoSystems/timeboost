use bon::Builder;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Keypair, x25519};
use timeboost_builder::{CertifierConfig, SubmitterConfig, robusta};
use timeboost_sequencer::SequencerConfig;
use timeboost_types::DecryptionKey;

#[derive(Debug, Clone, Builder)]
pub struct TimeboostConfig {
    /// The port to bind the metrics API server to.
    pub(crate) metrics_port: u16,

    /// The sailfish peers that this node will connect to.
    pub(crate) sailfish_committee: AddressableCommittee,

    /// The decrypt peers that this node will connect to.
    pub(crate) decrypt_committee: AddressableCommittee,

    /// The block certifier peers that this node will connect to.
    pub(crate) certifier_committee: AddressableCommittee,

    /// The keypair for the node to sign messages.
    pub(crate) sign_keypair: Keypair,

    /// The keypair for Diffie-Hellman key exchange.
    pub(crate) dh_keypair: x25519::Keypair,

    /// The decryption key material for the node.
    pub(crate) decryption_key: DecryptionKey,

    /// The bind address for the sailfish node.
    pub(crate) sailfish_addr: Address,

    /// The bind address for the decrypter node.
    pub(crate) decrypt_addr: Address,

    /// The bind address for the block certifier node.
    pub(crate) certifier_addr: Address,

    /// The bind address of the internal API.
    pub(crate) internal_api: Address,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    pub(crate) nitro_addr: Option<Address>,

    /// Is this node recovering from a crash?
    #[builder(default = true)]
    pub(crate) recover: bool,

    /// Length of the leash between Sailfish an other phases.
    #[builder(default = 100)]
    pub(crate) leash_len: usize,

    /// Configuration of espresso network client.
    pub(crate) robusta: robusta::Config,
}

impl TimeboostConfig {
    pub fn sequencer_config(&self) -> SequencerConfig {
        SequencerConfig::builder()
            .sign_keypair(self.sign_keypair.clone())
            .dh_keypair(self.dh_keypair.clone())
            .decryption_key(self.decryption_key.clone())
            .sailfish_addr(self.sailfish_addr.clone())
            .decrypt_addr(self.decrypt_addr.clone())
            .sailfish_committee(self.sailfish_committee.clone())
            .decrypt_committee(self.decrypt_committee.clone())
            .recover(self.recover)
            .leash_len(self.leash_len)
            .build()
    }

    pub fn certifier_config(&self) -> CertifierConfig {
        CertifierConfig::builder()
            .sign_keypair(self.sign_keypair.clone())
            .dh_keypair(self.dh_keypair.clone())
            .address(self.certifier_addr.clone())
            .committee(self.certifier_committee.clone())
            .recover(self.recover)
            .build()
    }

    pub fn submitter_config(&self) -> SubmitterConfig {
        SubmitterConfig::builder()
            .pubkey(self.sign_keypair.public_key())
            .robusta(self.robusta.clone())
            .build()
    }
}

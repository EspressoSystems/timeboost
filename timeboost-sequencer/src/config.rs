use bon::Builder;
use cliquenet as net;
use cliquenet::AddressableCommittee;
use multisig::{Committee, Keypair, PublicKey, x25519};
use sailfish::rbc::RbcConfig;
use sailfish::types::CommitteeVec;
use timeboost_types::{Address, DecryptionKey, DelayedInboxIndex};

#[derive(Debug, Clone, Builder)]
pub struct SequencerConfig {
    /// The keypair to sign messages.
    pub(crate) sign_keypair: Keypair,

    /// The keypair for Diffie-Hellman key exchanges.
    pub(crate) dh_keypair: x25519::Keypair,

    /// The key material for the decryption phase.
    pub(crate) decryption_key: DecryptionKey,

    /// The address the Sailfish TCP listener binds to.
    pub(crate) sailfish_addr: net::Address,

    /// The address the TCP listener for the decryption phase binds to.
    pub(crate) decrypt_addr: net::Address,

    /// The peers that Sailfish will connect to.
    pub(crate) sailfish_committee: AddressableCommittee,

    /// The peers that the decryption network will connect to.
    pub(crate) decrypt_committee: AddressableCommittee,

    /// The priority lane controller address.
    #[builder(default)]
    pub(crate) priority_addr: Address,

    /// The delayed inbox index.
    #[builder(default)]
    pub(crate) delayed_inbox_index: DelayedInboxIndex,

    /// Is this sequencer recovering from a crash?
    #[builder(default = true)]
    pub(crate) recover: bool,

    /// The previous Sailfish committee.
    pub(crate) previous_sailfish_committee: Option<AddressableCommittee>,

    /// Length of the leash between Sailfish and other phases.
    pub(crate) leash_len: usize,
}

impl SequencerConfig {
    pub fn sign_keypair(&self) -> &Keypair {
        &self.sign_keypair
    }

    pub fn dh_keypair(&self) -> &x25519::Keypair {
        &self.dh_keypair
    }

    pub fn sailfish_address(&self) -> &net::Address {
        &self.sailfish_addr
    }

    pub fn sailfish_committee(&self) -> &AddressableCommittee {
        &self.sailfish_committee
    }

    pub fn previous_sailfish_committee(&self) -> Option<&AddressableCommittee> {
        self.previous_sailfish_committee.as_ref()
    }

    pub fn decrypt_address(&self) -> &net::Address {
        &self.decrypt_addr
    }

    pub fn decrypt_committee(&self) -> &AddressableCommittee {
        &self.decrypt_committee
    }

    pub fn is_recover(&self) -> bool {
        self.recover
    }

    /// Derive an RBC config from this sequencer config.
    pub fn rbc_config(&self) -> RbcConfig {
        let cv = if let Some(prev) = &self.previous_sailfish_committee {
            CommitteeVec::new(prev.committee().clone())
                .with(self.sailfish_committee.committee().clone())
        } else {
            CommitteeVec::new(self.sailfish_committee.committee().clone())
        };
        let id = self.sailfish_committee.committee().id();
        RbcConfig::new(self.sign_keypair.clone(), id, cv).recover(self.recover)
    }

    pub fn decrypter_config(&self) -> DecrypterConfig {
        DecrypterConfig::builder()
            .label(self.sign_keypair.public_key())
            .retain(self.leash_len)
            .decryption_key(self.decryption_key.clone())
            .committee(self.decrypt_committee.committee().clone())
            .build()
    }
}

#[derive(Debug, Clone, Builder)]
pub struct DecrypterConfig {
    pub(crate) label: PublicKey,
    pub(crate) retain: usize,
    pub(crate) committee: Committee,
    pub(crate) decryption_key: DecryptionKey,
}

use bon::Builder;
use cliquenet as net;
use cliquenet::AddressableCommittee;
use multisig::{Keypair, x25519};
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
}

impl SequencerConfig {
    pub fn is_recover(&self) -> bool {
        self.recover
    }

    /// Derive an RBC config from this sequencer config.
    pub fn rbc_config(&self) -> RbcConfig {
        let mut cv = CommitteeVec::new();
        if let Some(prev) = &self.previous_sailfish_committee {
            cv.add(prev.committee().clone());
        }
        cv.add(self.sailfish_committee.committee().clone());
        let id = self.sailfish_committee.committee().id();
        RbcConfig::new(self.sign_keypair.clone(), id, cv).recover(self.recover)
    }
}

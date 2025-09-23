use alloy::primitives::BlockNumber;
use bon::Builder;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Keypair, x25519};
use timeboost_builder::{CertifierConfig, SubmitterConfig, robusta};
use timeboost_config::ChainConfig;
use timeboost_crypto::prelude::DkgDecKey;
use timeboost_sequencer::SequencerConfig;
use timeboost_types::{KeyStore, ThresholdKeyCell};

use crate::committee::CommitteeInfo;

#[derive(Debug, Clone, Builder)]
pub struct TimeboostConfig {
    /// The sailfish peers that this node will connect to.
    pub(crate) sailfish_committee: AddressableCommittee,

    /// The block in which the current committee is registered
    pub(crate) registered_blk: BlockNumber,

    /// Previous committee info stored on chain
    pub(crate) prev_committee: Option<CommitteeInfo>,

    /// The decrypt peers that this node will connect to.
    pub(crate) decrypt_committee: AddressableCommittee,

    /// The block certifier peers that this node will connect to.
    pub(crate) certifier_committee: AddressableCommittee,

    /// The keypair for the node to sign messages.
    pub(crate) sign_keypair: Keypair,

    /// The keypair for Diffie-Hellman key exchange.
    pub(crate) dh_keypair: x25519::Keypair,

    /// The encryption/decryption key used in the DKG or key resharing for secure communication.
    pub(crate) dkg_key: DkgDecKey,

    /// Key store containing DKG public keys of all nodes.
    pub(crate) key_store: KeyStore,

    /// The bind address for the sailfish node.
    pub(crate) sailfish_addr: Address,

    /// The bind address for the decrypter node.
    pub(crate) decrypt_addr: Address,

    /// The bind address for the block certifier node.
    pub(crate) certifier_addr: Address,

    /// The address of the Arbitrum Nitro node listener where we forward inclusion list to.
    pub(crate) nitro_addr: Option<Address>,

    /// Max. size of an espresso transaction.
    pub(crate) max_transaction_size: usize,

    /// Is this node recovering from a crash?
    #[builder(default = true)]
    pub(crate) recover: bool,

    /// Length of the leash between Sailfish an other phases.
    #[builder(default = 100)]
    pub(crate) leash_len: usize,

    /// Pending threshold encryption key that will be updated after DKG/resharing.
    pub(crate) threshold_dec_key: ThresholdKeyCell,

    /// Configuration of espresso network client.
    pub(crate) robusta: (robusta::Config, Vec<robusta::Config>),

    /// Chain configuration
    pub(crate) chain_config: ChainConfig,
}

impl TimeboostConfig {
    pub fn sequencer_config(&self) -> SequencerConfig {
        SequencerConfig::builder()
            .sign_keypair(self.sign_keypair.clone())
            .dh_keypair(self.dh_keypair.clone())
            .dkg_key(self.dkg_key.clone())
            .sailfish_addr(self.sailfish_addr.clone())
            .decrypt_addr(self.decrypt_addr.clone())
            .sailfish_committee(self.sailfish_committee.clone())
            .decrypt_committee((self.decrypt_committee.clone(), self.key_store.clone()))
            .recover(self.recover)
            .maybe_previous_sailfish_committee(
                self.prev_committee.as_ref().map(|c| c.sailfish_committee()),
            )
            .maybe_previous_decrypt_committee(
                self.prev_committee
                    .as_ref()
                    .map(|c| (c.decrypt_committee(), c.dkg_key_store())),
            )
            .leash_len(self.leash_len)
            .threshold_dec_key(self.threshold_dec_key.clone())
            .chain_config(self.chain_config.clone())
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
            .namespace(self.chain_config.namespace)
            .committee(self.sailfish_committee.committee().clone())
            .max_transaction_size(self.max_transaction_size)
            .build()
    }
}

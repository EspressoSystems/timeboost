use alloy::providers::ProviderBuilder;
use anyhow::Result;
use bon::Builder;
use cliquenet::{Address, AddressableCommittee};
use multisig::{Committee, Keypair, x25519};
use timeboost_builder::{CertifierConfig, SubmitterConfig, robusta};
use timeboost_config::{ChainConfig, DECRYPTER_PORT_OFFSET};
use timeboost_contract::{CommitteeMemberSol, KeyManager};
use timeboost_crypto::prelude::{DkgDecKey, DkgEncKey};
use timeboost_sequencer::SequencerConfig;
use timeboost_types::{KeyStore, ThresholdKeyCell};

#[derive(Debug, Clone, Builder)]
pub struct TimeboostConfig {
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
    pub async fn sequencer_config(&self) -> Result<SequencerConfig> {
        let cur_cid: u64 = self.sailfish_committee.committee().id().into();

        let (prev_sailfish, prev_decrypt) = if cur_cid == 0u64 {
            (None, None)
        } else {
            // syncing with contract to get peer info about the previous committee
            // largely adapted from binaries/timeboost.rs
            // TODO: (alex) extrapolate the remaining logic into a common helper
            let prev_cid = cur_cid - 1;

            let provider =
                ProviderBuilder::new().connect_http(self.chain_config.parent.rpc_url.clone());
            let contract =
                KeyManager::new(self.chain_config.parent.key_manager_contract, &provider);
            let members: Vec<CommitteeMemberSol> =
                contract.getCommitteeById(prev_cid).call().await?.members;

            tracing::info!(label = %self.sign_keypair.public_key(), committee_id = %prev_cid, "prev committee info synced");

            let peer_hosts_and_keys = members
                .iter()
                .map(|peer| {
                    let sig_key = multisig::PublicKey::try_from(peer.sigKey.as_ref())
                        .expect("Should parse sigKey bytes");
                    let dh_key = x25519::PublicKey::try_from(peer.dhKey.as_ref())
                        .expect("Should parse dhKey bytes");
                    let dkg_enc_key = DkgEncKey::from_bytes(peer.dkgKey.as_ref())
                        .expect("Should parse dkgKey bytes");
                    let sailfish_address =
                        cliquenet::Address::try_from(peer.networkAddress.as_ref())
                            .expect("Should parse networkAddress string");
                    (sig_key, dh_key, dkg_enc_key, sailfish_address)
                })
                .collect::<Vec<_>>();

            let mut sailfish_peer_hosts_and_keys = Vec::new();
            let mut decrypt_peer_hosts_and_keys = Vec::new();
            let mut dkg_enc_keys = Vec::new();

            for (signing_key, dh_key, dkg_enc_key, sailfish_addr) in
                peer_hosts_and_keys.iter().cloned()
            {
                sailfish_peer_hosts_and_keys.push((signing_key, dh_key, sailfish_addr.clone()));
                decrypt_peer_hosts_and_keys.push((
                    signing_key,
                    dh_key,
                    sailfish_addr.clone().with_offset(DECRYPTER_PORT_OFFSET),
                ));
                dkg_enc_keys.push(dkg_enc_key.clone());
            }

            let sailfish_committee = {
                let c = Committee::new(
                    prev_cid,
                    sailfish_peer_hosts_and_keys
                        .iter()
                        .enumerate()
                        .map(|(i, (k, ..))| (i as u8, *k)),
                );
                AddressableCommittee::new(c, sailfish_peer_hosts_and_keys.iter().cloned())
            };

            let decrypt_committee = {
                let c = Committee::new(
                    prev_cid,
                    decrypt_peer_hosts_and_keys
                        .iter()
                        .enumerate()
                        .map(|(i, (k, ..))| (i as u8, *k)),
                );
                AddressableCommittee::new(c, decrypt_peer_hosts_and_keys.iter().cloned())
            };

            let key_store = KeyStore::new(
                sailfish_committee.committee().clone(),
                dkg_enc_keys
                    .into_iter()
                    .enumerate()
                    .map(|(i, k)| (i as u8, k)),
            );

            (
                Some(sailfish_committee),
                Some((decrypt_committee, key_store)),
            )
        };

        Ok(SequencerConfig::builder()
            .sign_keypair(self.sign_keypair.clone())
            .dh_keypair(self.dh_keypair.clone())
            .dkg_key(self.dkg_key.clone())
            .sailfish_addr(self.sailfish_addr.clone())
            .decrypt_addr(self.decrypt_addr.clone())
            .sailfish_committee(self.sailfish_committee.clone())
            .decrypt_committee((self.decrypt_committee.clone(), self.key_store.clone()))
            .recover(self.recover)
            .maybe_previous_sailfish_committee(prev_sailfish)
            .maybe_previous_decrypt_committee(prev_decrypt)
            .leash_len(self.leash_len)
            .threshold_dec_key(self.threshold_dec_key.clone())
            .chain_config(self.chain_config.clone())
            .build())
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
            .build()
    }
}

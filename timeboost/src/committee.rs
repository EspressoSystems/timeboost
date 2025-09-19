//! Syncing committee info from the KeyManager contract

use std::pin::Pin;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
};
use anyhow::{Context as AnyhowContext, Result};
use cliquenet::AddressableCommittee;
use futures::{Stream, StreamExt};
use itertools::{Itertools, izip};
use multisig::{Committee, CommitteeId, x25519};
use timeboost_config::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, ParentChain};
use timeboost_contract::KeyManager::{self, CommitteeCreated};
use timeboost_contract::provider::PubSubProvider;
use timeboost_crypto::prelude::DkgEncKey;
use timeboost_types::{KeyStore, Timestamp};
use tracing::error;
use url::Url;

/// Type alias for the committee stream
pub type NewCommitteeStream = Pin<Box<dyn Stream<Item = CommitteeInfo>>>;

/// The committee info stored on the KeyManager contract, a subset of [`CommitteeConfig`]
/// Keys and hosts are ordered in the same as they were registered (with KeyId from 0..n)
#[derive(Debug, Clone)]
pub struct CommitteeInfo {
    id: CommitteeId,
    timestamp: Timestamp,
    signing_keys: Vec<multisig::PublicKey>,
    dh_keys: Vec<x25519::PublicKey>,
    dkg_keys: Vec<DkgEncKey>,
    public_addresses: Vec<cliquenet::Address>,
}

impl CommitteeInfo {
    /// Fetch the committee info for `committee_id` from `key_manager_addr` on chain
    pub async fn fetch(
        rpc: Url,
        key_manager_addr: Address,
        committee_id: CommitteeId,
    ) -> Result<Self> {
        let provider = ProviderBuilder::new().connect_http(rpc);
        Self::fetch_with(provider, key_manager_addr, committee_id).await
    }

    pub(crate) async fn fetch_with(
        provider: impl Provider,
        key_manager_addr: Address,
        committee_id: CommitteeId,
    ) -> Result<Self> {
        let contract = KeyManager::new(key_manager_addr, &provider);
        let c = contract
            .getCommitteeById(committee_id.into())
            .call()
            .await?;

        let (signing_keys, dh_keys, dkg_keys, public_addresses) = c
            .members
            .iter()
            .map(|m| {
                let sig_key = multisig::PublicKey::try_from(m.sigKey.as_ref())
                    .with_context(|| "Failed to parse sigKey bytes")?;
                let dh_key = x25519::PublicKey::try_from(m.dhKey.as_ref())
                    .with_context(|| "Failed to parse dhKey bytes")?;
                let dkg_key = DkgEncKey::from_bytes(m.dkgKey.as_ref())
                    .with_context(|| "Failed to parse dkgKey bytes")?;
                let addr = cliquenet::Address::try_from(m.networkAddress.as_ref())
                    .with_context(|| "Failed to parse networkAddress string")?;
                Ok((sig_key, dh_key, dkg_key, addr))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .multiunzip();

        Ok(Self {
            id: committee_id,
            timestamp: c.effectiveTimestamp.into(),
            signing_keys,
            dh_keys,
            dkg_keys,
            public_addresses,
        })
    }

    pub fn id(&self) -> CommitteeId {
        self.id
    }

    pub fn effective_timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn signing_keys(&self) -> &[multisig::PublicKey] {
        &self.signing_keys
    }

    pub fn committee(&self) -> Committee {
        Committee::new(
            self.id,
            self.signing_keys
                .iter()
                .enumerate()
                .map(|(i, k)| (i as u8, *k)),
        )
    }

    pub fn address_info(
        &self,
    ) -> impl Iterator<Item = (multisig::PublicKey, x25519::PublicKey, cliquenet::Address)> {
        izip!(
            self.signing_keys.iter().cloned(),
            self.dh_keys.iter().cloned(),
            self.public_addresses.iter().cloned()
        )
    }

    pub fn sailfish_committee(&self) -> AddressableCommittee {
        AddressableCommittee::new(self.committee(), self.address_info())
    }

    pub fn decrypt_committee(&self) -> AddressableCommittee {
        AddressableCommittee::new(
            self.committee(),
            izip!(
                self.signing_keys.iter().cloned(),
                self.dh_keys.iter().cloned(),
                self.public_addresses
                    .iter()
                    .map(|a| a.clone().with_offset(DECRYPTER_PORT_OFFSET)),
            ),
        )
    }

    pub fn certifier_committee(&self) -> AddressableCommittee {
        AddressableCommittee::new(
            self.committee(),
            izip!(
                self.signing_keys.iter().cloned(),
                self.dh_keys.iter().cloned(),
                self.public_addresses
                    .iter()
                    .map(|a| a.clone().with_offset(CERTIFIER_PORT_OFFSET)),
            ),
        )
    }

    pub fn dkg_key_store(&self) -> KeyStore {
        KeyStore::new(
            self.committee(),
            self.dkg_keys
                .iter()
                .enumerate()
                .map(|(i, k)| (i as u8, k.clone())),
        )
    }

    /// subscribe an event stream
    pub async fn new_committee_stream(
        provider: &PubSubProvider,
        start_ts: Timestamp,
        config: &ParentChain,
    ) -> Result<NewCommitteeStream> {
        let from_block = provider
            .get_block_number_by_timestamp(start_ts)
            .await?
            .unwrap_or_default();
        let events = provider
            .event_stream::<CommitteeCreated>(
                config.key_manager_contract,
                BlockNumberOrTag::Number(from_block),
            )
            .await
            .map_err(|e| {
                error!("Failed to create CommitteeCreated stream: {:?}", e);
                e
            })?;

        let provider = provider.clone();
        let key_manager_contract = config.key_manager_contract;
        let s = events.filter_map(move |log| {
            let provider = provider.clone();
            async move {
                let committee_id: CommitteeId = log.data().id.into();
                match CommitteeInfo::fetch_with(&*provider, key_manager_contract, committee_id)
                    .await
                {
                    Ok(comm_info) => Some(comm_info),
                    Err(err) => {
                        error!(%committee_id, %err, "fail to fetch new `CommitteeInfo`");
                        None
                    }
                }
            }
        });

        Ok(Box::pin(s))
    }
}

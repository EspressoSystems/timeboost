//! Syncing committee info from the KeyManager contract

use std::pin::Pin;
use std::task::{Context, Poll};

use alloy::{
    eips::BlockNumberOrTag,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol_types::SolEvent,
    transports::ws::WsConnect,
};
use anyhow::{Context as AnyhowContext, Result};
use cliquenet::AddressableCommittee;
use futures::{Stream, StreamExt};
use itertools::{Itertools, izip};
use multisig::{Committee, CommitteeId, x25519};
use timeboost_config::{CERTIFIER_PORT_OFFSET, DECRYPTER_PORT_OFFSET, ParentChain};
use timeboost_contract::KeyManager::{self, CommitteeCreated};
use timeboost_crypto::prelude::DkgEncKey;
use timeboost_types::{KeyStore, Timestamp};
use tracing::error;
use url::Url;

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
    pub async fn fetch(rpc: Url, key_manager_addr: Address, committee_id: u64) -> Result<Self> {
        let provider = ProviderBuilder::new().connect_http(rpc);

        let contract = KeyManager::new(key_manager_addr, &provider);
        let c = contract.getCommitteeById(committee_id).call().await?;

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
            id: committee_id.into(),
            timestamp: c.effectiveTimestamp.into(),
            signing_keys,
            dh_keys,
            dkg_keys,
            public_addresses,
        })
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

    pub fn group(
        &self,
    ) -> impl Iterator<Item = (multisig::PublicKey, x25519::PublicKey, cliquenet::Address)> {
        izip!(
            self.signing_keys.iter().cloned(),
            self.dh_keys.iter().cloned(),
            self.public_addresses.iter().cloned()
        )
    }

    pub fn sailfish_committee(&self) -> AddressableCommittee {
        AddressableCommittee::new(self.committee(), self.group())
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
}

/// An pubsub-provider-holding event stream. (the pubsub will close on drop)
pub struct NewCommitteeStream {
    _provider: Box<dyn Provider>,
    inner: Pin<Box<dyn Stream<Item = u64> + Send>>,
}

impl Stream for NewCommitteeStream {
    type Item = u64;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.as_mut().poll_next(cx)
    }
}

impl NewCommitteeStream {
    pub async fn create(config: &ParentChain) -> Result<Self> {
        // setup the websocket for contract event stream
        let ws = WsConnect::new(config.ws_url.clone());
        // spawn the pubsub service (and backend) and the frontend is registered at the provider
        let provider = ProviderBuilder::new()
            .connect_pubsub_with(ws)
            .await
            .map_err(|err| {
                error!(?err, "event pubsub failed to start");
                err
            })?;

        let chain_id = config.id;
        let tag = if chain_id == 31337 || chain_id == 1337 {
            // local test chain, we start scanning from the genesis
            BlockNumberOrTag::Number(0)
        } else {
            config.block_tag
        };

        let filter = Filter::new()
            .address(config.key_manager_contract)
            .event(KeyManager::CommitteeCreated::SIGNATURE)
            .from_block(tag);
        let events = provider
            .subscribe_logs(&filter)
            .await
            .map_err(|err| {
                error!(?err, "pubsub subscription failed");
                err
            })?
            .into_stream();

        let validated = events.filter_map(|log| async move {
            log.log_decode_validate::<CommitteeCreated>()
                .ok()
                .map(|v| v.data().id)
        });
        Ok(Self {
            _provider: Box::new(provider),
            inner: Box::pin(validated),
        })
    }
}

use std::sync::Arc;

use crate::{CommitteeConfig, CommitteeMember, NodeConfig};
use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder};
use anyhow::{Context, Result, bail};
use futures::StreamExt;
use futures::stream::{self, BoxStream};
use multisig::{CommitteeId, x25519};
use timeboost_contract::KeyManager::{self, CommitteeCreated, CommitteeIdDoesNotExist};
use timeboost_contract::provider::{HttpProvider, PubSubProvider};
use timeboost_crypto::prelude::DkgEncKey;
use tracing::error;
use url::Url;

#[derive(Debug)]
pub struct CommitteeContract {
    contract: Address,
    provider: HttpProvider,
    websocket_url: Url,
}

impl CommitteeContract {
    pub fn new(rpc: &Url, ws: &Url, addr: Address) -> Self {
        let p = ProviderBuilder::new().connect_http(rpc.clone());
        Self {
            contract: addr,
            provider: p,
            websocket_url: ws.clone(),
        }
    }

    pub async fn active(&mut self) -> Result<CommitteeConfig> {
        let km = KeyManager::new(self.contract, &self.provider);
        let id = km.currentCommitteeId().call().await?;
        let Some(cfg) = fetch(&self.provider, &self.contract, id.into()).await? else {
            bail!("no committee for id {id} at address {}", self.contract)
        };
        Ok(cfg)
    }

    pub async fn get(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        fetch(&self.provider, &self.contract, id).await
    }

    pub async fn next(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        fetch(&self.provider, &self.contract, id + 1).await
    }

    pub async fn prev(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        fetch(&self.provider, &self.contract, id - 1).await
    }

    pub async fn subscribe(
        &mut self,
        start: CommitteeId,
    ) -> Result<BoxStream<'static, CommitteeConfig>> {
        let contract = KeyManager::new(self.contract, &self.provider);
        let committee = contract.getCommitteeById(start.into()).call().await?;

        // Collect all committees already available after `start`:
        let mut cursor = start;
        let mut available = Vec::new();
        while let Some(c) = self.next(cursor).await? {
            cursor = c.id;
            available.push(c)
        }

        let provider = Arc::new(PubSubProvider::new(self.websocket_url.clone()).await?);
        let address = self.contract;
        let stream = provider
            .event_stream::<CommitteeCreated>(
                address,
                BlockNumberOrTag::Number(committee.registeredBlockNumber.to::<u64>()),
            )
            .await?
            .filter_map(move |log| {
                let provider = provider.clone();
                async move {
                    let id = log.data().id;
                    match fetch(&provider, &address, id.into()).await {
                        Ok(Some(c)) => Some(c),
                        Ok(None) => {
                            error!(committee = %id, "no committee for id");
                            None
                        }
                        Err(err) => {
                            error!(committee = %id, %err, "failed to fetch new committee config");
                            None
                        }
                    }
                }
            });

        Ok(stream::iter(available).chain(stream).boxed())
    }
}

impl From<&NodeConfig> for CommitteeContract {
    fn from(cfg: &NodeConfig) -> Self {
        let contract = &cfg.committee.contract;
        Self::new(&contract.rpc_url, &contract.websocket_url, contract.address)
    }
}

async fn fetch(
    provider: &HttpProvider,
    addr: &Address,
    id: CommitteeId,
) -> Result<Option<CommitteeConfig>> {
    let contract = KeyManager::new(*addr, provider);
    let committee = match contract.getCommitteeById(id.into()).call().await {
        Ok(c) => c,
        Err(err) => {
            if err.as_decoded_error::<CommitteeIdDoesNotExist>().is_some() {
                return Ok(None);
            } else {
                return Err(err.into());
            }
        }
    };

    let mut cfg = CommitteeConfig {
        id,
        effective: committee.effectiveTimestamp.into(),
        members: Vec::new(),
    };

    for m in committee.members {
        let signing_key = multisig::PublicKey::try_from(m.sigKey.as_ref())
            .context("failed to parse sigKey bytes")?;
        let dh_key =
            x25519::PublicKey::try_from(m.dhKey.as_ref()).context("failed to parse dhKey bytes")?;
        let dkg_enc_key =
            DkgEncKey::from_bytes(&m.dkgKey).context("failed to parse dkgKey bytes")?;
        let address = cliquenet::Address::try_from(&*m.networkAddress)
            .context("failed to parse networkAddress string")?;
        let batchposter = cliquenet::Address::try_from(&*m.batchPosterAddress)
            .context("failed to parse batchPosterAddress string")?;
        cfg.members.push(CommitteeMember {
            address,
            signing_key,
            dh_key,
            dkg_enc_key,
            batchposter,
        })
    }

    Ok(Some(cfg))
}

//! Syncing committee info from the KeyManager contract

use std::path::Path;
use std::sync::Arc;

use crate::{CommitteeConfig, CommitteeMember, ConfigService};
use timeboost_contract::KeyManager::{self, CommitteeCreated};
use timeboost_contract::provider::{HttpProvider, PubSubProvider};
use alloy::{eips::BlockNumberOrTag, primitives::Address, providers::ProviderBuilder};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::BoxStream;
use multisig::{CommitteeId, x25519};
use serde::{Deserialize, Serialize};
use timeboost_crypto::prelude::DkgEncKey;
use tokio::process::{Child, Command};
use tracing::error;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    rpc: Url,
    websocket: Url,
    contract: Address,
    anvil: Option<cliquenet::Address>,
}

#[derive(Debug)]
pub struct ContractConfigService {
    config: Config,
    provider: HttpProvider,
    _anvil: Option<Child>,
}

impl ContractConfigService {
    pub async fn create<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let s = tokio::fs::read_to_string(path).await?;
        let c: Config = toml::from_str(&s)?;
        let p = ProviderBuilder::new().connect_http(c.rpc.clone());
        let a = if let Some(addr) = &c.anvil {
            let mut anvil = Command::new("anvil");
            match addr {
                cliquenet::Address::Inet(ip, port) => {
                    anvil
                        .arg("--host")
                        .arg(format!("{ip}"))
                        .arg("--port")
                        .arg(format!("{port}"));
                }
                cliquenet::Address::Name(host, port) => {
                    anvil
                        .arg("--host")
                        .arg(format!("{host}"))
                        .arg("--port")
                        .arg(format!("{port}"));
                }
            }
            Some(anvil.kill_on_drop(true).spawn()?)
        } else {
            None
        };
        Ok(Self {
            config: c,
            provider: p,
            _anvil: a,
        })
    }
}

#[async_trait]
impl ConfigService for ContractConfigService {
    async fn get(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        fetch(&self.provider, &self.config.contract, id).await
    }

    async fn next(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        fetch(&self.provider, &self.config.contract, id + 1).await
    }

    async fn prev(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        fetch(&self.provider, &self.config.contract, id - 1).await
    }

    async fn subscribe(
        &mut self,
        start: CommitteeId,
    ) -> Result<BoxStream<'static, CommitteeConfig>> {
        let contract = KeyManager::new(self.config.contract, &self.provider);
        let committee = contract.getCommitteeById(start.into()).call().await?;
        let provider = Arc::new(PubSubProvider::new(self.config.websocket.clone()).await?);
        let address = self.config.contract.clone();
        let stream = provider
            .event_stream::<CommitteeCreated>(
                self.config.contract,
                BlockNumberOrTag::Number(committee.registeredBlockNumber.to::<u64>()),
            )
            .await?
            .filter_map(move |log| {
                let provider = provider.clone();
                async move {
                    let id = log.data().id;
                    match fetch(&*provider, &address, id.into()).await {
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
            })
            .boxed();

        Ok(stream)
    }
}

async fn fetch(
    provider: &HttpProvider,
    addr: &Address,
    id: CommitteeId,
) -> Result<Option<CommitteeConfig>> {
    let contract = KeyManager::new(addr.clone(), provider);
    let committee = contract.getCommitteeById(id.into()).call().await?;

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
            DkgEncKey::from_bytes(m.dkgKey.as_ref()).context("failed to parse dkgKey bytes")?;
        let address = cliquenet::Address::try_from(m.networkAddress.as_ref())
            .context("failed to parse networkAddress string")?;
        cfg.members.push(CommitteeMember {
            address,
            signing_key,
            dh_key,
            dkg_enc_key,
        })
    }

    Ok(Some(cfg))
}

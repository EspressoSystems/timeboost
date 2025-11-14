mod contract;
mod file;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use async_trait::async_trait;
use either::Either;
use futures::stream::BoxStream;
use multisig::CommitteeId;
use serde::Deserialize;

use crate::{CommitteeConfig, ConfigError, read_toml};

pub use contract::ContractConfigService;
pub use file::FileConfigService;

type CommitteeStream = BoxStream<'static, CommitteeConfig>;

#[async_trait]
pub trait ConfigService {
    async fn get(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>>;
    async fn next(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>>;
    async fn prev(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>>;
    async fn subscribe(&mut self, start: CommitteeId) -> Result<CommitteeStream>;
}

#[async_trait]
impl<T: ConfigService + Send + 'static + ?Sized> ConfigService for Box<T> {
    async fn get(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        (**self).get(id).await
    }
    async fn next(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        (**self).next(id).await
    }
    async fn prev(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        (**self).prev(id).await
    }
    async fn subscribe(&mut self, start: CommitteeId) -> Result<CommitteeStream> {
        (**self).subscribe(start).await
    }
}

pub async fn config_service(path: &str) -> Result<impl ConfigService + Send + 'static> {
    match path.split_once(':') {
        Some(("file", path)) => {
            let srv = FileConfigService::create(path).await?;
            Ok(Box::new(srv) as Box<dyn ConfigService + Send>)
        }
        Some(("contract", path)) => {
            let srv = ContractConfigService::create(path).await?;
            Ok(Box::new(srv) as Box<dyn ConfigService + Send>)
        }
        Some((other, _)) => {
            bail!("unknown config service {other:?}")
        }
        None => {
            bail!("invalid config service path {path:?}")
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServiceConfig {
    pub committee: Vec<CommitteeFile>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CommitteeFile {
    pub id: CommitteeId,
    #[serde(with = "either::serde_untagged")]
    pub start: Either<jiff::Timestamp, jiff::SignedDuration>,
    pub member: Vec<MemberFile>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MemberFile {
    pub config: PathBuf,
}

impl ServiceConfig {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        read_toml(path).await
    }
}

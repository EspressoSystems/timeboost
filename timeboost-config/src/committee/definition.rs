use std::path::{Path, PathBuf};

use anyhow::Result;
use either::Either;
use multisig::CommitteeId;
use serde::{Deserialize, Serialize};
use timeboost_types::Timestamp;

use crate::{CommitteeConfig, CommitteeMember, ConfigError, read_toml, write_toml};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommitteeDefinition {
    pub id: CommitteeId,
    #[serde(with = "either::serde_untagged")]
    pub start: Either<jiff::Timestamp, jiff::SignedDuration>,
    pub member: Vec<MemberFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MemberFile {
    pub config: PathBuf,
}

impl CommitteeDefinition {
    pub async fn read<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        read_toml(path).await
    }

    pub async fn write<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError> {
        write_toml(self, path).await
    }

    pub async fn to_config(&self) -> Result<CommitteeConfig, ConfigError> {
        let mut cfg = CommitteeConfig {
            effective: match self.start {
                Either::Left(ts) => {
                    let s: u64 = ts
                        .as_second()
                        .try_into()
                        .map_err(|e| ConfigError(PathBuf::new(), Box::new(e)))?;
                    Timestamp::from(s)
                }
                Either::Right(d) => {
                    let s: u64 = d
                        .as_secs()
                        .try_into()
                        .map_err(|e| ConfigError(PathBuf::new(), Box::new(e)))?;
                    Timestamp::now() + s
                }
            },
            id: self.id,
            members: Vec::new(),
        };
        for m in &self.member {
            let member = CommitteeMember::read(&m.config).await?;
            cfg.members.push(member)
        }
        Ok(cfg)
    }
}

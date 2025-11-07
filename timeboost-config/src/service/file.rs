use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use cliquenet::Address;
use either::Either;
use futures::{
    StreamExt,
    stream::{self, FuturesUnordered},
};
use multisig::CommitteeId;
use serde::{Deserialize, Serialize};
use timeboost_types::Timestamp;
use tokio::{fs, time::sleep};

use crate::{
    CommitteeConfig, CommitteeMember, ConfigService, NodeConfig, service::CommitteeStream,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Config {
    committee: Vec<Committee>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Committee {
    id: CommitteeId,
    #[serde(with = "either::serde_untagged")]
    start: Either<jiff::Timestamp, jiff::SignedDuration>,
    member: Vec<Member>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Member {
    config: PathBuf,
    address: Option<Address>,
}

#[derive(Debug)]
pub struct FileConfigService {
    committees: Vec<CommitteeConfig>,
}

impl FileConfigService {
    pub async fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let s = fs::read_to_string(path.as_ref())
            .await
            .with_context(|| format!("could not read config file: {:?}", path.as_ref()))?;

        let c: Config = toml::from_str(&s)
            .with_context(|| format!("invalid file config service config: {:?}", path.as_ref()))?;

        let mut committees = Vec::new();

        for r in &c.committee {
            let t = match r.start {
                Either::Left(ts) => {
                    let s: u64 = ts.as_second().try_into().context("negative timestamp")?;
                    Timestamp::from(s)
                }
                Either::Right(d) => {
                    let s: u64 = d.as_secs().try_into().context("invalid duration")?;
                    Timestamp::now() + s
                }
            };
            let mut committee = CommitteeConfig {
                id: r.id,
                effective: t,
                members: Vec::new(),
            };
            for n in &r.member {
                let node = NodeConfig::read(&n.config).await?;
                committee.members.push(CommitteeMember {
                    signing_key: node.keys.signing.public,
                    dh_key: node.keys.dh.public,
                    dkg_enc_key: node.keys.dkg.public,
                    address: n.address.clone().unwrap_or_else(|| node.net.bind.clone()),
                });
            }
            committees.push(committee)
        }

        Ok(Self { committees })
    }

    fn lookup(&self, id: CommitteeId) -> Option<&CommitteeConfig> {
        self.committees.iter().find(|c| c.id == id)
    }
}

#[async_trait]
impl ConfigService for FileConfigService {
    async fn get(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        Ok(self.lookup(id).cloned())
    }

    async fn next(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        if u64::from(id) == u64::MAX {
            return Ok(None);
        }
        Ok(self.lookup(id + 1).cloned())
    }

    async fn prev(&mut self, id: CommitteeId) -> Result<Option<CommitteeConfig>> {
        if u64::from(id) == u64::MIN {
            return Ok(None);
        }
        Ok(self.lookup(id - 1).cloned())
    }

    async fn subscribe(&mut self, start: CommitteeId) -> Result<CommitteeStream> {
        if self.lookup(start).is_none() {
            bail!("committee to start with ({start}) not found")
        }
        let now: u64 = Timestamp::now().into();
        let events = FuturesUnordered::new();
        for c in &self.committees {
            if c.id <= start {
                continue;
            }
            let c = c.clone();
            let t: u64 = c.effective.into();
            events.push(async move {
                let delay = t.saturating_sub(now).saturating_sub(10);
                sleep(Duration::from_secs(delay)).await;
                c
            });
        }
        Ok(events.chain(stream::pending()).boxed())
    }
}

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use either::Either;
use futures::{
    StreamExt,
    stream::{self, FuturesUnordered},
};
use multisig::CommitteeId;
use timeboost_types::Timestamp;
use tokio::time::sleep;

use crate::{
    CommitteeConfig, CommitteeMember, ConfigService,
    service::{CommitteeStream, ServiceConfig},
};

#[derive(Debug)]
pub struct FileConfigService {
    committees: Vec<CommitteeConfig>,
}

impl FileConfigService {
    pub async fn create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = ServiceConfig::read(path).await?;

        let mut committees = Vec::new();

        for r in &config.committee {
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
                let member = CommitteeMember::read(&n.config).await?;
                committee.members.push(member);
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

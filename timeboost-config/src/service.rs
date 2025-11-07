mod file;

use anyhow::Result;
use async_trait::async_trait;
use futures::stream::BoxStream;
use multisig::CommitteeId;

use crate::CommitteeConfig;

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
impl ConfigService for Box<dyn ConfigService + Send> {
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

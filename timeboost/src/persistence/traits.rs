use anyhow::Result;
use async_trait::async_trait;
use sailfish::consensus::Dag;

#[async_trait]
pub trait Persistence: Sized + Send + Sync + 'static {
    async fn load_dag(&self) -> Result<Dag>;
}

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub trait HasInitializer {
    type Initializer;
    type Into;
    async fn initialize(initializer: Self::Initializer) -> Result<Self::Into>;
}

#![cfg(feature = "noop")]

use anyhow::Result;
use async_trait::async_trait;
use serde::Serialize;
use timeboost_core::types::round_number::RoundNumber;

use super::traits::{Loadable, Persistence, Savable};

pub struct NoOpPersistence;

#[async_trait]
impl Persistence for NoOpPersistence {
    async fn new(_uri: String) -> Result<Self> {
        Ok(Self)
    }
    async fn save<M, T>(&self, _model: M, _saver: T) -> Result<()>
    where
        M: Serialize + Send + Sync,
        T: Savable<Model = M>,
    {
        Ok(())
    }
    async fn load<L>(&self) -> Result<L::Model>
    where
        L: Loadable,
    {
        L::into_model(vec![])
    }
    async fn gc(&self, _tables: &[&str], _round: RoundNumber) -> Result<()> {
        Ok(())
    }
}

use anyhow::Result;
use async_trait::async_trait;
use sailfish::consensus::ConsensusState;
use serde::Serialize;
use timeboost_core::types::round_number::RoundNumber;

use super::types::{consensus_state::ConsensusStateRow, dag::DagRow};

pub(crate) type PgQuery<'q> =
    sqlx::query::Query<'q, sqlx::postgres::Postgres, sqlx::postgres::PgArguments>;

#[async_trait]
#[allow(dead_code)]
pub trait Persistence: Sized + Send + Sync + 'static {
    async fn new(uri: String) -> Result<Self>;
    async fn save_table<M, T>(&self, model: M, saver: T) -> Result<()>
    where
        M: Serialize + Send + Sync,
        T: Savable<Model = M>;
    async fn load_table<L>(&self) -> Result<L::Model>
    where
        L: Loadable;
    async fn gc(&self, round: RoundNumber) -> Result<()>;
}

pub trait Loadable: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin {
    type Model;
    fn table_name() -> &'static str;
    fn into_model(rows: Vec<Self>) -> Result<Self::Model>;
}

pub trait Savable: Send + Sync {
    type Model: Serialize + Send + Sync;

    fn table_name() -> &'static str;
    fn column_names() -> &'static [&'static str];
    fn bind_values(self, query: PgQuery<'_>) -> PgQuery<'_>;
    fn from_model(model: Self::Model) -> Result<Vec<Self>>
    where
        Self: Sized;
}

#[allow(dead_code)]
pub struct Storage<P: Persistence> {
    persistence: P,
}

#[allow(dead_code)]
impl<P: Persistence> Storage<P> {
    pub async fn new(uri: String) -> Result<Self> {
        let persistence = P::new(uri).await?;
        Ok(Self { persistence })
    }

    pub async fn gc(&self, round: RoundNumber) -> Result<()> {
        self.persistence.gc(round).await
    }

    pub async fn load_consensus_state(&self) -> Result<ConsensusState> {
        let consensus_state = self.persistence.load_table::<ConsensusStateRow>().await?;
        let dag = self.persistence.load_table::<DagRow>().await?;
        Ok(ConsensusState {
            round: consensus_state.round,
            committed_round: consensus_state.committed_round,
            transactions: consensus_state.transactions,
            dag,
        })
    }
}

use anyhow::{Context, Result};
use sailfish::consensus::{ConsensusState, Dag};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use timeboost_core::types::round_number::RoundNumber;

use crate::persistence::traits::{Loadable, Query, Savable};

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub(crate) struct ConsensusStateRow {
    pub round: i64,
    pub committed_round: i64,
    pub transactions: Vec<u8>,
}

impl ConsensusStateRow {
    /// Convert a `ConsensusState` into a `ConsensusStateRaw`. We deliberately ignore
    /// the DAG as it is stored via the Vertex Post method instead of dumping the entire
    /// reference into the table.
    pub fn from_consensus_state(state: &ConsensusState) -> Result<Self> {
        Ok(Self {
            round: state.round().i64(),
            committed_round: state.committed_round().i64(),
            transactions: bincode::serialize(&state.transactions())?,
        })
    }
}

impl Savable for ConsensusStateRow {
    type Model = ConsensusState;

    fn table_name() -> &'static str {
        "consensus_state"
    }

    fn column_names() -> &'static [&'static str] {
        &["round", "committed_round", "transactions"]
    }

    fn bind_values(self, query: Query<'_>) -> Query<'_> {
        #[cfg(not(feature = "noop"))]
        {
            query
                .bind(self.round)
                .bind(self.committed_round)
                .bind(self.transactions)
        }

        #[cfg(feature = "noop")]
        query
    }

    fn from_model(model: Self::Model) -> Result<Vec<Self>>
    where
        Self: Sized,
    {
        Ok(vec![Self::from_consensus_state(&model)?])
    }
}

impl Loadable for ConsensusStateRow {
    type Model = ConsensusState;

    fn table_name() -> &'static str {
        "consensus_state"
    }

    fn into_model(rows: Vec<Self>) -> Result<Self::Model> {
        let state = rows.first().context("no rows found")?;
        let transactions = bincode::deserialize(&state.transactions)?;

        // We need a dummy DAG here before we coalesce into the real one.
        let dag = Dag::new(NonZeroUsize::new(1).context("invalid committee size")?);

        Ok(ConsensusState {
            round: RoundNumber::from(state.round),
            committed_round: RoundNumber::from(state.committed_round),
            transactions,
            dag,
        })
    }
}

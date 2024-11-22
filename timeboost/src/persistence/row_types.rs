use anyhow::{Context, Result};
use sailfish::consensus::{ConsensusState, Dag, VoteAccumulator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use timeboost_core::types::{
    message::{NoVote, Timeout},
    round_number::RoundNumber,
    transaction::TransactionsQueue,
    vertex::Vertex,
    PublicKey,
};

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct DagRow {
    pub round: i64,
    pub public_key: Vec<u8>,
    pub vertex: Vec<u8>,
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct ConsensusStatePartialRow {
    pub round: i64,
    pub committed_round: i64,
    pub transactions: Vec<u8>,
}

impl ConsensusStatePartialRow {
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

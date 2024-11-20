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
pub struct TimeoutsRow {
    pub round: i64,
    pub votes: Vec<u8>,
}

impl TimeoutsRow {
    pub fn from_consensus_state(state: &ConsensusState) -> Result<Vec<Self>> {
        let mut timeouts: Vec<TimeoutsRow> = Vec::new();
        for (k, v) in state.timeouts.iter() {
            timeouts.push(TimeoutsRow {
                round: k.i64(),
                votes: bincode::serialize(&v)?,
            });
        }

        Ok(timeouts)
    }
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct DeliveredRow {
    pub round: i64,
    pub public_key: Vec<u8>,
}

impl DeliveredRow {
    pub fn from_consensus_state(state: &ConsensusState) -> Result<Vec<Self>> {
        let mut delivered: Vec<DeliveredRow> = Vec::new();
        for (k, v) in state.delivered.iter() {
            delivered.push(DeliveredRow {
                round: k.i64(),
                public_key: bincode::serialize(&v)?,
            });
        }

        Ok(delivered)
    }
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct ConsensusStatePartialRow {
    pub round: i64,
    pub committed_round: i64,
    pub buffer: Vec<u8>,
    pub delivered: Vec<u8>,
    pub no_votes: Vec<u8>,
    pub leader_stack: Vec<u8>,
    pub transactions: Vec<u8>,
}

impl ConsensusStatePartialRow {
    /// Convert a `ConsensusState` into a `ConsensusStateRaw`. We deliberately ignore
    /// the DAG as it is stored via the Vertex Post method instead of dumping the entire
    /// reference into the table.
    pub fn from_consensus_state(state: &ConsensusState) -> Result<Self> {
        Ok(Self {
            round: state.round.i64(),
            committed_round: state.committed_round.i64(),
            buffer: bincode::serialize(&state.buffer)?,
            delivered: bincode::serialize(&state.delivered)?,
            no_votes: bincode::serialize(&state.no_votes)?,
            leader_stack: bincode::serialize(&state.leader_stack)?,
            transactions: bincode::serialize(&state.transactions)?,
        })
    }
}

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub(crate) struct ConsensusStateRaw {
    pub state_partial: ConsensusStatePartialRow,
    pub timeouts: Vec<TimeoutsRow>,
    pub delivered: Vec<DeliveredRow>,
    pub dag: Option<Dag>,
}

impl From<ConsensusStateRaw> for Result<ConsensusState> {
    fn from(raw: ConsensusStateRaw) -> Self {
        let round = RoundNumber::from(raw.state_partial.round as u64);
        let committed_round = RoundNumber::from(raw.state_partial.committed_round as u64);
        let buffer: HashSet<Vertex> = bincode::deserialize(&raw.state_partial.buffer)?;
        let delivered: HashSet<(RoundNumber, PublicKey)> =
            bincode::deserialize(&raw.state_partial.delivered)?;
        let mut timeouts: BTreeMap<RoundNumber, VoteAccumulator<Timeout>> = BTreeMap::new();
        for row in raw.timeouts {
            let round = RoundNumber::from(row.round as u64);
            let votes: VoteAccumulator<Timeout> = bincode::deserialize(&row.votes)?;
            timeouts.insert(round, votes);
        }
        let no_votes: VoteAccumulator<NoVote> = bincode::deserialize(&raw.state_partial.no_votes)?;
        let leader_stack: Vec<Vertex> = bincode::deserialize(&raw.state_partial.leader_stack)?;
        let transactions: TransactionsQueue =
            bincode::deserialize(&raw.state_partial.transactions)?;

        let dag = raw
            .dag
            .context("dag was somehow not available during deserialization")?;

        Ok(ConsensusState {
            dag,
            round,
            committed_round,
            buffer,
            delivered,
            timeouts,
            no_votes,
            leader_stack,
            transactions,
        })
    }
}

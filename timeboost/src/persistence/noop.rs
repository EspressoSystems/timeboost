use anyhow::Result;
use async_trait::async_trait;
use sailfish::consensus::{ConsensusState, Dag};
use timeboost_core::types::{
    committee::StaticCommittee, round_number::RoundNumber, vertex::Vertex,
};

use super::traits::Persistence;

pub struct NoOpPersistence;

#[async_trait]
impl Persistence for NoOpPersistence {
    async fn new(_uri: String) -> Result<Self> {
        Ok(Self)
    }

    async fn load_dag(&self, committee: &StaticCommittee) -> Result<Dag> {
        Ok(Dag::new(committee.size()))
    }
    async fn save_vertex(&self, _vertex: &Vertex) -> Result<()> {
        Ok(())
    }
    async fn load_consensus_state(&self, committee: &StaticCommittee) -> Result<ConsensusState> {
        Ok(ConsensusState::new(committee))
    }
    async fn save_consensus_state(&self, _state: &ConsensusState) -> Result<()> {
        Ok(())
    }
    async fn gc(&self, _round: RoundNumber) -> Result<()> {
        Ok(())
    }
}

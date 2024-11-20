use anyhow::Result;
use async_trait::async_trait;
use sailfish::consensus::{ConsensusState, Dag};
use timeboost_core::types::{
    committee::StaticCommittee, round_number::RoundNumber, vertex::Vertex,
};

#[async_trait]
#[allow(dead_code)]
pub trait Persistence: Sized + Send + Sync + 'static {
    async fn load_dag(&self, committee: &StaticCommittee) -> Result<Dag>;
    async fn save_vertex(&self, vertex: &Vertex) -> Result<()>;
    async fn load_consensus_state(&self, committee: &StaticCommittee) -> Result<ConsensusState>;
    async fn save_consensus_state(&self, state: &ConsensusState) -> Result<()>;
    async fn gc(&self, round: RoundNumber) -> Result<()>;
}

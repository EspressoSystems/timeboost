use anyhow::Result;
use timeboost_core::types::block::timeboost::{InclusionPhaseBlock, TimeboostBlock};
pub mod noop;
pub trait BlockBuilder {
    fn build(&self, ordered_transactions: Vec<InclusionPhaseBlock>) -> Result<TimeboostBlock>;
}

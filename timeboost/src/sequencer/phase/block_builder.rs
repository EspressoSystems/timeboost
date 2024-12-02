use anyhow::Result;
use block::TimeboostBlock;

use super::inclusion::block::InclusionPhaseBlock;

pub mod block;
pub mod noop;
pub trait BlockBuilder {
    fn build(&self, ordered_transactions: Vec<InclusionPhaseBlock>) -> Result<TimeboostBlock>;
}

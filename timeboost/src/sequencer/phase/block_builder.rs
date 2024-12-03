use super::inclusion::InclusionList;
use anyhow::Result;
use timeboost_core::types::block::timeboost::TimeboostBlock;

pub mod noop;

pub trait BlockBuilder {
    fn build(&self, ordered_transactions: InclusionList) -> Result<TimeboostBlock>;
}

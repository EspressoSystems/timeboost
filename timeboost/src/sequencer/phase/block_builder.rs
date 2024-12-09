use anyhow::Result;
use timeboost_core::types::block::timeboost::TimeboostBlock;

use super::inclusion::InclusionList;
pub mod noop;
pub trait BlockBuilder {
    fn build(&self, ordered_transactions: InclusionList) -> Result<TimeboostBlock>;
}

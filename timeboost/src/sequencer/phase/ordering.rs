use anyhow::Result;
use timeboost_core::types::block::timeboost::InclusionPhaseBlock;

pub mod noop;

pub trait OrderingPhase {
    fn order(&self, decrypted_list: Vec<InclusionPhaseBlock>) -> Result<Vec<InclusionPhaseBlock>>;
}

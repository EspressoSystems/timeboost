use anyhow::Result;

use super::inclusion::block::InclusionPhaseBlock;

pub mod noop;

pub trait OrderingPhase {
    fn order(&self, decrypted_list: Vec<InclusionPhaseBlock>) -> Result<Vec<InclusionPhaseBlock>>;
}

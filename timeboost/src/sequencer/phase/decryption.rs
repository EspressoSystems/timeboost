use anyhow::Result;
use timeboost_core::types::block::timeboost::InclusionPhaseBlock;

pub mod noop;

pub trait DecryptionPhase {
    fn decrypt(&self, inclusion_list: Vec<InclusionPhaseBlock>)
        -> Result<Vec<InclusionPhaseBlock>>;
}

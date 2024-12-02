use anyhow::Result;

use super::inclusion::block::InclusionPhaseBlock;

pub mod noop;

pub trait DecryptionPhase {
    fn decrypt(&self, inclusion_list: Vec<InclusionPhaseBlock>)
        -> Result<Vec<InclusionPhaseBlock>>;
}

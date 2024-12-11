use anyhow::Result;

use super::inclusion::InclusionList;

pub mod noop;

pub trait DecryptionPhase {
    fn decrypt(&self, inclusion_list: InclusionList) -> Result<InclusionList>;
}

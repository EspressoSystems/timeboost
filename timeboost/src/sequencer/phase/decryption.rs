use super::inclusion::InclusionList;
use anyhow::Result;

pub mod noop;

pub trait DecryptionPhase {
    fn decrypt(&self, inclusion_list: InclusionList) -> Result<InclusionList>;
}

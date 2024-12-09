use anyhow::Result;

use super::inclusion::InclusionList;

pub mod noop;

pub trait OrderingPhase {
    fn order(&self, decrypted_list: InclusionList) -> Result<InclusionList>;
}

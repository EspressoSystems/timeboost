use anyhow::Result;
use timeboost_core::types::{time::Timestamp, transaction::Transaction};

use super::inclusion::InclusionList;

pub mod canonical;
pub mod noop;

pub trait OrderingPhase {
    fn order(&self, decrypted_list: InclusionList) -> Result<(Timestamp, Vec<Transaction>)>;
}

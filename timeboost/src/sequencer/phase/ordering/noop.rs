use crate::sequencer::phase::inclusion::InclusionList;
use anyhow::Result;
use timeboost_core::types::{time::Timestamp, transaction::Transaction};

use super::OrderingPhase;

pub struct NoOpOrderingPhase;
impl OrderingPhase for NoOpOrderingPhase {
    fn order(&self, decrypted_list: InclusionList) -> Result<(Timestamp, Vec<Transaction>)> {
        Ok((decrypted_list.timestamp, decrypted_list.into_transactions()))
    }
}

use anyhow::Result;

use crate::types::message::SailfishEvent;

pub fn round_task(_event: SailfishEvent) -> Result<Vec<SailfishEvent>> {
    Ok(vec![])
}

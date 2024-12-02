use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

pub mod noop;

pub trait DecryptionPhase {
    fn decrypt(&self, inclusion_list: Vec<SailfishBlock>) -> Result<Vec<SailfishBlock>>;
}

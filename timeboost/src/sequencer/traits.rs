use anyhow::Result;
use timeboost_core::types::block::SailfishBlock;

pub trait OrderingPhase {
    fn order(&self, decrypted_list: Vec<SailfishBlock>) -> Result<Vec<SailfishBlock>>;
}

pub trait BlockBuilder {
    fn build(&self, ordered_transactions: Vec<SailfishBlock>) -> Result<SailfishBlock>;
}

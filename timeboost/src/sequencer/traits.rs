use anyhow::Result;
use timeboost_core::types::block::Block;

pub trait InclusionPhase {
    fn produce_inclusion_list(&self, candidate_list: Vec<Block>) -> Result<Vec<Block>>;
}

pub trait DecryptionPhase {
    fn decrypt(&self, inclusion_list: Vec<Block>) -> Result<Vec<Block>>;
}

pub trait OrderingPhase {
    fn order(&self, decrypted_list: Vec<Block>) -> Result<Vec<Block>>;
}

pub trait BlockBuilder {
    fn build(&self, ordered_transactions: Vec<Block>) -> Result<Block>;
}

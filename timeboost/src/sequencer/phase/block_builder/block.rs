use crate::sequencer::phase::inclusion::block::InclusionPhaseBlock;

pub struct TimeboostBlock {
    pub transactions: Vec<InclusionPhaseBlock>,
}

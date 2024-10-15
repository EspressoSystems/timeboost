use std::fmt::Display;

use hotshot::types::BLSPubKey;
use hotshot_types::data::ViewNumber;
use serde::{Deserialize, Serialize};

use super::block::Block;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vertex {
    /// The round of the vertex $v$ in the DAG.
    pub round: ViewNumber,

    /// The source that broadcasted this vertex $v$
    source: BLSPubKey,

    /// The block of transactions being transmitted
    block: Block,

    /// The at-least `2f + 1` vertices from round `r - 1`.
    strong_edges: u64,

    /// The up-to `f` vertices from round < `r - 1` such that there is no path
    /// from `v` to these vertices.
    weak_edges: u64,
}

impl Display for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vertex(round: {}, source: {})", self.round, self.source)
    }
}

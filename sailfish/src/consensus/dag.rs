use std::collections::{BTreeMap, BTreeSet};

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};

use crate::types::vertex::Vertex;

#[derive(Debug)]
pub struct Dag {
    elements: BTreeMap<ViewNumber, BTreeSet<Vertex>>,
}

impl Dag {
    pub fn new() -> Self {
        Self {
            elements: BTreeMap::new(),
        }
    }

    /// Is there a connection between two vertices?
    ///
    /// If `strong_only` is true, only strong edges are considered at each step.
    pub fn is_connected(&self, from: &Vertex, to: &Vertex, strong_only: bool) -> bool {
        let mut current = vec![from];
        for nodes in self
            .elements
            .range(ViewNumber::genesis()..from.id().round())
            .rev()
            .map(|e| e.1)
        {
            current = nodes
                .iter()
                .filter_map(|v| {
                    current
                        .iter()
                        .any(|x| {
                            if x.has_strong(v.id()) {
                                return true;
                            }
                            if !strong_only && x.has_weak(v.id()) {
                                return true;
                            }
                            false
                        })
                        .then_some(v)
                })
                .collect();

            if current.is_empty() {
                return false;
            }

            if current.contains(&to) {
                return true;
            }
        }
        false
    }
}

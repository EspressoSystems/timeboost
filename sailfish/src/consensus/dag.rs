use std::collections::BTreeMap;

use hotshot_types::{data::ViewNumber, traits::node_implementation::ConsensusTime};

use crate::types::{vertex::Vertex, PublicKey};

#[derive(Debug)]
pub struct Dag {
    elements: BTreeMap<ViewNumber, BTreeMap<PublicKey, Vertex>>,
}

impl Default for Dag {
    fn default() -> Self {
        Self::new()
    }
}

impl Dag {
    pub fn new() -> Self {
        Self {
            elements: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, v: Vertex) {
        let r = v.id().round();
        let s = v.id().source();
        self.elements.entry(r).or_default().insert(*s, v);
    }

    pub fn max_round(&self) -> Option<ViewNumber> {
        self.elements.keys().max().cloned()
    }

    pub fn vertices_from(&self, r: ViewNumber) -> impl Iterator<Item = &Vertex> + Clone {
        self.elements.range(r..).flat_map(|(_, m)| m.values())
    }

    pub fn vertices(&self, r: ViewNumber) -> impl Iterator<Item = &Vertex> + Clone {
        self.elements.get(&r).into_iter().flat_map(|m| m.values())
    }

    pub fn vertex(&self, r: ViewNumber, l: &PublicKey) -> Option<&Vertex> {
        self.elements.get(&r)?.get(l)
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
                .filter_map(|(_, v)| {
                    current
                        .iter()
                        .any(|x| {
                            if x.has_strong_edge(v.id()) {
                                return true;
                            }
                            if !strong_only && x.has_weak_edge(v.id()) {
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

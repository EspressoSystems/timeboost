use std::collections::BTreeMap;

use timeboost_core::types::{round_number::RoundNumber, vertex::Vertex, PublicKey};

#[derive(Debug)]
pub struct Dag {
    elements: BTreeMap<RoundNumber, BTreeMap<PublicKey, Vertex>>,
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
        let r = v.round();
        let s = v.source();
        self.elements.entry(r).or_default().insert(*s, v);
    }

    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    pub fn max_round(&self) -> Option<RoundNumber> {
        self.elements.keys().max().cloned()
    }

    pub fn vertices_from(&self, r: RoundNumber) -> impl Iterator<Item = &Vertex> + Clone {
        self.elements.range(r..).flat_map(|(_, m)| m.values())
    }

    pub fn vertices(&self, r: RoundNumber) -> impl Iterator<Item = &Vertex> + Clone {
        self.elements.get(&r).into_iter().flat_map(|m| m.values())
    }

    pub fn vertex(&self, r: RoundNumber, l: &PublicKey) -> Option<&Vertex> {
        self.elements.get(&r)?.get(l)
    }

    pub fn vertex_count(&self, r: RoundNumber) -> usize {
        self.elements.get(&r).map(|m| m.len()).unwrap_or(0)
    }

    /// Is there a connection between two vertices?
    ///
    /// If `strong_only` is true, only strong edges are considered at each step.
    pub fn is_connected(&self, from: &Vertex, to: &Vertex, strong_only: bool) -> bool {
        let mut current = vec![from];
        for nodes in self
            .elements
            .range(RoundNumber::genesis()..from.round())
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

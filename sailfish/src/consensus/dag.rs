use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::Hash,
    num::NonZeroUsize,
};

use timeboost_core::types::{round_number::RoundNumber, vertex::Vertex, PublicKey};
use tracing::instrument;

#[derive(Debug)]
pub struct Dag<T = PublicKey> {
    elements: BTreeMap<RoundNumber, HashMap<T, Vertex<T>>>,
    max_keys: NonZeroUsize,
}

impl<T: Clone + Eq + Hash> Dag<T> {
    pub fn new(max_keys: NonZeroUsize) -> Self {
        Self {
            elements: BTreeMap::new(),
            max_keys,
        }
    }

    pub fn add(&mut self, v: Vertex<T>) {
        debug_assert!(!self.contains(&v));
        let r = v.round();
        let s = v.source();
        let m = self.elements.entry(r).or_default();
        debug_assert!(m.len() < self.max_keys.get());
        m.insert(s.clone(), v);
    }

    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    pub fn max_round(&self) -> Option<RoundNumber> {
        self.elements.keys().max().cloned()
    }

    pub fn contains(&self, v: &Vertex<T>) -> bool {
        self.elements
            .get(&v.round())
            .map(|m| m.contains_key(v.source()))
            .unwrap_or(false)
    }

    pub fn vertices_from(&self, r: RoundNumber) -> impl Iterator<Item = &Vertex<T>> + Clone {
        self.elements.range(r..).flat_map(|(_, m)| m.values())
    }

    pub fn vertices(&self, r: RoundNumber) -> impl Iterator<Item = &Vertex<T>> + Clone {
        self.elements.get(&r).into_iter().flat_map(|m| m.values())
    }

    pub fn vertex(&self, r: RoundNumber, s: &T) -> Option<&Vertex<T>> {
        self.elements.get(&r)?.get(s)
    }

    pub fn vertex_count(&self, r: RoundNumber) -> usize {
        self.elements.get(&r).map(|m| m.len()).unwrap_or(0)
    }

    /// Is there a connection between two vertices?
    pub fn is_connected(&self, from: &Vertex<T>, to: &Vertex<T>) -> bool {
        let mut current = vec![from];
        for nodes in self
            .elements
            .range(RoundNumber::genesis()..from.round())
            .rev()
            .map(|e| e.1)
        {
            current = nodes
                .iter()
                .filter_map(|(_, v)| current.iter().any(|x| x.has_edge(v.source())).then_some(v))
                .collect();

            if current.is_empty() {
                break;
            }

            if current.contains(&to) {
                return true;
            }
        }
        false
    }

    /// Remove the vertex denoted by the given ID from the DAG.
    ///
    /// If this removes the last vertex of a source in a round, the whole entry is removed.
    fn remove(&mut self, r: RoundNumber, s: &T) {
        let Some(m) = self.elements.get_mut(&r) else {
            return;
        };
        m.remove(s);
        if m.is_empty() {
            self.elements.remove(&r);
        }
    }

    /// Remove vertices from rounds < r if they are not referenced in rounds >= r.
    #[instrument(level = "trace", skip(self))]
    pub fn prune(&mut self, r: RoundNumber) {
        // Consider all IDs from rounds < r:
        let candidates: HashSet<(RoundNumber, T)> = self
            .elements
            .range(RoundNumber::genesis()..r)
            .flat_map(|(r, m)| m.values().map(|v| (*r, v.source().clone())))
            .collect();

        // We can remove those IDs which are not referenced from vertices in rounds >= r:
        let to_remove = self.vertices_from(r).fold(candidates, |mut set, v| {
            for e in v.edges() {
                set.remove(&(v.round(), e.clone()));
            }
            set
        });

        for (r, s) in to_remove {
            self.remove(r, &s)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use timeboost_core::types::vertex::Vertex;

    use crate::consensus::Dag;

    #[test]
    fn test_is_connected() {
        let mut dag = Dag::new(NonZeroUsize::new(10).unwrap());

        let pk1 = "pk1";
        let pk2 = "pk2";
        let pk3 = "pk3";
        let pk4 = "pk4";
        let pk5 = "pk5";

        // Layer 1
        let v11 = Vertex::new(1, pk1);
        let v12 = Vertex::new(1, pk2);
        let v13 = Vertex::new(1, pk3);
        let v14 = Vertex::new(1, pk4);
        let v15 = Vertex::new(1, pk5);

        // Layer 2
        let mut v21 = Vertex::new(2, pk1);
        let mut v22 = Vertex::new(2, pk2);
        let mut v23 = Vertex::new(2, pk3);

        // Layer 3
        let mut v31 = Vertex::new(3, pk1);
        let mut v32 = Vertex::new(3, pk2);
        let mut v33 = Vertex::new(3, pk3);

        // Layer 4
        let mut v41 = Vertex::new(4, pk1);

        v41.add_edges([*v31.source(), *v32.source(), *v33.source()]);

        v31.add_edges([*v21.source(), *v22.source(), *v23.source()]);
        v32.add_edges([*v21.source(), *v22.source(), *v23.source()]);
        v33.add_edges([*v21.source(), *v22.source(), *v23.source()]);

        v21.add_edges([*v11.source(), *v12.source(), *v13.source()]);
        v22.add_edges([*v11.source(), *v12.source(), *v13.source()]);
        v23.add_edges([*v12.source(), *v13.source(), *v14.source()]);

        [
            v11.clone(),
            v12,
            v13,
            v14,
            v15.clone(),
            v21,
            v22,
            v23,
            v31,
            v32,
            v33.clone(),
            v41.clone(),
        ]
        .into_iter()
        .for_each(|v| dag.add(v.clone()));

        // v41 has a path to v11
        assert!(dag.is_connected(&v41, &v11));
        // v41 has no path to v15
        assert!(!dag.is_connected(&v41, &v15));
    }
}

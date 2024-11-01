use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    num::NonZeroUsize,
};

use either::Either;
use timeboost_core::types::{
    round_number::RoundNumber,
    vertex::{Vertex, VertexId},
    PublicKey,
};
use tracing::instrument;

#[derive(Debug)]
pub struct Dag {
    elements: BTreeMap<RoundNumber, BTreeMap<PublicKey, Vertex>>,
    max_keys: NonZeroUsize,
}

impl Dag {
    pub fn new(max_keys: NonZeroUsize) -> Self {
        Self {
            elements: BTreeMap::new(),
            max_keys,
        }
    }

    pub fn add(&mut self, v: Vertex) {
        debug_assert!(!self.contains(v.id()));
        let r = v.round();
        let s = v.source();
        let m = self.elements.entry(r).or_default();
        debug_assert!(m.len() < self.max_keys.get());
        m.insert(*s, v);
    }

    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    pub fn max_round(&self) -> Option<RoundNumber> {
        self.elements.keys().max().cloned()
    }

    pub fn contains(&self, v: &VertexId) -> bool {
        self.elements
            .get(&v.round())
            .map(|m| m.contains_key(v.source()))
            .unwrap_or(false)
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

    /// BFS to check if there is a path from `from` to `to`.
    /// If `strong_only` is true, only strong edges are considered at each step.
    pub fn is_connected(&self, from: &Vertex, to: &Vertex, strong_only: bool) -> bool {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        visited.insert(from.id());
        queue.push_back(from);
        while let Some(current) = queue.pop_front() {
            if current == to {
                return true;
            }

            let edges = if strong_only {
                Either::Right(current.strong_edges())
            } else {
                Either::Left(current.strong_edges().chain(current.weak_edges()))
            };

            for edge in edges {
                if visited.insert(edge) {
                    if let Some(v) = self.vertex(edge.round(), edge.source()) {
                        queue.push_back(v);
                    }
                }
            }
        }
        false
    }

    /// Remove the vertex denoted by the given ID from the DAG.
    ///
    /// If this removes the last vertex of a source in a round, the whole entry is removed.
    #[instrument(level = "trace", skip(self))]
    fn remove(&mut self, id: &VertexId) {
        let Some(m) = self.elements.get_mut(&id.round()) else {
            return;
        };
        m.remove(id.source());
        if m.is_empty() {
            self.elements.remove(&id.round());
        }
    }

    /// Remove vertices from rounds < r if they are not referenced in rounds >= r.
    #[instrument(level = "trace", skip(self))]
    pub fn prune(&mut self, r: RoundNumber) {
        // Consider all IDs from rounds < r:
        let candidates: HashSet<VertexId> = self
            .elements
            .range(RoundNumber::genesis()..r)
            .flat_map(|(_, m)| m.values().map(|v| *v.id()))
            .collect();

        // We can remove those IDs which are not referenced from vertices in rounds >= r:
        let to_remove = self.vertices_from(r).fold(candidates, |mut set, v| {
            for e in v.strong_edges().chain(v.weak_edges()) {
                set.remove(e);
            }
            set
        });

        for id in &to_remove {
            self.remove(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use hotshot::types::SignatureKey;
    use rand::Rng;
    use std::num::NonZeroUsize;

    use timeboost_core::types::{round_number::RoundNumber, vertex::Vertex, PublicKey};

    use crate::consensus::Dag;

    fn create_vertex(round: u64, source: PublicKey) -> Vertex {
        Vertex::new(RoundNumber::new(round), source)
    }

    #[test]
    fn test_is_connected() {
        let max_keys = NonZeroUsize::new(10).unwrap();
        let mut dag = Dag::new(max_keys);
        let pk1 = generate_random_public_key();
        let pk2 = generate_random_public_key();
        let pk3 = generate_random_public_key();
        let pk4 = generate_random_public_key();
        let pk5 = generate_random_public_key();

        // Layer 1
        let v11 = create_vertex(1, pk1);
        let v12 = create_vertex(1, pk2);
        let v13 = create_vertex(1, pk3);
        let v14 = create_vertex(1, pk4);
        let v15 = create_vertex(1, pk5);

        // Layer 2
        let mut v21 = create_vertex(2, pk1);
        let mut v22 = create_vertex(2, pk2);
        let mut v23 = create_vertex(2, pk3);

        // Layer 3
        let mut v31 = create_vertex(3, pk1);
        let mut v32 = create_vertex(3, pk2);
        let mut v33 = create_vertex(3, pk3);

        // Layer 4
        let mut v41 = create_vertex(4, pk1);

        v41.add_strong_edges(vec![*v31.id(), *v32.id(), *v33.id()]);

        v31.add_strong_edges(vec![*v21.id(), *v22.id(), *v23.id()]);
        v32.add_strong_edges(vec![*v21.id(), *v22.id(), *v23.id()]);
        v33.add_strong_edges(vec![*v21.id(), *v22.id(), *v23.id()]);
        v33.add_weak_edge(*v15.id());

        v21.add_strong_edges(vec![*v11.id(), *v12.id(), *v13.id()]);
        v22.add_strong_edges(vec![*v11.id(), *v12.id(), *v13.id()]);
        v23.add_strong_edges(vec![*v12.id(), *v13.id(), *v14.id()]);

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

        // v41 has a strong path to v11
        assert!(dag.is_connected(&v41, &v11, true));
        // v41 has no strong path to v15
        assert!(!dag.is_connected(&v41, &v15, true));
        // v41 has a weak path to v15
        assert!(dag.is_connected(&v41, &v15, false));
    }

    fn generate_random_public_key() -> PublicKey {
        let mut rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        let priv_key = PublicKey::generated_from_seed_indexed(seed, 0).1;
        PublicKey::from_private(&priv_key)
    }
}

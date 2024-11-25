use std::{collections::BTreeMap, num::NonZeroUsize, ops::RangeBounds};

use serde::{Deserialize, Serialize};
use timeboost_core::types::{vertex::Vertex, PublicKey};
use timeboost_util::types::round_number::RoundNumber;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Adds a new vertex to the DAG in its corresponding round and source position
    pub fn add(&mut self, v: Vertex) {
        debug_assert!(!self.contains(&v));
        let r = v.round();
        let s = v.source();
        let m = self.elements.entry(r).or_default();
        debug_assert!(m.len() < self.max_keys.get());
        m.insert(*s, v);
    }

    /// Removes all rounds up to (and including) the specified round number from the DAG
    pub fn remove(&mut self, r: RoundNumber) {
        self.elements = self.elements.split_off(&r);
    }

    /// Returns the total number of rounds present in the DAG
    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    /// Returns an iterator over all round numbers present in the DAG
    pub fn rounds(&self) -> impl Iterator<Item = RoundNumber> + '_ {
        self.elements.keys().copied()
    }

    /// Returns the highest round number present in the DAG, if any
    pub fn max_round(&self) -> Option<RoundNumber> {
        self.elements.keys().max().cloned()
    }

    /// Checks if a specific vertex exists in the DAG
    pub fn contains(&self, v: &Vertex) -> bool {
        self.elements
            .get(&v.round())
            .map(|m| m.contains_key(v.source()))
            .unwrap_or(false)
    }

    /// Returns an iterator over all vertices in a specific round
    pub fn vertices(&self, r: RoundNumber) -> impl Iterator<Item = &Vertex> + Clone {
        self.elements.get(&r).into_iter().flat_map(|m| m.values())
    }

    /// Retrieves a specific vertex by its round number and source public key
    pub fn vertex(&self, r: RoundNumber, s: &PublicKey) -> Option<&Vertex> {
        self.elements.get(&r)?.get(s)
    }

    /// Returns an iterator over all vertices within the specified round range.
    ///
    /// This method allows iteration over vertices across multiple rounds using any valid range syntax:
    /// - `vertex_range(1..4)` - vertices from rounds 1,2,3
    /// - `vertex_range(1..=4)` - vertices from rounds 1,2,3,4
    /// - `vertex_range(1..)` - vertices from round 1 onwards
    /// - `vertex_range(..4)` - vertices from all rounds before 4
    ///
    /// The implementation:
    /// 1. Uses BTreeMap's range() to get rounds within the specified bounds
    /// 2. For each round, flattens its map of vertices into a single iterator
    /// 3. Combines all rounds' vertices into a single sequential iterator
    pub fn vertex_range<R>(&self, r: R) -> impl Iterator<Item = &Vertex> + Clone
    where
        R: RangeBounds<RoundNumber>,
    {
        self.elements.range(r).flat_map(|(_, m)| m.values())
    }

    /// Returns the number of vertices present in a specific round
    pub fn vertex_count(&self, r: RoundNumber) -> usize {
        self.elements.get(&r).map(|m| m.len()).unwrap_or(0)
    }

    /// Is there a connection between two vertices?
    pub fn is_connected(&self, from: &Vertex, to: &Vertex) -> bool {
        let mut current = vec![from];
        for nodes in self.elements.range(..from.round()).rev().map(|e| e.1) {
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

    pub fn dbg_dag(&self) {
        for (r, e) in &self.elements {
            println!("{r} -> {{");
            for v in e.values() {
                print!("  ");
                v.dbg_edges();
            }
            println!("}}")
        }
    }

    pub fn max_keys(&self) -> NonZeroUsize {
        self.max_keys
    }

    pub fn to_entries(&self) -> impl Iterator<Item = (&RoundNumber, &PublicKey, &Vertex)> {
        self.elements
            .iter()
            .flat_map(|(r, map)| map.iter().map(move |(pk, v)| (r, pk, v)))
    }

    pub fn from_entries<I>(entries: I, max_keys: NonZeroUsize) -> Self
    where
        I: IntoIterator<Item = (RoundNumber, PublicKey, Vertex)>,
    {
        let mut dag = Self::new(max_keys);
        for (_, _, vertex) in entries {
            dag.add(vertex);
        }
        dag
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use timeboost_core::types::{vertex::Vertex, Keypair};

    use crate::consensus::Dag;

    #[test]
    fn test_is_connected() {
        let mut dag = Dag::new(NonZeroUsize::new(10).unwrap());

        let pk1 = *Keypair::random().public_key();
        let pk2 = *Keypair::random().public_key();
        let pk3 = *Keypair::random().public_key();
        let pk4 = *Keypair::random().public_key();
        let pk5 = *Keypair::random().public_key();

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

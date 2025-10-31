use std::{collections::BTreeMap, fmt, ops::RangeBounds};

use multisig::{Committee, KeyId, PublicKey};
use sailfish_types::{RoundNumber, Vertex};

#[derive(Debug, Clone)]
pub struct Dag<T> {
    committee: Committee,
    elements: BTreeMap<RoundNumber, BTreeMap<KeyId, Vertex<T>>>,
}

impl<T: PartialEq> Dag<T> {
    /// Create a new empty DAG.
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            elements: BTreeMap::new(),
        }
    }

    /// Adds a new vertex to the DAG in its corresponding round and source position
    pub fn add(&mut self, v: Vertex<T>) {
        debug_assert!(!self.contains(&v));
        let r = v.round().data().num();
        let s = v.source().0;
        let m = self.elements.entry(r).or_default();
        debug_assert!(m.len() < self.committee.size().get());
        m.insert(s, v);
    }

    /// Removes all rounds up to the specified round number from the DAG
    pub fn remove(&mut self, r: RoundNumber) {
        self.elements = self.elements.split_off(&r);
    }

    /// Is this DAG empty?
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Returns the total number of rounds present in the DAG
    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    /// Returns an iterator over all round numbers present in the DAG
    pub fn rounds(&self) -> impl Iterator<Item = RoundNumber> + '_ {
        self.elements.keys().copied()
    }

    /// Returns the highest round number present in the DAG, if any.
    pub fn max_round(&self) -> Option<RoundNumber> {
        self.elements.keys().max().copied()
    }

    /// Returns the lowest round number present in the DAG, if any.
    pub fn min_round(&self) -> Option<RoundNumber> {
        self.elements.keys().min().copied()
    }

    /// Checks if a specific vertex exists in the DAG
    pub fn contains(&self, v: &Vertex<T>) -> bool {
        self.elements
            .get(&v.round().data().num())
            .map(|m| m.contains_key(&v.source().0))
            .unwrap_or(false)
    }

    /// Returns an iterator over all vertices in a specific round
    pub fn vertices(&self, r: RoundNumber) -> impl Iterator<Item = &Vertex<T>> + Clone {
        self.elements.get(&r).into_iter().flat_map(|m| m.values())
    }

    /// Retrieves a specific vertex by its round number and source public key
    pub fn vertex(&self, r: RoundNumber, s: &KeyId) -> Option<&Vertex<T>> {
        self.elements.get(&r)?.get(s)
    }

    /// Consume the DAG as an iterator over its elements.
    pub fn drain(&mut self) -> impl Iterator<Item = (RoundNumber, PublicKey, Vertex<T>)> + '_ {
        std::mem::take(&mut self.elements)
            .into_iter()
            .flat_map(move |(r, map)| {
                let com: Committee = self.committee.clone();
                map.into_iter().map(move |(ix, v)| {
                    let pk = com.get_key(ix).unwrap();
                    (r, *pk, v)
                })
            })
    }

    /// Remove elements at a given round and return iterator over the values
    pub fn drain_round(&mut self, r: RoundNumber) -> impl Iterator<Item = Vertex<T>> {
        self.elements
            .remove(&r)
            .into_iter()
            .flat_map(|m| m.into_values())
    }

    /// Returns an iterator over all vertices within the specified round range.
    ///
    /// This method allows iteration over vertices across multiple rounds using any valid range
    /// syntax:
    /// - `vertex_range(1..4)` - vertices from rounds 1,2,3
    /// - `vertex_range(1..=4)` - vertices from rounds 1,2,3,4
    /// - `vertex_range(1..)` - vertices from round 1 onwards
    /// - `vertex_range(..4)` - vertices from all rounds before 4
    ///
    /// The implementation:
    /// 1. Uses BTreeMap's range() to get rounds within the specified bounds
    /// 2. For each round, flattens its map of vertices into a single iterator
    /// 3. Combines all rounds' vertices into a single sequential iterator
    pub fn vertex_range<R>(&self, r: R) -> impl Iterator<Item = &Vertex<T>> + Clone
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
    pub fn is_connected(&self, from: &Vertex<T>, to: &Vertex<T>) -> bool {
        let mut current = vec![from];
        for nodes in self
            .elements
            .range(..from.round().data().num())
            .rev()
            .map(|e| e.1)
        {
            current = nodes
                .iter()
                .filter_map(|(_, v)| {
                    current
                        .iter()
                        .any(|x| x.has_edge(&v.source().0))
                        .then_some(v)
                })
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

    /// Iterate over the DAG elements.
    pub fn iter(&self) -> impl Iterator<Item = (&RoundNumber, &PublicKey, &Vertex<T>)> {
        self.elements.iter().flat_map(move |(r, map)| {
            map.iter().map(move |(ix, v)| {
                let pk = self.committee.get_key(*ix).unwrap();
                (r, pk, v)
            })
        })
    }
}

impl<T: fmt::Display> Dag<T> {
    /// Create a string representation of the DAG for debugging purposes.
    pub fn dbg(&self) -> String {
        let mut s = String::from("\n\n");
        for (r, e) in &self.elements {
            s += &format!("{r} -> {{\n");
            for v in e.values() {
                s += &format!("  {}\n", v.dbg())
            }
            s += "}\n"
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use multisig::{Committee, KeyId, Keypair, Signed, VoteAccumulator};

    use sailfish_types::{Round, Unit, Vertex};

    use super::Dag;

    #[test]
    fn test_is_connected() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let kp3 = Keypair::generate();
        let kp4 = Keypair::generate();
        let kp5 = Keypair::generate();

        let kid1 = KeyId::from(1);
        let kid2 = KeyId::from(2);
        let kid3 = KeyId::from(3);
        let kid4 = KeyId::from(4);
        let kid5 = KeyId::from(5);

        let com = Committee::new(
            0,
            [
                (1, kp1.public_key()),
                (2, kp2.public_key()),
                (3, kp3.public_key()),
                (4, kp4.public_key()),
                (5, kp5.public_key()),
            ],
        );
        let mut dag: Dag<Unit> = Dag::<Unit>::new(com.clone());

        let gen_evidence = |r: u64| {
            let mut va = VoteAccumulator::new(com.clone());
            va.add(Signed::new(Round::new(r, 0), &kp1)).unwrap();
            va.add(Signed::new(Round::new(r, 0), &kp2)).unwrap();
            va.add(Signed::new(Round::new(r, 0), &kp3)).unwrap();
            va.add(Signed::new(Round::new(r, 0), &kp4)).unwrap();
            va.add(Signed::new(Round::new(r, 0), &kp5)).unwrap();
            va.into_certificate().unwrap()
        };

        // Layer 1
        let v11 = Vertex::new(Round::new(1, 0), gen_evidence(0), Unit, kid1, &kp1);
        let v12 = Vertex::new(Round::new(1, 0), gen_evidence(0), Unit, kid2, &kp2);
        let v13 = Vertex::new(Round::new(1, 0), gen_evidence(0), Unit, kid3, &kp3);
        let v14 = Vertex::new(Round::new(1, 0), gen_evidence(0), Unit, kid4, &kp4);
        let v15 = Vertex::new(Round::new(1, 0), gen_evidence(0), Unit, kid5, &kp5);

        // Layer 2
        let mut v21 = Vertex::new(Round::new(2, 0), gen_evidence(1), Unit, kid1, &kp1);
        let mut v22 = Vertex::new(Round::new(2, 0), gen_evidence(1), Unit, kid2, &kp2);
        let mut v23 = Vertex::new(Round::new(2, 0), gen_evidence(1), Unit, kid3, &kp3);

        // Layer 3
        let mut v31 = Vertex::new(Round::new(3, 0), gen_evidence(2), Unit, kid1, &kp1);
        let mut v32 = Vertex::new(Round::new(3, 0), gen_evidence(2), Unit, kid2, &kp2);
        let mut v33 = Vertex::new(Round::new(3, 0), gen_evidence(2), Unit, kid3, &kp3);

        // Layer 4
        let mut v41 = Vertex::new(Round::new(4, 0), gen_evidence(3), Unit, kid1, &kp1);

        v41.add_edges([v31.source().0, v32.source().0, v33.source().0]);

        v31.add_edges([v21.source().0, v22.source().0, v23.source().0]);
        v32.add_edges([v21.source().0, v22.source().0, v23.source().0]);
        v33.add_edges([v21.source().0, v22.source().0, v23.source().0]);

        v21.add_edges([v11.source().0, v12.source().0, v13.source().0]);
        v22.add_edges([v11.source().0, v12.source().0, v13.source().0]);
        v23.add_edges([v12.source().0, v13.source().0, v14.source().0]);

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

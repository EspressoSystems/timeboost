use std::num::NonZeroUsize;

#[derive(Debug)]
pub struct NodeInfo<K, V> {
    nodes: Vec<(K, V)>,
    quorum: NonZeroUsize,
}

impl<K, V> NodeInfo<K, V> {
    pub fn new(quorum: NonZeroUsize) -> Self {
        Self {
            nodes: Vec::new(),
            quorum,
        }
    }
}

impl<K: PartialOrd, V: PartialOrd> NodeInfo<K, V> {
    pub fn record(&mut self, k: K, v: V) {
        self.nodes.retain(|(p, _)| *p != k);

        let i = self
            .nodes
            .iter()
            .position(|(_, r)| v >= *r)
            .unwrap_or(self.nodes.len());

        self.nodes.insert(i, (k, v));

        debug_assert!({
            let it = self.nodes.iter().map(|(_, r)| r);
            it.clone().zip(it.skip(1)).all(|(a, b)| a >= b)
        });
    }

    pub fn records(&self) -> &[(K, V)] {
        &self.nodes
    }

    /// Gets the lower bound of the highest quorum interval.
    pub fn quorum(&self) -> Option<&V> {
        if self.nodes.len() < self.quorum.get() {
            return None;
        }
        Some(&self.nodes[self.quorum.get() - 1].1)
    }

    /// Gets the upper bound of the lowest quorum interval.
    pub fn quorum_rev(&self) -> Option<&V> {
        if self.nodes.len() < self.quorum.get() {
            return None;
        }
        Some(&self.nodes[self.nodes.len() - self.quorum.get()].1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::{TestResult, quickcheck};
    use std::collections::HashMap;

    #[test]
    fn example() {
        let mut n = NodeInfo::new(quorum(5));
        assert!(n.quorum().is_none());
        assert!(n.quorum_rev().is_none());

        n.record(0, 123);
        assert!(n.quorum().is_none());
        assert!(n.quorum_rev().is_none());

        n.record(1, 482);
        assert!(n.quorum().is_none());
        assert!(n.quorum_rev().is_none());

        n.record(2, 183);
        assert!(n.quorum().is_none());
        assert!(n.quorum_rev().is_none());

        n.record(3, 936);
        assert_eq!(123, n.quorum().copied().unwrap_or_default());
        assert_eq!(936, n.quorum_rev().copied().unwrap_or_default());

        n.record(4, 645);
        assert_eq!(183, n.quorum().copied().unwrap_or_default());
        assert_eq!(645, n.quorum_rev().copied().unwrap_or_default());
    }

    quickcheck! {
        fn prop_quorum(input: HashMap<u8, u64>) -> TestResult {
            if input.is_empty() {
                return TestResult::discard()
            }
            let mut info = NodeInfo::new(quorum(input.len()));
            for (k, v) in &input {
                info.record(*k, *v)
            }
            let mut v: Vec<u64> = input.values().copied().collect();
            v.sort();
            TestResult::from_bool(info.quorum().copied() == Some(v[v.len() - quorum(v.len()).get()]))
        }

        fn prop_quorum_rev(input: HashMap<u8, u64>) -> TestResult {
            if input.is_empty() {
                return TestResult::discard()
            }
            let mut info = NodeInfo::new(quorum(input.len()));
            for (k, v) in &input {
                info.record(*k, *v)
            }
            let mut v: Vec<u64> = input.values().copied().collect();
            v.sort();
            TestResult::from_bool(info.quorum_rev().copied() == Some(v[quorum(v.len()).get() - 1]))
        }
    }

    fn quorum(n: usize) -> NonZeroUsize {
        debug_assert!(n > 0);
        NonZeroUsize::new(n * 2 / 3 + 1).expect("n + 1 > 0")
    }
}

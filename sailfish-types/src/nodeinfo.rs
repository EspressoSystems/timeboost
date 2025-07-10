use multisig::{Committee, PublicKey};

#[derive(Debug)]
pub struct NodeInfo<T> {
    nodes: Vec<(PublicKey, T)>,
    quorum: usize,
}

impl<T: Default + PartialOrd + Clone> NodeInfo<T> {
    pub fn new(c: &Committee) -> Self {
        Self {
            nodes: c.parties().map(|k| (*k, T::default())).collect(),
            quorum: c.quorum_size().get(),
        }
    }

    /// Store a value of a party.
    pub fn record(&mut self, k: &PublicKey, new: T) -> bool {
        let Some(i) = self.nodes.iter().position(|(p, _)| p == k) else {
            return false;
        };

        if new <= self.nodes[i].1 {
            return true;
        }

        self.nodes.remove(i);

        let i = self
            .nodes
            .iter()
            .position(|(_, r)| new >= *r)
            .unwrap_or(self.nodes.len());

        self.nodes.insert(i, (*k, new));

        debug_assert!({
            let it = self.nodes.iter().map(|(_, r)| r);
            it.clone().zip(it.skip(1)).all(|(a, b)| a >= b)
        });

        true
    }

    /// Gets the lower bound of the highest quorum interval.
    pub fn quorum(&self) -> T {
        debug_assert!(self.quorum <= self.nodes.len());
        self.nodes[self.quorum - 1].1.clone()
    }
}

use multisig::{Committee, PublicKey};
use timeboost_utils::types::round_number::RoundNumber;

/// Information about nodes.
#[derive(Debug)]
pub struct NodeInfo {
    /// Associative list of public key to committed round number.
    nodes: Vec<(PublicKey, RoundNumber)>,
    /// The quorum size of the nodes.
    quorum: usize,
}

impl NodeInfo {
    pub fn new(c: &Committee) -> Self {
        Self {
            nodes: c.parties().map(|k| (*k, RoundNumber::genesis())).collect(),
            quorum: c.quorum_size().get(),
        }
    }

    pub fn set_committed_round(&mut self, k: &PublicKey, new: RoundNumber) -> bool {
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
            let it = self.nodes.iter().map(|(_, r)| *r);
            it.clone().zip(it.skip(1)).all(|(a, b)| a >= b)
        });

        true
    }

    pub fn committed_round_quorum(&self) -> RoundNumber {
        debug_assert!(self.quorum <= self.nodes.len());
        self.nodes[self.quorum - 1].1
    }
}

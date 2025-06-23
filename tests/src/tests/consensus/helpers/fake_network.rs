use multisig::PublicKey;
use sailfish::types::{Evidence, RoundNumber};
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

use super::{interceptor::Interceptor, node_instrument::TestNodeInstrument};
use crate::prelude::*;

/// Mock the network
pub struct FakeNetwork {
    pub(crate) nodes: HashMap<PublicKey, TestNodeInstrument>,
    msg_interceptor: Interceptor,
}

impl FakeNetwork {
    pub(crate) fn new(
        nodes: HashMap<PublicKey, TestNodeInstrument>,
        msg_interceptor: Interceptor,
    ) -> Self {
        Self {
            nodes,
            msg_interceptor,
        }
    }

    pub(crate) fn start(&mut self) {
        let mut next = Vec::new();
        let committee_size = NonZeroUsize::new(self.nodes.len()).unwrap();
        for node_instrument in self.nodes.values_mut() {
            let node = node_instrument.node_mut();
            for a in node.go(Dag::new(committee_size), Evidence::Genesis) {
                Self::handle_action(a, &mut next)
            }
        }
        self.dispatch(next)
    }

    pub(crate) fn consensus(&self) -> impl Iterator<Item = &Consensus> {
        self.nodes.values().map(|c| c.node())
    }

    pub(crate) fn current_round(&self) -> RoundNumber {
        self.nodes
            .values()
            .map(|node_instrument| node_instrument.node().round())
            .max()
            .unwrap()
    }

    pub(crate) fn leader_for_round(&self, round: RoundNumber) -> PublicKey {
        self.nodes
            .values()
            .next()
            .expect("at least one node exists")
            .committee()
            .leader(*round as usize)
    }

    pub(crate) fn leader(&self, round: RoundNumber) -> &Consensus {
        let key = self.leader_for_round(round);
        self.nodes.get(&key).map(|n| n.node()).unwrap()
    }

    /// Process the current message on the queue
    /// Push the next messages after processing
    pub(crate) fn process(&mut self) {
        let mut next_msgs = Vec::new();
        for node_handle in self.nodes.values_mut() {
            while let Some(msg) = node_handle.pop_msg() {
                for a in Self::handle_message(node_handle, msg, &self.msg_interceptor) {
                    Self::handle_action(a, &mut next_msgs);
                }
            }
        }
        self.dispatch(next_msgs);
    }

    /// Look in each node and grab their queue of messages
    /// Used for asserting in tests to make sure outputs are expected
    pub(crate) fn msgs_in_queue(&self) -> HashMap<PublicKey, &VecDeque<Message>> {
        self.nodes
            .iter()
            .map(|(key, node_instrument)| (*key, node_instrument.msg_queue()))
            .collect()
    }

    /// Handle a message, and apply any transformations as setup in the test
    fn handle_message(
        node_handle: &mut TestNodeInstrument,
        msg: Message,
        interceptor: &Interceptor,
    ) -> Vec<Action> {
        let msgs = interceptor.intercept_message(msg, node_handle);
        let mut actions = Vec::new();
        let n = node_handle.node_mut();
        for msg in msgs {
            actions.extend(n.handle_message(msg));
        }
        actions
    }

    fn dispatch(&mut self, msgs: Vec<(Option<PublicKey>, Message)>) {
        for m in msgs {
            match m {
                (None, msg) => {
                    for node_instrument in self.nodes.values_mut() {
                        node_instrument.add_msg(msg.clone());
                    }
                }
                (Some(pub_key), msg) => {
                    let node_instrument = self.nodes.get_mut(&pub_key).unwrap();
                    node_instrument.add_msg(msg);
                }
            }
        }
    }

    fn handle_action(a: Action, msgs: &mut Vec<(Option<PublicKey>, Message)>) {
        let msg = match a {
            Action::ResetTimer(_)
            | Action::Deliver(_)
            | Action::Gc(_)
            | Action::Catchup(_)
            | Action::UseCommittee(..) => {
                return;
            }
            Action::SendNoVote(to, e) => (Some(to), Message::NoVote(e)),
            Action::SendProposal(e) => (None, Message::Vertex(e)),
            Action::SendTimeout(e) => (None, Message::Timeout(e)),
            Action::SendTimeoutCert(c) => (None, Message::TimeoutCert(c)),
            Action::SendHandover(e) => (None, Message::Handover(e)),
            Action::SendHandoverCert(c) => (None, Message::HandoverCert(c)),
        };
        msgs.push(msg)
    }
}

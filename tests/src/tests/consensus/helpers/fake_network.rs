use sailfish::consensus::{Consensus, Dag};
use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroUsize,
};
use timeboost_core::types::{
    message::{Action, Message},
    round_number::RoundNumber,
    NodeId, PublicKey,
};
use tracing::info;

use super::{
    interceptor::Interceptor, node_instrument::TestNodeInstrument,
    test_helpers::create_timeout_vote_action,
};

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
            let node_state = &mut node_instrument.node;
            for a in node_state.go(Dag::new(committee_size)) {
                Self::handle_action(node_state.id(), a, &mut next)
            }
        }
        self.dispatch(next)
    }

    pub(crate) fn consensus(&self) -> impl Iterator<Item = &Consensus> {
        self.nodes.values().map(|c| &c.node)
    }

    pub(crate) fn current_round(&self) -> RoundNumber {
        self.nodes
            .values()
            .map(|node_instrument| node_instrument.node.round())
            .max()
            .unwrap()
    }

    pub(crate) fn leader_for_round(&self, round: RoundNumber) -> PublicKey {
        self.nodes
            .values()
            .map(|node_instrument| node_instrument.node.committee().leader(round))
            .max()
            .unwrap()
    }

    pub(crate) fn leader(&self, round: RoundNumber) -> &Consensus {
        let key = self
            .nodes
            .values()
            .next()
            .expect("at least one node exists")
            .node
            .committee()
            .leader(round);
        self.consensus().find(|c| c.public_key() == &key).unwrap()
    }

    /// Process the current message on the queue
    /// Push the next messages after processing
    pub(crate) fn process(&mut self) {
        let mut next_msgs = Vec::new();
        for node_instrument in self.nodes.values_mut() {
            let state = &mut node_instrument.node;
            let msg_queue = &mut node_instrument.msg_queue;
            let mut actions_processed = Vec::new();
            while let Some(msg) = msg_queue.pop_front() {
                for a in Self::handle_message(state, msg, &self.msg_interceptor, msg_queue) {
                    // node_instrument.handle_action(a);
                    actions_processed.push(a.clone());
                    Self::handle_action(state.id(), a, &mut next_msgs);
                }
            }
            node_instrument.handle_action(actions_processed);
        }
        self.dispatch(next_msgs);
    }

    /// Look in each node and grab their queue of messages
    /// Used for asserting in tests to make sure outputs are expected
    pub(crate) fn msgs_in_queue(&self) -> HashMap<NodeId, VecDeque<Message>> {
        let nodes_msgs = self
            .nodes
            .values()
            .map(|node_instrument| (node_instrument.node.id(), node_instrument.msg_queue.clone()))
            .collect();
        nodes_msgs
    }

    pub(crate) fn timeout_round(&mut self, round: RoundNumber) {
        let mut msgs: Vec<(Option<PublicKey>, Message)> = Vec::new();
        for node_instrument in self.nodes.values_mut() {
            let mut keep = VecDeque::new();
            while let Some(msg) = node_instrument.msg_queue.pop_front() {
                if let Message::Vertex(v) = msg.clone() {
                    // TODO: Byzantine framework to simulate a dishonest leader who doesnt propose
                    // To simulate a timeout we just drop the message with the leader vertex
                    // We still keep the other vertices from non leader nodes so we will have 2f + 1 vertices
                    // And be able to propose a vertex with timeout cert
                    if *v.signing_key() == node_instrument.node.committee().leader(v.data().round())
                    {
                        continue;
                    }
                }

                // Keep the message if it is not a vertex or if it is a vertex from a non-leader
                keep.push_back(msg);
            }
            node_instrument.msg_queue.extend(keep);

            let timeout_action = create_timeout_vote_action(
                round,
                *node_instrument.node.public_key(),
                node_instrument.node.private_key(),
            );

            // Process timeout actions
            Self::handle_action(node_instrument.node.id(), timeout_action, &mut msgs);
        }

        // Send out msgs
        self.dispatch(msgs);
    }

    /// Handle a message, and apply any transformations as setup in the test
    fn handle_message(
        node: &mut Consensus,
        msg: Message,
        interceptor: &Interceptor,
        queue: &mut VecDeque<Message>,
    ) -> Vec<Action> {
        let msgs = interceptor.intercept_message(msg, node.committee(), queue);
        let mut actions = Vec::new();
        for msg in msgs {
            actions.extend(node.handle_message(msg));
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

    fn handle_action(node: NodeId, a: Action, msgs: &mut Vec<(Option<PublicKey>, Message)>) {
        let msg = match a {
            Action::ResetTimer(_) => {
                // TODO
                info!(%node, "reset timer");
                return;
            }
            Action::Deliver(_b, r, src) => {
                // TODO
                info!(%node, %r, %src, "deliver");
                return;
            }
            Action::SendNoVote(to, e) => (Some(to), Message::NoVote(e.cast())),
            Action::SendProposal(e) => (None, Message::Vertex(e.cast())),
            Action::SendTimeout(e) => (None, Message::Timeout(e.cast())),
            Action::SendTimeoutCert(c) => (None, Message::TimeoutCert(c)),
        };
        msgs.push(msg)
    }
}

use sailfish::consensus::{Consensus, Dag};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    num::NonZeroUsize,
};
use timeboost_core::types::{
    message::{Action, Message},
    round_number::RoundNumber,
    NodeId, PublicKey,
};
use tracing::info;

use super::{
    action_validator::{ActionTaken, ConsensusValidator, ProcessedState},
    interceptor::Interceptor,
    test_helpers::create_timeout_vote_action,
};

/// Mock the network
pub struct FakeNetwork {
    pub(crate) nodes: HashMap<PublicKey, (Consensus, VecDeque<Message>)>,
    msg_interceptor: Interceptor,
}

impl FakeNetwork {
    pub(crate) fn new(nodes: Vec<(PublicKey, Consensus)>, msg_interceptor: Interceptor) -> Self {
        Self {
            nodes: nodes
                .into_iter()
                .map(|(id, n)| (id, (n, VecDeque::new())))
                .collect(),
            msg_interceptor,
        }
    }

    pub(crate) fn start(&mut self) {
        let mut next = Vec::new();
        let committee_size = NonZeroUsize::new(self.nodes.len()).unwrap();
        for (_pub_key, (node, _)) in self.nodes.iter_mut() {
            for a in node.go(Dag::new(committee_size)) {
                Self::handle_action(node.id(), a, &mut next);
            }
        }
        self.dispatch(next)
    }

    pub(crate) fn consensus(&self) -> impl Iterator<Item = &Consensus> {
        self.nodes.values().map(|(c, _)| c)
    }

    pub(crate) fn current_round(&self) -> RoundNumber {
        self.nodes
            .values()
            .map(|(node, _)| node.round())
            .max()
            .unwrap()
    }

    pub(crate) fn leader_for_round(&self, round: RoundNumber) -> PublicKey {
        self.nodes
            .values()
            .map(|(node, _)| node.committee().leader(round))
            .max()
            .unwrap()
    }

    pub(crate) fn leader(&self, round: RoundNumber) -> &Consensus {
        let key = self
            .nodes
            .values()
            .next()
            .expect("at least one node exists")
            .0
            .committee()
            .leader(round);
        self.consensus().find(|c| c.public_key() == &key).unwrap()
    }

    /// Process the current message on the queue
    /// Push the next messages after processing
    pub(crate) fn process(&mut self, expected: Option<HashSet<ActionTaken>>) {
        let mut next_msgs = Vec::new();
        let validator = if let Some(e) = expected {
            ConsensusValidator::new(e)
        } else {
            ConsensusValidator::default()
        };

        for (_pub_key, (node, queue)) in self.nodes.iter_mut() {
            let mut actions_taken = HashSet::new();
            while let Some(msg) = queue.pop_front() {
                for a in Self::handle_message(node, msg, &self.msg_interceptor, queue) {
                    let action = Self::handle_action(node.id(), a, &mut next_msgs);
                    actions_taken.insert(action);
                }
            }
            let leader = node.committee().leader(node.round());
            validator.validate_state(
                ProcessedState::new(node.id(), node.round(), actions_taken),
                leader == *node.public_key(),
            );
        }
        self.dispatch(next_msgs);
    }

    /// Look in each node and grab their queue of messages
    /// Used for asserting in tests to make sure outputs are expected
    pub(crate) fn msgs_in_queue(&self) -> HashMap<NodeId, VecDeque<Message>> {
        let nodes_msgs = self
            .nodes
            .values()
            .map(|node| (node.0.id(), node.1.clone()))
            .collect();
        nodes_msgs
    }

    pub(crate) fn timeout_round(&mut self, round: RoundNumber) {
        let mut msgs: Vec<(Option<PublicKey>, Message)> = Vec::new();
        for (node, queue) in self.nodes.values_mut() {
            let mut keep = VecDeque::new();
            while let Some(msg) = queue.pop_front() {
                if let Message::Vertex(v) = msg.clone() {
                    // TODO: Byzantine framework to simulate a dishonest leader who doesnt propose
                    // To simulate a timeout we just drop the message with the leader vertex
                    // We still keep the other vertices from non leader nodes so we will have 2f + 1 vertices
                    // And be able to propose a vertex with timeout cert
                    if *v.signing_key() == node.committee().leader(v.data().round()) {
                        continue;
                    }
                }

                // Keep the message if it is not a vertex or if it is a vertex from a non-leader
                keep.push_back(msg);
            }
            queue.extend(keep);

            let timeout_action =
                create_timeout_vote_action(round, *node.public_key(), node.private_key());

            // Process timeout actions
            Self::handle_action(node.id(), timeout_action, &mut msgs);
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
        let msgs = interceptor.intercept_message(msg, node, queue);
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
                    for (_, queue) in self.nodes.values_mut() {
                        queue.push_back(msg.clone());
                    }
                }
                (Some(pub_key), msg) => {
                    let (_, queue) = self.nodes.get_mut(&pub_key).unwrap();
                    queue.push_back(msg);
                }
            }
        }
    }

    fn handle_action(
        node: NodeId,
        a: Action,
        msgs: &mut Vec<(Option<PublicKey>, Message)>,
    ) -> ActionTaken {
        let action_taken: ActionTaken;
        let msg: (Option<PublicKey>, Message) = match a {
            Action::ResetTimer(_) => {
                // TODO
                info!(%node, "reset timer");
                return ActionTaken::ResetTimer;
            }
            Action::Deliver(_b, r, src) => {
                // TODO
                info!(%node, %r, %src, "deliver");
                return ActionTaken::Deliver;
            }
            Action::SendNoVote(to, e) => {
                action_taken = ActionTaken::SendNoVote;
                (Some(to), Message::NoVote(e.cast()))
            }
            Action::SendProposal(e) => {
                action_taken = ActionTaken::SendProposal;
                (None, Message::Vertex(e.cast()))
            }
            Action::SendTimeout(e) => {
                action_taken = ActionTaken::SendTimeout;
                (None, Message::Timeout(e.cast()))
            }
            Action::SendTimeoutCert(c) => {
                action_taken = ActionTaken::SendTimeoutCert;
                (None, Message::TimeoutCert(c))
            }
        };
        msgs.push(msg);
        action_taken
    }
}

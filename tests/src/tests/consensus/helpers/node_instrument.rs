use std::collections::VecDeque;

use sailfish::consensus::Consensus;
use timeboost_core::types::{
    message::{Action, Message},
    round_number::RoundNumber,
};
pub(crate) struct TestNodeInstrument {
    node: Consensus,
    msg_queue: VecDeque<Message>,
    actions_taken: Vec<Action>,
}

impl TestNodeInstrument {
    pub fn new(node: Consensus) -> Self {
        Self {
            node,
            msg_queue: VecDeque::new(),
            actions_taken: Vec::new(),
        }
    }

    pub fn handle_message(&mut self, msg: Message) {
        self.actions_taken.extend(self.node.handle_message(msg))
    }

    pub fn add_msg(&mut self, msg: Message) {
        self.msg_queue.push_back(msg);
    }

    pub fn add_msgs(&mut self, msgs: Vec<Message>) {
        self.msg_queue.extend(msgs);
    }

    pub fn pop_msg(&mut self) -> Option<Message> {
        self.msg_queue.pop_front()
    }

    pub fn msg_queue(&self) -> &VecDeque<Message> {
        &self.msg_queue
    }

    pub fn node(&self) -> &Consensus {
        &self.node
    }

    pub fn node_mut(&mut self) -> &mut Consensus {
        &mut self.node
    }

    pub fn actions_taken_len(&self) -> usize {
        self.actions_taken.len()
    }

    pub fn create_vertex_proposal_action(&self, round: RoundNumber) -> Action {
        // first find what is stored in our dag
        let v = self
            .node()
            .dag()
            .vertex(round, self.node().public_key())
            .unwrap();
        // sign
        let e = self.node.sign(v.clone());
        Action::SendProposal(e)
    }

    pub fn assert_actions(&self, expected: Vec<Action>) {
        assert_eq!(
            expected.len(),
            self.actions_taken.len(),
            "Expected Actions should match actual actions len"
        );

        for idx in 0..expected.len() {
            let expected_action = expected.get(idx).unwrap();
            let actual_action = self.actions_taken.get(idx).unwrap();
            assert_eq!(
                expected_action, actual_action,
                "Expected vs Actual actions do not match"
            );
        }
    }
}

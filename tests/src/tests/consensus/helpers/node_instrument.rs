use std::collections::VecDeque;

use sailfish::consensus::Consensus;
use timeboost_core::types::{
    message::{Action, Message},
    vertex::Vertex,
};

pub(crate) struct TestNodeInstrument {
    pub node: Consensus,
    msg_queue: VecDeque<Message>,
    pub actions_taken: Vec<Action>
}

impl TestNodeInstrument {
    pub fn new(node: Consensus) -> Self {
        Self {
            node,
            msg_queue: VecDeque::new(),
            actions_taken: Vec::new()
        }
    }

    pub fn add_vertex_to_dag(&mut self, v: Vertex) {
        self.node.add_vertex_to_dag(v);
    }

    pub fn handle_message(&mut self, msg: Message) {
        self.actions_taken.extend(self.node.handle_message(msg))
    }

    pub fn add_msg(&mut self, msg: Message) {
        self.msg_queue.push_back(msg);
    }

    pub fn pop_msg(&mut self) -> Option<Message> {
        self.msg_queue.pop_front()
    }

    pub fn msg_queue(&self) -> &VecDeque<Message> {
        &self.msg_queue
    }

    pub fn _assert_actions(&self, _expected: Action) {

    }
}

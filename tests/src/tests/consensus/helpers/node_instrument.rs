use std::collections::{BTreeMap, VecDeque};

use sailfish::consensus::Consensus;
use timeboost_core::types::{
    message::{Action, Message},
    round_number::RoundNumber,
};

pub(crate) struct TestNodeInstrument {
    pub node: Consensus,
    pub msg_queue: VecDeque<Message>,
    pub assertions: BTreeMap<RoundNumber, Vec<Action>>,
}

impl TestNodeInstrument {
    pub fn new(node: Consensus, assertions: BTreeMap<RoundNumber, Vec<Action>>) -> Self {
        Self {
            node,
            msg_queue: VecDeque::new(),
            assertions,
        }
    }

    pub fn add_msg(&mut self, msg: Message) {
        self.msg_queue.push_back(msg);
    }

    pub fn handle_action(&self, action: Vec<Action>) {
        // todo
    }
}

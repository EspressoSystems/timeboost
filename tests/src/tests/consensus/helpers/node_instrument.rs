use std::collections::VecDeque;

use committable::Committable;
use multisig::{Certificate, Committee, PublicKey};
use multisig::{Envelope, Validated, VoteAccumulator};
use sailfish::consensus::Consensus;
use timeboost_core::types::{
    message::{Action, Message, NoVote, Timeout},
    vertex::Vertex,
};
use timeboost_utils::types::round_number::RoundNumber;

pub(crate) struct TestNodeInstrument {
    node: Consensus,
    msg_queue: VecDeque<Message>,
    expected_actions: VecDeque<Action>,
}

impl TestNodeInstrument {
    pub(crate) fn new(node: Consensus) -> Self {
        Self {
            node: node.sign_deterministically(true),
            msg_queue: VecDeque::new(),
            expected_actions: VecDeque::new(),
        }
    }

    pub(crate) fn insert_expected_actions(&mut self, expected_actions: Vec<Action>) {
        self.expected_actions = VecDeque::from(expected_actions);
    }

    pub(crate) fn handle_message_and_verify_actions(&mut self, msg: Message) {
        for a in self.node.handle_message(msg) {
            if let Some(expected) = self.expected_actions.pop_front() {
                assert_eq!(
                    a, expected,
                    "Expected action {expected} should match actual action {a}"
                )
            } else {
                panic!("Action was processed but expected actions was empty");
            }
        }
    }

    pub(crate) fn add_msg(&mut self, msg: Message) {
        self.msg_queue.push_back(msg);
    }

    pub(crate) fn add_msgs(&mut self, msgs: Vec<Message>) {
        self.msg_queue.extend(msgs);
    }

    pub(crate) fn pop_msg(&mut self) -> Option<Message> {
        self.msg_queue.pop_front()
    }

    pub(crate) fn msg_queue(&self) -> &VecDeque<Message> {
        &self.msg_queue
    }

    pub(crate) fn node(&self) -> &Consensus {
        &self.node
    }

    pub(crate) fn node_mut(&mut self) -> &mut Consensus {
        &mut self.node
    }

    pub(crate) fn committee(&self) -> &Committee {
        self.node.committee()
    }

    pub(crate) fn expected_vertex_proposal(
        &self,
        round: RoundNumber,
        edges: Vec<PublicKey>,
        timeout_cert: Option<Certificate<Timeout>>,
    ) -> Envelope<Vertex, Validated> {
        let mut v = Vertex::new(round, self.node.public_key());
        v.add_edges(edges);
        if let Some(tc) = timeout_cert {
            v.set_timeout(tc);
        }
        self.node.sign(v.clone())
    }

    pub(crate) fn expected_timeout(&self, round: RoundNumber) -> Envelope<Timeout, Validated> {
        let d = Timeout::new(round);
        self.node.sign(d.clone())
    }

    pub(crate) fn expected_timeout_certificate(
        &self,
        signers: Vec<Envelope<Timeout, Validated>>,
    ) -> Certificate<Timeout> {
        let mut va = VoteAccumulator::new(self.committee().clone());
        for e in signers {
            va.add(e).unwrap();
        }
        va.certificate().cloned().unwrap()
    }

    pub(crate) fn expected_no_vote(&self, round: RoundNumber) -> Envelope<NoVote, Validated> {
        let nv = NoVote::new(round);
        self.node.sign(nv)
    }

    pub(crate) fn expected_actions_is_empty(&self) -> bool {
        self.expected_actions.is_empty()
    }

    pub(crate) fn assert_timeout_accumulator(&self, expected_round: RoundNumber, votes: u64) {
        let timeout_accumulators = self.node.timeout_accumulators();
        let accumulator = timeout_accumulators.get(&expected_round);

        if let Some(accumulator) = accumulator {
            assert_eq!(
                accumulator.votes(&Timeout::new(expected_round).commit()),
                votes as usize,
                "Timeout votes accumulated do not match expected votes"
            );
            return;
        }

        assert_eq!(votes, 0, "Expected no votes when accumulator is missing");
    }
}

use std::collections::VecDeque;

use bitvec::vec::BitVec;
use ethereum_types::U256;
use hotshot::types::SignatureKey;
use sailfish::consensus::Consensus;
use timeboost_core::types::{
    certificate::Certificate,
    committee::StaticCommittee,
    envelope::{Envelope, Validated},
    message::{Action, Evidence, Message, NoVoteMessage, Timeout, TimeoutMessage},
    round_number::RoundNumber,
    vertex::Vertex,
    PublicKey, Signature,
};

use super::key_manager::KeyManager;
pub(crate) struct TestNodeInstrument {
    node: Consensus,
    msg_queue: VecDeque<Message>,
    expected_actions: VecDeque<Action>,
}

impl TestNodeInstrument {
    pub(crate) fn new(node: Consensus) -> Self {
        Self {
            node,
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
                assert_eq!(a, expected, "Expected action should match actual action")
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

    pub(crate) fn committee(&self) -> &StaticCommittee {
        self.node.committee()
    }

    pub(crate) fn expected_vertex_proposal(
        &self,
        manager: &KeyManager,
        round: RoundNumber,
        edges: Vec<PublicKey>,
        timeout_cert: Option<Certificate<Timeout>>,
    ) -> Envelope<Vertex, Validated> {
        let sig = self.quorum_signature(
            round,
            manager,
            self.committee().quorum_size().get() as usize,
            false,
        );

        let mut v = if let Some(tc) = timeout_cert {
            Vertex::new(round, Evidence::Timeout(tc), self.node.key_pair())
        } else {
            let evidence = Evidence::Regular(Certificate::new(round - 1, sig));
            Vertex::new(round, evidence, self.node.key_pair())
        };
        v.add_edges(edges);

        self.node.sign(v.clone())
    }

    pub(crate) fn expected_timeout(
        &self,
        manager: &KeyManager,
        round: RoundNumber,
    ) -> Envelope<TimeoutMessage, Validated> {
        let e = manager.round_evidence(round - 1, self.committee());
        let d = TimeoutMessage::new(round, e, self.node.key_pair());
        self.node.sign(d.clone())
    }

    pub(crate) fn expected_timeout_certificate(
        &self,
        round: RoundNumber,
        manager: &KeyManager,
        sig_count: usize,
        e: &Envelope<TimeoutMessage, Validated>,
    ) -> Certificate<Timeout> {
        let sig = self.quorum_signature(round, manager, sig_count, true);
        Certificate::new(e.data().round().data().clone(), sig)
    }

    pub(crate) fn expected_no_vote(
        &self,
        round: RoundNumber,
        cert: Certificate<Timeout>,
    ) -> Envelope<NoVoteMessage, Validated> {
        let d = NoVoteMessage::new(round, cert, self.node.key_pair());
        self.node.sign(d.clone())
    }

    pub(crate) fn expected_actions_is_empty(&self) -> bool {
        self.expected_actions.is_empty()
    }

    pub(crate) fn assert_timeout_accumulator(&self, expected_round: RoundNumber, votes: u64) {
        let accumulator = self.node.timeout_accumulators().get(&expected_round);

        if let Some(accumulator) = accumulator {
            assert_eq!(
                accumulator.votes(),
                votes as usize,
                "Timeout votes accumulated do not match expected votes"
            );
            return;
        }

        assert_eq!(votes, 0, "Expected no votes when accumulator is missing");
    }

    fn quorum_signature(
        &self,
        round: RoundNumber,
        manager: &KeyManager,
        sig_count: usize,
        is_timeout: bool,
    ) -> (Signature, BitVec) {
        let signers = if !is_timeout {
            manager.signers_for_round(round - 1, self.committee(), sig_count)
        } else {
            manager.signers_for_timeout(round, self.committee(), sig_count)
        };
        let pp = <PublicKey as SignatureKey>::public_parameter(
            self.node.committee().stake_table(),
            U256::from(self.node.committee().quorum_size().get()),
        );
        <PublicKey as SignatureKey>::assemble(&pp, &signers.0, &signers.1)
    }
}

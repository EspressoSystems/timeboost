use std::collections::{BTreeSet, VecDeque};

use crate::tests::consensus::helpers::key_manager::KeyManager;
use committable::Committable;
use multisig::{Certificate, Committee, PublicKey};
use multisig::{Envelope, Keypair, Validated, VoteAccumulator};
use sailfish::types::{NoVoteMessage, RoundNumber, Timeout, TimeoutMessage};

use crate::prelude::*;

pub(crate) struct TestNodeInstrument {
    node: Consensus,
    kpair: Keypair,
    manager: KeyManager,
    msg_queue: VecDeque<Message>,
    expected_actions: VecDeque<Action>,
}

impl TestNodeInstrument {
    pub(crate) fn new(manager: KeyManager, kpair: Keypair, node: Consensus) -> Self {
        Self {
            kpair,
            manager,
            node,
            msg_queue: VecDeque::new(),
            expected_actions: VecDeque::new(),
        }
    }

    pub(crate) fn insert_expected_actions(&mut self, expected_actions: Vec<Action>) {
        self.expected_actions = VecDeque::from(expected_actions);
    }

    pub(crate) fn handle_message_and_verify_actions(&mut self, msg: Message) {
        let c = self.manager.committee();
        for a in self.node.handle_message(msg) {
            if let Some(expected) = self.expected_actions.pop_front() {
                assert_equiv(&expected, &a, &c)
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

    pub(crate) fn committee(&self) -> Committee {
        self.manager.committee()
    }

    pub(crate) fn expected_vertex_proposal(
        &self,
        round: RoundNumber,
        edges: Vec<PublicKey>,
        timeout_cert: Option<Certificate<Timeout>>,
    ) -> Envelope<Vertex, Validated> {
        let mut v = if let Some(tc) = timeout_cert {
            Vertex::new(round, tc, EmptyBlocks.next(round), &self.kpair)
        } else {
            Vertex::new(
                round,
                self.manager.gen_round_cert(round - 1),
                EmptyBlocks.next(round),
                &self.kpair,
            )
        };
        v.add_edges(edges);
        self.sign(v)
    }

    pub(crate) fn expected_timeout(
        &self,
        round: RoundNumber,
    ) -> Envelope<TimeoutMessage, Validated> {
        let d = TimeoutMessage::new(self.manager.gen_round_cert(round - 1).into(), &self.kpair);
        self.sign(d.clone())
    }

    pub(crate) fn expected_timeout_certificate(
        &self,
        signers: Vec<Envelope<Timeout, Validated>>,
    ) -> Certificate<Timeout> {
        let mut va = VoteAccumulator::new(self.committee().clone());
        for e in signers {
            va.add(e.into_signed()).unwrap();
        }
        va.certificate().cloned().unwrap()
    }

    pub(crate) fn expected_no_vote(
        &self,
        round: RoundNumber,
    ) -> Envelope<NoVoteMessage, Validated> {
        let nv = NoVoteMessage::new(self.manager.gen_timeout_cert(round), &self.kpair);
        self.sign(nv)
    }

    pub(crate) fn expected_actions_is_empty(&self) -> bool {
        self.expected_actions.is_empty()
    }

    pub(crate) fn assert_timeout_accumulator(&self, expected_round: RoundNumber, votes: u64) {
        let accumulator = self
            .node
            .timeout_accumulators()
            .find_map(|(r, v)| (r == expected_round).then_some(v));

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

    pub(crate) fn sign<D: Committable>(&self, d: D) -> Envelope<D, Validated> {
        Envelope::signed(d, &self.kpair)
    }
}

fn assert_equiv(a: &Action, b: &Action, c: &Committee) {
    let parties: BTreeSet<PublicKey> = c.parties().copied().collect();
    match (a, b) {
        (Action::ResetTimer(x), Action::ResetTimer(y)) => {
            assert_eq!(x, y)
        }
        (Action::Deliver(x), Action::Deliver(y)) => {
            assert_eq!(x.round(), y.round());
            assert_eq!(x.source(), y.source());
            block_equiv(x.data(), y.data());
        }
        (Action::SendProposal(x), Action::SendProposal(y)) => {
            assert_eq!(x.is_valid(c), y.is_valid(c));
            let xv = x.data();
            let yv = y.data();
            let xe = xv.evidence().is_valid(*xv.round().data(), c);
            let ye = yv.evidence().is_valid(*yv.round().data(), c);
            let xn = xv.no_vote_cert().map(|crt| crt.is_valid(c));
            let yn = yv.no_vote_cert().map(|crt| crt.is_valid(c));
            let xve = xv.edges().copied().collect::<BTreeSet<_>>();
            let yve = yv.edges().copied().collect::<BTreeSet<_>>();
            assert_eq!(xv.round(), yv.round());
            assert_eq!(xv.source(), yv.source());
            assert_eq!(xe, ye);
            assert_eq!(xn, yn);
            assert!(xve.is_subset(&parties));
            assert!(yve.is_subset(&parties));
            assert!(xve.len() >= c.quorum_size().get());
            assert!(yve.len() >= c.quorum_size().get());
            block_equiv(xv.payload(), yv.payload());
        }
        (Action::SendTimeout(x), Action::SendTimeout(y)) => {
            assert_eq!(x.is_valid(c), y.is_valid(c));
            let xt = x.data();
            let yt = y.data();
            assert_eq!(xt.timeout(), yt.timeout());
            let xe = xt.evidence().is_valid(xt.timeout().data().round(), c);
            let ye = yt.evidence().is_valid(yt.timeout().data().round(), c);
            assert_eq!(xe, ye);
        }
        (Action::SendNoVote(xto, x), Action::SendNoVote(yto, y)) => {
            assert_eq!(xto, yto);
            assert_eq!(x.is_valid(c), y.is_valid(c));
            let xn = x.data();
            let yn = y.data();
            assert_eq!(xn.no_vote(), yn.no_vote());
            let xe = xn.certificate().is_valid(c);
            let ye = yn.certificate().is_valid(c);
            assert_eq!(xe, ye);
        }
        (Action::SendTimeoutCert(x), Action::SendTimeoutCert(y)) => {
            assert_eq!(x.is_valid(c), y.is_valid(c));
            assert_eq!(x.data(), y.data());
        }
        (Action::Gc(x), Action::Gc(y)) => {
            assert_eq!(x, y)
        }
        _ => panic!("{a} ≁ {b}"),
    }
}

fn block_equiv(l: &SailfishBlock, r: &SailfishBlock) {
    assert!(
        l.timestamp().abs_diff(*r.timestamp()) <= 5,
        "Drift is too high from expected to actual block timestamps"
    );
}

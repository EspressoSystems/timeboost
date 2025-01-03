use criterion::{criterion_group, criterion_main, Criterion};
use multisig::{Committee, Keypair, PublicKey, Validated};
use sailfish::consensus::{Consensus, Dag};
use std::{collections::HashMap, num::NonZeroUsize, sync::LazyLock};
use timeboost_core::types::{
    message::{Action, Evidence, Message},
    NodeId,
};
use timeboost_utils::types::{logging, round_number::RoundNumber};

const SEED: [u8; 32] = [
    1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

static TEST_DATA: LazyLock<HashMap<u64, Vec<Message>>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    m.insert(
        10,
        generate_quorum_data(MultiRoundTestSpec {
            rounds: 10,
            ..Default::default()
        }),
    );
    m
});

#[derive(Debug, Clone, Copy)]
struct MultiRoundTestSpec {
    pub nodes: u64,
    pub rounds: u64,
}

impl Default for MultiRoundTestSpec {
    fn default() -> Self {
        Self {
            nodes: 1,
            rounds: 10,
        }
    }
}

struct Net {
    /// Mapping of public key to the corresponding cx node.
    pub nodes: HashMap<PublicKey, Consensus>,

    /// How many rounds to run until
    pub rounds: u64,
}

impl Net {
    pub fn new(spec: MultiRoundTestSpec) -> Self {
        let MultiRoundTestSpec { nodes, rounds } = spec;
        let kps = (0..nodes)
            .map(|_| Keypair::from_seed(SEED))
            .collect::<Vec<_>>();
        let com = Committee::new(
            kps.iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );
        let nodes = kps
            .into_iter()
            .enumerate()
            .map(|(i, kp)| {
                (
                    kp.public_key(),
                    Consensus::new(NodeId::from(i as u64), kp, com.clone()),
                )
            })
            .collect::<HashMap<_, _>>();
        Self { nodes, rounds }
    }

    pub fn run(&mut self) -> Vec<Message> {
        let mut ret = Vec::new();
        let com_sz = NonZeroUsize::new(self.nodes.len()).expect("nonzero usize > 0");
        let d = Dag::new(com_sz);

        // Get the initial message batch
        let mut init_actions = Vec::new();
        for node in self.nodes.values_mut() {
            init_actions.extend(node.go(d.clone(), Evidence::Genesis));
        }
        let mut msgs = Self::action_to_msg(init_actions);
        ret.extend(msgs.clone());

        while *self.round() < self.rounds {
            let a = self.send(msgs);
            msgs = Self::action_to_msg(a);
            ret.extend(msgs.clone());
        }

        ret
    }

    /// Many-to-many broadcast of a message stack.
    fn send(&mut self, msgs: Vec<Message>) -> Vec<Action> {
        let mut ret = Vec::new();
        for node in self.nodes.values_mut() {
            for m in &msgs {
                ret.extend(node.handle_message(m.clone()))
            }
        }
        ret
    }

    fn action_to_msg(actions: Vec<Action>) -> Vec<Message> {
        let mut ret = Vec::new();
        for a in actions {
            let msg = match a {
                Action::SendNoVote(_, e) => Message::NoVote(e),
                Action::SendProposal(e) => Message::Vertex(e),
                Action::SendTimeout(e) => Message::Timeout(e),
                Action::SendTimeoutCert(c) => Message::TimeoutCert(c),
                Action::ResetTimer(_) => continue,
                Action::Deliver(..) => continue,
            };
            ret.push(msg)
        }
        ret
    }

    fn round(&self) -> RoundNumber {
        self.nodes
            .values()
            .map(|cx| cx.round())
            .min()
            .expect("round number exists in cx stack")
    }
}

/// Generates quorum data in one-shot to use as inputs to a node.
fn generate_quorum_data(spec: MultiRoundTestSpec) -> Vec<Message<Validated>> {
    Net::new(spec).run()
}

#[inline]
fn bench_multi_round_consensus(rounds: u64) {
    logging::init_logging();

    let msgs = TEST_DATA
        .get(&rounds)
        .expect("data for rounds to exist")
        .clone();
    assert_eq!(msgs.len() as u64, 11);

    // Run the actual test.
    let kp = Keypair::from_seed(SEED);
    let com = Committee::new([(0_u8, kp.public_key())]);
    let mut cx = Consensus::new(NodeId::from(0), kp, com);
    cx.go(Dag::new(NonZeroUsize::new(1).unwrap()), Evidence::Genesis);

    msgs.into_iter().for_each(move |msg| {
        cx.handle_message(msg);
    });
}

pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("multi_round_10", |b| {
        b.iter(|| bench_multi_round_consensus(10))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

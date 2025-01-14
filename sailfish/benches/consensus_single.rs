use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use multisig::{Committee, Keypair, PublicKey};
use sailfish::consensus::{Consensus, Dag};
use std::{collections::HashMap, fmt, num::NonZeroUsize};
use timeboost_core::types::{
    message::{Action, Evidence, Message},
    NodeId,
};
use timeboost_utils::types::logging;

#[derive(Debug, Clone, Copy)]
struct MultiRoundTestSpec {
    pub nodes: u64,
    pub rounds: u64,
}

impl fmt::Display for MultiRoundTestSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ nodes := {}, rounds := {} }}",
            self.nodes, self.rounds
        )
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
        let kps = (0..nodes).map(|_| Keypair::generate()).collect::<Vec<_>>();
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

    pub fn run(&mut self) {
        let d = Dag::new(NonZeroUsize::new(self.nodes.len()).unwrap());

        let mut actions = Vec::new();

        for node in self.nodes.values_mut() {
            actions.extend(node.go(d.clone(), Evidence::Genesis));
        }

        let mut messages: Vec<Message> = actions.drain(..).filter_map(action_to_msg).collect();

        for _ in 0..self.rounds {
            messages = self
                .send(&messages)
                .drain(..)
                .filter_map(action_to_msg)
                .collect();
        }

        // Check that all nodes did indeed make progress:
        for node in self.nodes.values() {
            assert_eq!(*node.round(), self.rounds);
        }
    }

    /// Many-to-many broadcast of a message stack.
    fn send(&mut self, msgs: &[Message]) -> Vec<Action> {
        use rayon::prelude::*;

        if self.nodes.len() == 1 {
            let mut actions = Vec::new();
            for n in self.nodes.values_mut() {
                for m in msgs {
                    actions.extend(n.handle_message(m.clone()))
                }
            }
            return actions;
        }

        self.nodes
            .par_iter_mut()
            .map(|(_, node)| {
                let mut actions = Vec::new();
                for m in msgs {
                    actions.extend(node.handle_message(m.clone()))
                }
                actions
            })
            .flatten()
            .collect()
    }
}

fn action_to_msg(action: Action) -> Option<Message> {
    match action {
        Action::SendNoVote(_, e) => Some(Message::NoVote(e)),
        Action::SendProposal(e) => Some(Message::Vertex(e)),
        Action::SendTimeout(e) => Some(Message::Timeout(e)),
        Action::SendTimeoutCert(c) => Some(Message::TimeoutCert(c)),
        Action::ResetTimer(_) => None,
        Action::Deliver(..) => None,
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    logging::init_logging();

    let mut group = c.benchmark_group("multi-round consensus");
    for s in [
        MultiRoundTestSpec {
            nodes: 1,
            rounds: 10,
        },
        MultiRoundTestSpec {
            nodes: 5,
            rounds: 10,
        },
        MultiRoundTestSpec {
            nodes: 10,
            rounds: 10,
        },
        MultiRoundTestSpec {
            nodes: 15,
            rounds: 10,
        },
        MultiRoundTestSpec {
            nodes: 20,
            rounds: 10,
        },
        MultiRoundTestSpec {
            nodes: 1,
            rounds: 100,
        },
        MultiRoundTestSpec {
            nodes: 5,
            rounds: 100,
        },
        MultiRoundTestSpec {
            nodes: 10,
            rounds: 100,
        },
        MultiRoundTestSpec {
            nodes: 15,
            rounds: 100,
        },
        MultiRoundTestSpec {
            nodes: 20,
            rounds: 100,
        },
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(s), &s, |b, &s| {
            let mut net = Net::new(s);
            b.iter(|| net.run())
        });
    }
    group.finish()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

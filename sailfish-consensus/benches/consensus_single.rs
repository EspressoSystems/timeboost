use std::iter::repeat;
use std::{collections::HashMap, fmt, num::NonZeroUsize};

use committable::Committable;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use multisig::{Committee, Keypair, PublicKey};
use sailfish_consensus::{Consensus, Dag};
use sailfish_types::{Action, Evidence, Message, Timestamp, UNKNOWN_COMMITTEE_ID};

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
    nodes: HashMap<PublicKey, Consensus<Timestamp>>,

    /// How many rounds to run until.
    rounds: u64,

    /// Number of times `Net::run` was invoked.
    iteration: u64,

    /// Message buffer.
    messages: Vec<Message<Timestamp>>,
}

impl Net {
    pub fn new(spec: MultiRoundTestSpec) -> Self {
        let MultiRoundTestSpec { nodes, rounds } = spec;
        let kps = (0..nodes).map(|_| Keypair::generate()).collect::<Vec<_>>();

        let com = Committee::new(
            UNKNOWN_COMMITTEE_ID,
            kps.iter()
                .enumerate()
                .map(|(i, kp)| (i as u8, kp.public_key())),
        );

        let now = Timestamp::now();

        let mut nodes = kps
            .into_iter()
            .map(|kp| {
                (
                    kp.public_key(),
                    Consensus::new(kp, com.clone(), repeat(now)),
                )
            })
            .collect::<HashMap<_, _>>();

        let dag = Dag::new(NonZeroUsize::new(nodes.len()).unwrap());

        let mut messages = Vec::new();

        for node in nodes.values_mut() {
            let actions = node.go(dag.clone(), Evidence::Genesis);
            messages.extend(actions.into_iter().filter_map(action_to_msg));
        }

        Self {
            nodes,
            rounds,
            messages,
            iteration: 0,
        }
    }

    pub fn run(&mut self) {
        self.iteration += 1;
        for _ in 0..self.rounds {
            self.messages = send(&mut self.nodes, &self.messages)
                .drain(..)
                .filter_map(action_to_msg)
                .collect();
        }

        // Check that all nodes did indeed make progress:
        for node in self.nodes.values() {
            assert_eq!(*node.round(), self.iteration * self.rounds);
        }
    }
}

/// Many-to-many broadcast of a message stack.
fn send(
    nodes: &mut HashMap<PublicKey, Consensus<Timestamp>>,
    msgs: &[Message<Timestamp>],
) -> Vec<Action<Timestamp>> {
    use rayon::prelude::*;

    if nodes.len() == 1 {
        let mut actions = Vec::new();
        for n in nodes.values_mut() {
            for m in msgs {
                actions.extend(n.handle_message(m.clone()))
            }
        }
        return actions;
    }

    nodes
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

fn action_to_msg<T: Committable>(action: Action<T>) -> Option<Message<T>> {
    match action {
        Action::SendNoVote(_, e) => Some(Message::NoVote(e)),
        Action::SendProposal(e) => Some(Message::Vertex(e)),
        Action::SendTimeout(e) => Some(Message::Timeout(e)),
        Action::SendTimeoutCert(c) => Some(Message::TimeoutCert(c)),
        Action::SendHandover(e) => Some(Message::Handover(e)),
        Action::SendHandoverCert(c) => Some(Message::HandoverCert(c)),
        Action::ResetTimer(_) => None,
        Action::Deliver(..) => None,
        Action::Gc(_) => None,
        Action::Catchup(_) => None,
        Action::UseCommittee(_) => None,
    }
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_round_consensus");
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

use crate::tests::consensus::helpers::shaping::{
    edge, edges, Event, Name, Rule, RuleGen, Simulator,
};
use std::collections::{BTreeMap, HashSet};
use timeboost_utils::types::round_number::RoundNumber;

/// A simple test that always delivers messages to all parties.
///
/// No timeouts are expected to occur.
#[test]
fn immediate_delivery_to_all() {
    timeboost_utils::types::logging::init_logging();

    let all = ["A", "B", "C", "D", "E"];

    let mut sim = Simulator::new(all);
    sim.set_rules([Rule::new("immediate fanout")
        .repeat(100)
        .with(edges("A", all))
        .with(edges("B", all))
        .with(edges("C", all))
        .with(edges("D", all))
        .with(edges("E", all))]);
    sim.goto(100);
    assert!(sim.events().iter().all(|e| e.is_deliver()));
    assert!(is_valid_delivery(&sim));
}

/// A single node (D) sees its own messages immediately but everyone else
/// receives them delayed. This happens long enough such that the other
/// parties have garbage collected their DAG, hence by the time the delayed
/// messages from D arrive, they can not be added to the DAG as their
/// references can not be fully resolved. D however keeps adding those
/// references as it receives its own proposals immediately.
///
/// Once this happens there will be continuous timeouts everytime D becomes
/// leader as the other parties can not advance before timeout. NB how all
/// parties except D have buffered vertex proposals.
#[test]
fn delayed_delivery() {
    timeboost_utils::types::logging::init_logging();

    let all = ["A", "B", "C", "D", "E"];

    let mut sim = Simulator::new(all);
    sim.set_rules([
        Rule::new("immediate fanout")
            .with(edges("A", all))
            .with(edges("B", all))
            .with(edges("C", all))
            .with(edges("D", all))
            .with(edges("E", all)),
        Rule::new("traffic from one party is delayed")
            .repeat(10)
            .with(edges("A", all))
            .with(edges("B", all))
            .with(edges("C", all))
            .plus(edge("D", "A").delay(20))
            .plus(edge("D", "B").delay(20))
            .plus(edge("D", "C").delay(20))
            .plus(edge("D", "D"))
            .plus(edge("D", "E").delay(20))
            .with(edges("E", all)),
    ]);
    sim.goto(500);

    assert_eq!(135, sim.events().iter().filter(|e| e.is_timeout()).count());

    assert_eq!(6, sim.consensus("A").buffer_depth());
    assert_eq!(6, sim.consensus("B").buffer_depth());
    assert_eq!(6, sim.consensus("C").buffer_depth());
    assert_eq!(6, sim.consensus("E").buffer_depth());

    assert_eq!(0, sim.consensus("D").buffer_depth());

    assert!(is_valid_delivery(&sim));
}

/// Show that any prefix of edge delays is followed by deliver events.
#[test]
fn progress_after_random_prefix() {
    timeboost_utils::types::logging::init_logging();

    let all = ["A", "B", "C", "D", "E"];
    let mut gen = RuleGen::new(all)
        .with_max_delay(17)
        .with_max_repeat(29)
        .with_min_edges(all.len());

    let mut sim = Simulator::new(all);
    sim.set_rules(gen.generate(50));
    sim.goto(1000);

    assert_eq!(0, sim.pending_messages());
    assert_eq!(0, sim.rules().count());

    let n = sim.events().len();

    sim.set_rules([]);
    sim.goto(2000);

    assert!(
        sim.events().len() > n,
        "no new events (seed = {})",
        gen.seed()
    );

    assert!(
        sim.events()[n..].iter().any(|e| e.is_deliver()),
        "no deliveries (seed = {})",
        gen.seed()
    );

    assert!(
        is_valid_delivery(&sim),
        "invalid deliveries (seed = {})",
        gen.seed()
    )
}

/// Check that delivery properties hold true.
///
/// 1. All parties deliver the same sequence of deliver events.
/// 2. No delivery is repeated.
/// 3. The sequence of deliveries is non-empty.
fn is_valid_delivery(sim: &Simulator) -> bool {
    let mut m: BTreeMap<Name, Vec<(RoundNumber, Name)>> = BTreeMap::new();
    for e in sim.events() {
        if let Event::Deliver(_, source, round, party) = e {
            m.entry(*source).or_default().push((*round, *party))
        }
    }
    if m.is_empty() {
        return false;
    }
    if m.values().zip(m.values().skip(1)).any(|(a, b)| a != b) {
        return false;
    }
    let mut s = HashSet::new();
    for e in m.values() {
        s.clear();
        for d in e {
            s.insert(d);
        }
        if s.is_empty() {
            return false;
        }
        if e.len() != s.len() {
            return false;
        }
    }
    true
}

/// In this test B ignores A for some time, i.e. it does not send its messages
/// to A. This creates a gap where vertices can not be fully resolved and
/// subsequent vertex proposals can not be added to the DAG but must be buffered.
/// The catch-up logic in sailfish inspects the buffer size and eventually
/// replaces its DAG with the buffer, which prevents infinite buffer growth and
/// allows A to rejoin the game again.
#[test]
fn gap_does_not_cause_infinite_buffer_growth() {
    timeboost_utils::types::logging::init_logging();

    let all = ["A", "B", "C", "D", "E"];

    let mut sim = Simulator::new(all);
    sim.set_rules([
        Rule::new("immediate fanout")
            .repeat(10)
            .with(edges("A", all))
            .with(edges("B", all))
            .with(edges("C", all))
            .with(edges("D", all))
            .with(edges("E", all)),
        Rule::new("B ignores A")
            .repeat(10)
            .with(edges("A", all))
            .plus(edge("B", "B"))
            .plus(edge("B", "C"))
            .plus(edge("B", "D"))
            .plus(edge("B", "E"))
            .with(edges("C", all))
            .with(edges("D", all))
            .with(edges("E", all)),
    ]);
    sim.go(100);

    assert!(sim.events().iter().filter(|e| e.is_timeout()).count() > 0);

    assert_eq!(0, sim.consensus("A").buffer_depth())
}

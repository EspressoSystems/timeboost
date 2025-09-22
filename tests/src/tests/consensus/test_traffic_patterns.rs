use std::collections::{BTreeMap, HashSet};

use sailfish::types::RoundNumber;

use crate::tests::consensus::helpers::shaping::{
    Event, Name, Rule, RuleGen, Simulator, edge, edges,
};

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

    assert_eq!(10, sim.events().iter().filter(|e| e.is_timeout()).count());

    assert_eq!(0, sim.consensus("A").buffer_depth());
    assert_eq!(0, sim.consensus("B").buffer_depth());
    assert_eq!(0, sim.consensus("C").buffer_depth());
    assert_eq!(0, sim.consensus("D").buffer_depth());
    assert_eq!(0, sim.consensus("E").buffer_depth());

    assert!(is_valid_delivery(&sim));
}

/// Show that any prefix of edge delays is followed by deliver events.
#[test]
fn progress_after_random_prefix() {
    timeboost_utils::types::logging::init_logging();

    let all = ["A", "B", "C", "D", "E"];
    let mut rgen = RuleGen::new(all)
        .with_max_delay(17)
        .with_max_repeat(29)
        .with_min_edges(all.len());

    let mut sim = Simulator::new(all);
    sim.set_rules(rgen.generate(50));
    sim.goto(1000);

    assert_eq!(0, sim.pending_messages());
    assert_eq!(0, sim.rules().count());

    let n = sim.events().len();

    sim.set_rules([]);
    sim.goto(3000);

    assert!(
        sim.events().len() > n,
        "no new events (seed = {})",
        rgen.seed()
    );

    assert!(
        sim.events()[n..].iter().any(|e| e.is_deliver()),
        "no deliveries (seed = {})",
        rgen.seed()
    );

    assert!(
        is_valid_delivery(&sim),
        "invalid deliveries (seed = {})",
        rgen.seed()
    )
}

/// This test triggers a timeout by delaying the leader vertex in round 1.
/// In addition, the vertex proposals of round 1 to the leader of round 2
/// are delayed, to ensure no-vote messages arrive first and cause it to
/// advance to round 2.
#[test]
fn delay_vertices_to_leader() {
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
        Rule::new("trigger timeout of leader vertex")
            .precondition(|sim| {
                sim.round() == Some(1) && sim.leader(1) == Some("B") && sim.leader(2) == Some("D")
            })
            .plus(edge("A", "A"))
            .plus(edge("A", "B").delay_fn(|m| if m.is_vertex() { 15 } else { 0 }))
            .plus(edge("A", "C"))
            .plus(edge("A", "D"))
            .plus(edge("A", "E"))
            .plus(edge("B", "A").delay(15))
            .plus(edge("B", "B").delay(15))
            .plus(edge("B", "C").delay(15))
            .plus(edge("B", "D").delay(15))
            .plus(edge("B", "E").delay(15))
            .plus(edge("C", "A"))
            .plus(edge("C", "B").delay_fn(|m| if m.is_vertex() { 15 } else { 0 }))
            .plus(edge("C", "C"))
            .plus(edge("C", "D"))
            .plus(edge("C", "E"))
            .plus(edge("D", "A"))
            .plus(edge("D", "B").delay_fn(|m| if m.is_vertex() { 15 } else { 0 }))
            .plus(edge("D", "C"))
            .plus(edge("D", "D"))
            .plus(edge("D", "E"))
            .plus(edge("E", "A").delay_fn(|m| if m.is_vertex() { 15 } else { 0 }))
            .plus(edge("E", "B"))
            .plus(edge("E", "C"))
            .plus(edge("E", "D"))
            .plus(edge("E", "E")),
    ]);
    sim.goto(50);

    assert!(is_valid_delivery(&sim));
    assert!(matches!(sim.events().last(), Some(Event::Deliver(..))))
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
    for r in 0..sim.events().len() {
        let mut d = 0;
        for (a, b) in m.values().zip(m.values().skip(1)) {
            d += (a.get(r) != b.get(r)) as usize
        }
        if d >= sim.committee().one_honest_threshold().get() {
            return false;
        }
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

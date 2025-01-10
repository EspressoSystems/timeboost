use crate::tests::consensus::helpers::shaping::{edge, edges, Rule, RuleGen, Simulator};

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
    sim.go(100);
    assert!(sim.events().iter().all(|e| e.is_deliver()));
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
    sim.go(500);

    assert_eq!(135, sim.events().iter().filter(|e| e.is_timeout()).count());

    assert_eq!(8, sim.consensus("A").buffer_depth());
    assert_eq!(8, sim.consensus("B").buffer_depth());
    assert_eq!(8, sim.consensus("C").buffer_depth());
    assert_eq!(8, sim.consensus("E").buffer_depth());

    assert_eq!(0, sim.consensus("D").buffer_depth());
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
    sim.set_rules(gen.generate(20));
    sim.go(100);

    let n = sim.events().len();

    sim.set_rules([]);
    sim.go(200);

    assert!(
        sim.events().len() > n,
        "no new events (seed = {})",
        gen.seed()
    );

    assert!(
        sim.events()[n..].iter().any(|e| e.is_deliver()),
        "no deliveries (seed = {})",
        gen.seed()
    )
}

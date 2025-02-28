#![allow(unused)]

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::{fmt, mem};

use multisig::{Committee, Keypair, PublicKey};
use rand::prelude::*;
use sailfish::types::{Evidence, RoundNumber};
use tracing::debug;

use crate::prelude::*;

/// Name of a party.
pub type Name = &'static str;

/// Simulated time.
type Time = u64;

/// An edge points from some source to some destination party.
///
/// Optionally, an edge may attach a time delay for messages to arrive
/// at destination.
pub struct Edge {
    src: Name,
    dst: Name,
    delay: Box<dyn Fn(&Message) -> Time>,
}

impl Edge {
    /// Attach some message delay to this edge.
    pub fn delay(mut self, d: Time) -> Self {
        self.delay = Box::new(move |_| d);
        self
    }

    /// Attach some message delay function to this edge.
    pub fn delay_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&Message) -> Time + 'static,
    {
        self.delay = Box::new(f);
        self
    }
}

/// Create an edge with 0 delay.
pub fn edge(src: Name, dst: Name) -> Edge {
    Edge {
        src,
        dst,
        delay: Box::new(move |_| 0),
    }
}

/// Create multiple edges with 0 delay.
pub fn edges<I>(src: Name, dst: I) -> impl Iterator<Item = Edge>
where
    I: IntoIterator<Item = Name>,
{
    dst.into_iter().map(move |d| Edge {
        src,
        dst: d,
        delay: Box::new(move |_| 0),
    })
}

/// A rule contains edges from multiple sources to multiple destinations.
pub struct Rule {
    /// A short description of the rule.
    descr: &'static str,
    /// A precondition to hold before applying the rule.
    precond: Box<dyn Fn(&Simulator) -> bool>,
    /// The actual edges as a map from source to destination with delay function.
    #[allow(clippy::type_complexity)]
    edges: BTreeMap<Name, BTreeMap<Name, Box<dyn Fn(&Message) -> Time>>>,
    /// How many times the rule should be repeated?
    repeat: usize,
}

impl Rule {
    pub fn new(descr: &'static str) -> Self {
        Self {
            descr,
            precond: Box::new(|_| true),
            edges: BTreeMap::new(),
            repeat: 0,
        }
    }

    pub fn repeat(mut self, r: usize) -> Self {
        self.repeat = r;
        self
    }

    pub fn precondition<F>(mut self, f: F) -> Self
    where
        F: Fn(&Simulator) -> bool + 'static,
    {
        self.precond = Box::new(f);
        self
    }

    pub fn plus(mut self, e: Edge) -> Self {
        self.edges.entry(e.src).or_default().insert(e.dst, e.delay);
        self
    }

    pub fn with<I>(mut self, edges: I) -> Self
    where
        I: IntoIterator<Item = Edge>,
    {
        for e in edges.into_iter() {
            self.edges.entry(e.src).or_default().insert(e.dst, e.delay);
        }
        self
    }

    pub fn lookup(&self, src: Name, dst: Name) -> Option<&dyn Fn(&Message) -> Time> {
        self.edges.get(src)?.get(dst).map(|f| &**f)
    }
}

/// A rule generator.
///
/// Generates random rules subject to certain configurable constraints.
pub struct RuleGen {
    /// The parties for which to create edge rules.
    parties: Vec<Name>,
    /// The highest time delay to apply to an edge.
    max_delay: Time,
    /// How often to repeat applying a rule (upper bound).
    max_repeat: usize,
    /// The mininum number of edges to have between each pair of parties.
    min_edges: usize,
    /// The seed for the randon number generator.
    seed: u64,
    /// The random number generator to use.
    rgen: StdRng,
}

impl RuleGen {
    /// Create a new rule generator for the given parties using defaults.
    pub fn new<I: IntoIterator<Item = &'static str>>(names: I) -> Self {
        let seed = rand::random();
        let parties: Vec<Name> = names.into_iter().collect();
        assert!(!parties.is_empty());
        Self {
            // Some arbitrary value. Should take the timeout setting of
            // the `Simulator` into considerations, which is 10 by default.
            max_delay: 19,
            // Another arbitrary value.
            max_repeat: 27,
            min_edges: parties.len(),
            parties,
            seed,
            rgen: StdRng::seed_from_u64(seed),
        }
    }

    /// Use the given max. time delay for edges.
    pub fn with_max_delay(mut self, d: Time) -> Self {
        self.max_delay = d;
        self
    }

    /// Repeat the generated rule at most `r` times.
    pub fn with_max_repeat(mut self, r: usize) -> Self {
        self.max_repeat = r;
        self
    }

    /// Use at least `n` edges between each pair of parties.
    pub fn with_min_edges(mut self, n: usize) -> Self {
        self.min_edges = n;
        self
    }

    /// Use the given see with the internal entropy source.
    ///
    /// Useful for reproducing test runs.
    pub fn with_seed(mut self, s: u64) -> Self {
        self.seed = s;
        self.rgen = StdRng::seed_from_u64(s);
        self
    }

    /// Get the seed used for the entropy source.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Generate a sequence of random rules.
    pub fn generate(&mut self, len: usize) -> Vec<Rule> {
        let mut rules = Vec::new();

        for _ in 0..len {
            let mut rule = Rule::new("randomly generated");
            while rule.edges.len() < self.min_edges {
                let src = self
                    .parties
                    .choose(&mut self.rgen)
                    .expect("parties not empty");
                while rule.edges.get(src).map(|d| d.len()).unwrap_or(0) < self.min_edges {
                    let dst = self
                        .parties
                        .choose(&mut self.rgen)
                        .expect("parties not empty");
                    let del = self.rgen.random_range(0..self.max_delay);
                    rule = rule.plus(edge(src, dst).delay(del))
                }
            }
            rules.push(rule.repeat(self.rgen.random_range(0..self.max_repeat)))
        }

        rules
    }
}

/// A party's buffer contains messages to be delivered at some time.
#[derive(Default)]
pub struct Buffer {
    items: BTreeMap<Time, Vec<Message>>,
}

/// A party represents a node in the network.
///
/// It contains of consensus logic and a buffer of incoming messages
/// plus timeout information.
pub struct Party {
    name: Name,
    logic: Consensus,
    buffer: Buffer,
    timeout: (Time, RoundNumber),
}

impl Party {
    pub fn add_message(&mut self, t: Time, m: Message) {
        self.buffer.items.entry(t).or_default().push(m);
    }
}

/// Events are accumulated when a simulation is run to enable later inspection.
#[derive(Debug)]
pub enum Event {
    /// A vertex proposal was delivered.
    Deliver(Time, Name, RoundNumber, Name),
    /// A timeout occurred.
    Timeout(Time, Name, RoundNumber, Name),
}

impl Event {
    pub fn time(&self) -> Time {
        match self {
            Self::Deliver(t, ..) => *t,
            Self::Timeout(t, ..) => *t,
        }
    }

    pub fn is_deliver(&self) -> bool {
        matches!(self, Self::Deliver(..))
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout(..))
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deliver(t, n, r, k) => {
                write!(f, "[{t:4}] {n}: deliver (round := {r}, source := {k})")
            }
            Self::Timeout(t, n, r, m) => {
                write!(f, "[{t:4}] {n}: timeout (round := {r}, leader := {m})")
            }
        }
    }
}

/// The simulator that runs multiple parties.
pub struct Simulator {
    /// The current virtual time.
    time: Time,
    /// The duration before a timeout occurs.
    timeout: Time,
    /// The consensus committee config.
    committee: Committee,
    /// Resolve a public key to a party name.
    resolve: BTreeMap<PublicKey, Name>,
    /// The actual consensus parties.
    parties: BTreeMap<Name, Party>,
    /// The sequence of rules to apply.
    rules: Vec<Rule>,
    /// Buffer of actions per party.
    actions: Vec<(Name, Vec<Action>)>,
    /// Event trail.
    events: Vec<Event>,
}

impl Simulator {
    pub fn new<I: IntoIterator<Item = &'static str>>(names: I) -> Self {
        let keypairs: Vec<(Name, Keypair)> = names
            .into_iter()
            .map(|name| {
                let mut seed = [0; 32];
                for (b, s) in name.as_bytes().iter().zip(seed.iter_mut()) {
                    *s = *b
                }
                (name, Keypair::from_seed(seed))
            })
            .collect();

        let committee = Committee::new(
            keypairs
                .iter()
                .enumerate()
                .map(|(i, (_, k))| (i as u8, k.public_key())),
        );

        let resolve = keypairs.iter().map(|(n, k)| (k.public_key(), *n)).collect();

        let mut parties: BTreeMap<Name, Party> = keypairs
            .into_iter()
            .map(|(n, k)| {
                let p = Party {
                    name: n,
                    logic: Consensus::new(k, committee.clone(), EmptyBlocks),
                    buffer: Buffer::default(),
                    timeout: (0, RoundNumber::genesis()),
                };
                (n, p)
            })
            .collect();

        assert!(!parties.is_empty());

        let dag = Dag::new(NonZeroUsize::new(parties.len()).unwrap());

        let mut actions = Vec::new();

        for (name, party) in &mut parties {
            actions.push((*name, party.logic.go(dag.clone(), Evidence::Genesis)));
        }

        Self {
            time: 0,
            timeout: 10,
            committee,
            resolve,
            parties,
            rules: Vec::new(),
            actions,
            events: Vec::new(),
        }
    }

    pub fn rules(&mut self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().rev()
    }

    pub fn set_rules<I>(&mut self, rules: I)
    where
        I: IntoIterator<Item = Rule>,
    {
        self.rules = rules.into_iter().collect();
        self.rules.reverse()
    }

    pub fn set_timeout(&mut self, t: Time) {
        self.timeout = t;
    }

    pub fn events(&self) -> &[Event] {
        &self.events
    }

    pub fn consensus(&self, n: Name) -> &Consensus {
        &self.parties[n].logic
    }

    pub fn time(&self) -> Time {
        self.time
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    pub fn round(&self) -> Option<usize> {
        let mut it = self.parties.values().map(|p| p.logic.round());
        let r = it.clone().next()?;
        it.all(|x| r == x).then_some(*r as usize)
    }

    pub fn leader(&self, round: usize) -> Option<Name> {
        let k = self.committee.leader(round);
        self.resolve.get(&k).map(|n| &**n)
    }

    pub fn pending_messages(&self) -> usize {
        self.parties.values().fold(0, |acc, p| {
            acc + p.buffer.items.values().map(|v| v.len()).sum::<usize>()
        })
    }

    pub fn parties(&self) -> impl Iterator<Item = (PublicKey, Name)> + '_ {
        self.resolve.iter().map(|(k, n)| (*k, *n))
    }

    pub fn goto(&mut self, timeout: Time) {
        let mut rule = self.rules.pop();

        while self.time < timeout {
            debug!(time = %self.time);
            for (name, actions) in mem::take(&mut self.actions) {
                self.eval(name, actions, rule.as_ref());
            }
            self.actions = self.timeouts();
            let actions = self.deliver();
            self.actions.extend(actions);
            self.time += 1;
            if let Some(r) = &mut rule {
                if r.repeat > 0 {
                    r.repeat = r.repeat.saturating_sub(1);
                    continue;
                }
            }
            rule = self.rules.pop();
            if let Some(r) = &rule {
                debug!(time = %self.time, description = %r.descr, "next rule")
            } else {
                debug!(time = %self.time, "default rule")
            }
        }
    }

    fn eval(&mut self, party: Name, actions: Vec<Action>, rule: Option<&Rule>) {
        if let Some(r) = &rule {
            assert!((r.precond)(self), "{}: precondition failed", r.descr)
        }
        for a in actions {
            match a {
                Action::SendNoVote(to, e) => {
                    let Some(dst) = self.resolve.get(&to).and_then(|n| self.parties.get_mut(n))
                    else {
                        continue;
                    };
                    if let Some(rule) = rule {
                        if let Some(delay) = rule.lookup(party, dst.name) {
                            let m = Message::NoVote(e);
                            dst.add_message(self.time + delay(&m), m)
                        }
                    } else {
                        dst.add_message(self.time, Message::NoVote(e))
                    }
                }
                Action::SendProposal(e) => {
                    if let Some(rule) = rule {
                        for (name, delay) in rule.edges.get(party).into_iter().flatten() {
                            if let Some(p) = self.parties.get_mut(name) {
                                let m = Message::Vertex(e.clone());
                                p.add_message(self.time + delay(&m), m)
                            }
                        }
                    } else {
                        for p in self.parties.values_mut() {
                            p.add_message(self.time, Message::Vertex(e.clone()))
                        }
                    }
                }
                Action::SendTimeout(e) => {
                    if let Some(rule) = rule {
                        for (name, delay) in rule.edges.get(party).into_iter().flatten() {
                            if let Some(p) = self.parties.get_mut(name) {
                                let m = Message::Timeout(e.clone());
                                p.add_message(self.time + delay(&m), m)
                            }
                        }
                    } else {
                        for p in self.parties.values_mut() {
                            p.add_message(self.time, Message::Timeout(e.clone()))
                        }
                    }
                }
                Action::SendTimeoutCert(c) => {
                    if let Some(rule) = rule {
                        for (name, delay) in rule.edges.get(party).into_iter().flatten() {
                            if let Some(p) = self.parties.get_mut(name) {
                                let m = Message::TimeoutCert(c.clone());
                                p.add_message(self.time + delay(&m), m)
                            }
                        }
                    } else {
                        for p in self.parties.values_mut() {
                            p.add_message(self.time, Message::TimeoutCert(c.clone()))
                        }
                    }
                }
                Action::ResetTimer(r) => {
                    if let Some(p) = self.parties.get_mut(party) {
                        p.timeout.0 = self.time + self.timeout;
                        p.timeout.1 = r;
                    }
                }
                Action::Deliver(data) => {
                    let k = self.resolve.get(&data.source()).expect("known public key");
                    self.events
                        .push(Event::Deliver(self.time, party, data.round(), k))
                }
            }
        }
    }

    fn deliver(&mut self) -> Vec<(Name, Vec<Action>)> {
        let mut actions = Vec::new();
        for (name, party) in &mut self.parties {
            let mut items = party.buffer.items.split_off(&(self.time + 1));
            mem::swap(&mut party.buffer.items, &mut items);
            let mut a = Vec::new();
            for m in items.into_values().flatten() {
                a.extend(party.logic.handle_message(m))
            }
            actions.push((*name, a))
        }
        actions
    }

    fn timeouts(&mut self) -> Vec<(Name, Vec<Action>)> {
        let mut actions = Vec::new();
        for (name, party) in &mut self.parties {
            if party.timeout.0 == self.time {
                let k = self.committee.leader(*party.timeout.1 as usize);
                let l = self.resolve.get(&k).expect("known public key");
                self.events
                    .push(Event::Timeout(self.time, name, party.timeout.1, l));
                actions.push((*name, party.logic.timeout(party.timeout.1)))
            }
        }
        actions
    }
}

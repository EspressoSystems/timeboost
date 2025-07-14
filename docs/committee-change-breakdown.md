# Committee Change Logic and Flow - TimeBoost

## Overview

This document provides a detailed breakdown of the committee change logic and flow in TimeBoost, covering the switchover process, mode transitions, and cross-committee RBC (Reliable Broadcast Communication) mechanisms.

---

## 1. Committee Change Architecture

### Core Components

**Committee Management:**
- **Current Committee**: The active committee handling consensus
- **Next Committee**: The committee that will take over after transition
- **Previous Committee**: The committee that was previously active (used for handover)

**Key Data Structures:**
- `CommitteeId` - Unique identifier for each committee
- `AddressableCommittee` - Committee with network addresses
- `ConsensusTime` - Time-based committee transition scheduling

**Integration Points:**
- **Sequencer ↔ Coordinator**: Committee change coordination
- **Consensus ↔ RBC**: Cross-committee message handling
- **Network ↔ Overlay**: Peer management during transitions

---

## 2. Committee Transition Flow

### 2.1 Transition Initiation

The committee change process begins when a new committee is scheduled to take over:

```rust
// From timeboost-sequencer/src/lib.rs:218-227
pub async fn set_next_committee(
    &mut self,
    t: ConsensusTime,
    a: AddressableCommittee,
) -> Result<()> {
    self.commands
        .send(Command::NextCommittee(t, a, self.bundles.clone()))
        .await
        .map_err(|_| TimeboostError::ChannelClosed)
}
```

### 2.2 Command Processing

The `NextCommittee` command triggers the transition process:

```rust
// From timeboost-sequencer/src/lib.rs:300-311
cmd = self.commands.recv(), if pending.is_none() => match cmd {
    Some(Command::NextCommittee(t, a, b)) => {
        self.sailfish.set_next_committee(t, a.committee().clone(), a.clone()).await?;
        if a.committee().contains_key(&self.kpair.public_key()) {
            let cons = Consensus::new(self.kpair.clone(), a.committee().clone(), b);
            let acts = self.sailfish.set_next_consensus(cons);
            candidates = self.execute(acts).await?
        }
        if let Err(err) = self.decrypter.next_committee(a).await {
            error!(node = %self.label, %err, "decrypt next committee error");
        }
    }
    // ...
}
```

### 2.3 Coordinator Committee Management

The `Coordinator` manages the transition between committees:

```rust
// From sailfish/src/coordinator.rs:124-133
pub async fn set_next_committee(
    &mut self,
    t: ConsensusTime,
    c: Committee,
    a: C::CommitteeInfo,
) -> Result<(), C::Err> {
    self.buffer.retain(|_, m| m.committee() == c.id());
    self.current_consensus_mut().set_next_committee(t, c.id());
    self.comm.add_committee(a).await
}
```

---

## 3. Mode Transitions

### 3.1 Sequencer Mode Management

The sequencer operates in different modes during committee transitions:

```rust
// From timeboost-sequencer/src/lib.rs:77-90
/// Mode of operation.
#[derive(Debug, Copy, Clone)]
enum Mode {
    /// The sequencer will not produce transactions.
    Passive,
    /// The sequencer will produce transactions.
    Active,
}

impl Mode {
    fn is_passive(self) -> bool {
        matches!(self, Self::Passive)
    }
}
```


### 3.2 Coordinator State Management

The coordinator tracks its state during transitions:

```rust
// From sailfish/src/coordinator.rs:61-75
/// Internal coordinator state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Initial state.
    Start,
    /// Coordinator starts as a new committee member.
    AwaitHandover,
    /// Operating state after initialization/handover.
    Running,
}
```

### 3.3 Committee Update Logic

The coordinator updates its current committee when transitioning:

```rust
// From sailfish/src/coordinator.rs:167-188
fn update_consensus(&mut self, r: Round) -> bool {
    if self.current_committee == r.committee() {
        return false;
    }
    if self
        .previous_committees
        .iter()
        .any(|id| *id == r.committee())
    {
        // Never go back to a previous instance.
        return false;
    }
    self.instances.truncate(1);
    self.previous_committees.truncate(MAX_OLD_COMMITTEE_IDS - 1);
    self.previous_committees.insert(0, self.current_committee);
    self.current_committee = r.committee();
    debug_assert_eq!(
        self.current_committee,
        self.current_consensus().committee().id()
    );
    true
}
```


---

## 4. Cross-Committee RBC

### 4.1 RBC Committee Management

The RBC layer handles cross-committee communication during transitions:

```rust
// From sailfish-rbc/src/abraham/worker.rs:338-363
/// Add a new committee.
///
/// Peers that do not exist in the current committee are added to the network
/// as passive nodes.
async fn add_committee(&mut self, c: AddressableCommittee) -> RbcResult<()> {
    debug!(node = %self.key, committee = %c.committee().id(), "add committee");

    if self.config.committees.contains(c.committee().id()) {
        warn!(node = %self.key, committee = %c.committee().id(), "committee already added");
        return Ok(())
    }

    let Some(committee) = self.config.committees.get(self.config.committee_id) else {
        return Err(RbcError::NoCommittee(self.config.committee_id))
    };

    let mut additional = Vec::new();
    for (k, x, a) in c.entries().filter(|(k, ..)| !committee.contains_key(k)) {
        additional.push((k, x, a))
    }
    self.comm.add(additional).await?;

    self.config.committees.add(c.committee().clone());

    Ok(())
}
```


### 4.2 Committee Switchover

The RBC layer switches to use a new committee:

```rust
// From sailfish-rbc/src/abraham/worker.rs:365-388
/// Switch over to use a committee that has previously been added.
///
/// Peers that do not exist in the given committee are removed from the
/// network and all committee peers are assigned an active role.
async fn use_committee(&mut self, round: Round) -> RbcResult<()> {
    debug!(node = %self.key, %round, "use committee");
    let Some(committee) = self.config.committees.get(round.committee()) else {
        error!(node = %self.key, id = %round.committee(), "committee to use does not exist");
        return Err(RbcError::NoCommittee(round.committee()))
    };
    let old = self.comm
        .parties()
        .map(|(p, _)| p)
        .filter(|p| !committee.contains_key(p))
        .copied();
    self.comm.remove(old.collect()).await?;
    self.comm.assign(Role::Active, committee.parties().copied().collect()).await?;
    self.config.committee_id = round.committee();
    for (_, m) in self.buffer.range_mut(round.num() ..) {
        // Remove all messages from the old committee starting at round.
        m.map.retain(|d, _| d.round().committee() == round.committee())
    }
    Ok(())
}
```


### 4.3 Cross-Committee Message Handling

The RBC layer handles messages crossing committee boundaries:

```rust
// From sailfish-rbc/src/abraham/worker.rs:411-427
// Messages not directed to the current committee will be multicasted.
// This only affects handover messages and certificates which cross
// committee boundaries.
if committee_id != self.config.committee_id {
    let Some(committee) = self.config.committees.get(committee_id) else {
        return Err(RbcError::NoCommittee(committee_id))
    };
    let dest = committee.parties().copied().collect();
    self.comm.multicast(dest, *msg.round().num(), data).await?;
    debug!(node = %self.key, %digest, "message multicasted");
} else {
    self.comm.broadcast(*msg.round().num(), data).await?;
    debug!(node = %self.key, %digest, "message broadcasted");
}
```


---

## 5. Handover Process

### 5.1 Handover Initiation

The consensus layer initiates handover when committee change is detected:

```rust
// From sailfish-consensus/src/lib.rs:139-141
pub fn set_next_committee(&mut self, start: ConsensusTime, c: CommitteeId) {
    self.next_committee = Some(NextCommittee { start, id: c })
}
```


### 5.2 Handover Committee Setup

The consensus sets up the handover committee:

```rust
// From sailfish-consensus/src/lib.rs:143-145
pub fn set_handover_committee(&mut self, c: Committee) {
    self.handovers = Some(VoteAccumulator::new(c))
}
```


### 5.3 Handover Message Processing

The consensus handles handover messages from the previous committee:

```rust
// From sailfish-consensus/src/lib.rs:570-603
/// Members of the next committee receive handover messages.
pub fn handle_handover(&mut self, e: Envelope<HandoverMessage, Validated>) -> Vec<Action<T>> {
    trace!(node = %self.public_key(), round = %e.data().handover().data().round(), "handover");

    let mut actions = Vec::new();

    let (handover, _) = e.into_signed().into_data().into_parts();

    let Some(handovers) = &mut self.handovers else {
        warn!(
            node     = %self.keypair.public_key(),
            handover = %handover.data(),
            "unexpected handover message"
        );
        return actions;
    };

    match handovers.add(handover) {
        Ok(Some(cert)) => {
            let cert = cert.clone();
            actions.push(Action::SendHandoverCert(cert.clone()));
            actions.extend(self.start_committee(cert))
        }
        Ok(None) => {}
        Err(err) => {
            warn!(
                node = %self.keypair.public_key(),
                err  = %err,
                "could not add handover data to vote accumulator"
            )
        }
    }

    actions
}
```


---

## 6. Testing and Validation

### 6.1 Handover Test Structure

The system includes comprehensive handover tests:

```rust
// From tests/src/tests/timeboost/handover.rs:188-309
/// Run a handover test between a current and a next set of nodes.
async fn run_handover(curr: &[SequencerConfig], next: &[SequencerConfig]) {
    const NEXT_COMMITTEE_DELAY: u64 = 5;

    let mut tasks = JoinSet::new();
    let (bcast, _) = broadcast::channel(3);

    let a1 = curr[0].sailfish_committee().clone();
    let a2 = next[0].sailfish_committee().clone();
    let c1 = a1.committee().id();
    let c2 = a2.committee().id();

    assert_ne!(c1, c2);

    // ... test implementation continues
}
```


### 6.2 Committee Configuration

The test suite creates configurations for different committee sizes:

```rust
// From tests/src/tests/timeboost/handover.rs:40-141
fn mk_configs<C>(
    id: C,
    prev: &[SequencerConfig],
    keep: usize,
    add: NonZeroUsize,
    set_prev: bool,
) -> impl Iterator<Item = SequencerConfig>
where
    C: Into<CommitteeId>,
{
    // ... configuration creation logic
}
```


---

## 7. Committee Change Sequence Diagram

```
Time →
┌─────────────────────────────────────────────────────────────────────────┐
│                     Committee Change Process                            │
├─────────────────────────────────────────────────────────────────────────┤
│  Current Committee (C1)              │  Next Committee (C2)             │
│                                      │                                  │
│  1. Announce Committee Change        │                                  │
│  │                                   │                                  │
│  2. Set Next Committee               │                                  │
│     └─> set_next_committee(t, C2)    │                                  │
│                                      │                                  │
│  3. Add Committee to RBC             │                                  │
│     └─> add_committee(C2)            │                                  │
│                                      │                                  │
│  4. Initiate Handover               │                                  │
│     └─> SendHandover(evidence)       │                                  │
│                                      │                                  │
│  5. Handover Messages               │  ← Receive Handover              │
│     └─> Multicast to C2             │                                  │
│                                      │                                  │
│  6. Handover Certificate            │  ← Process Handover Votes        │
│     └─> Certificate formed          │                                  │
│                                      │                                  │
│  7. Committee Switch                │  ← Use Committee                 │
│     └─> use_committee(C2)           │     └─> State: Running           │
│                                      │                                  │
│  8. Cleanup Old Committee          │  ← Active Committee              │
│     └─> Remove old peers            │                                  │
│                                      │                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 8. Key Considerations

### 8.1 Safety Properties

**Committee Transition Safety:**
- Only one committee can be active at a time
- Handover messages must achieve quorum before transition
- Previous committee information is preserved for proper handover

**Message Delivery:**
- Cross-committee messages are multicasted to target committee
- Messages are buffered during committee transitions
- Duplicate detection prevents message replay

### 8.2 Performance Optimizations

**Network Efficiency:**
- Passive nodes are added before committee switch
- Active roles are assigned only to current committee members
- Old committee members are removed after successful transition

**Memory Management:**
- Message buffers are cleaned up per round
- Committee information is limited to prevent memory leaks
- Previous committee data is bounded

### 8.3 Fault Tolerance

**Byzantine Fault Tolerance:**
- Handover requires >2f+1 votes from previous committee
- Committee membership is cryptographically verified
- Invalid handover messages are rejected

**Network Partitions:**
- Committee transitions can proceed with quorum
- Partitioned nodes can rejoin after healing
- Recovery mechanisms handle missed transitions

---

## Conclusion

The committee change system in TimeBoost provides a robust, Byzantine fault-tolerant mechanism for transitioning between different consensus committees. The system ensures safety through cryptographic verification, maintains liveness through quorum-based decisions, and provides efficiency through optimized network management and message handling.

The integration between the Sequencer, Coordinator, Consensus, and RBC layers ensures seamless transitions while maintaining the security and performance properties required for a production transaction ordering system.

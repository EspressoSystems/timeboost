# Timeboost Committee Change Logic and Flow

## Overview

This document provides a detailed breakdown of the committee change logic and flow in TimeBoost, covering the switchover process, mode transitions, and cross-committee RBC (Reliable Broadcast Communication) mechanisms.

---

## 1. Committee Change Architecture

### Core Components

**Committee Management:**
- **Current Committee (C1)**: The active committee handling consensus, also referred to as "previous committee" during handover from C2's perspective
- **Next Committee (C2)**: The committee that will take over after transition, receives handover messages from C1
- **Previous Committee**: The committee that was previously active (used for handover)

**Committee Perspectives:**
- From C1's perspective: C1 is "current", C2 is "next"
- From C2's perspective: C1 is "previous", C2 is becoming "current"
- Only two committees are involved at any time during handover

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
```

**Key Role Behaviors:**
- **Active peers**: Receive all broadcast messages (consensus vertices, timeouts, etc.)
- **Passive peers**: Excluded from broadcasts but can receive direct unicast/multicast messages
- **Committee transition strategy**: C2 members start as passive, then become active after handover


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

**Passive Node Addition Process:**
When a new committee (C2) is added, its members that don't exist in the current committee (C1) are added to the network as **passive peers**. This allows C2 to:
- Connect to the network early
- Receive targeted messages via multicast/unicast
- Build network connections before becoming active
- Prepare for consensus participation without interfering with C1's broadcasts


### 4.2 Committee Switchover with Role Management

The RBC layer switches to use a new committee and promotes passive peers to active:

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

**Role Transition Process:**
1. **Remove old peers**: Nodes not in the new committee are removed from the network
2. **Promote to active**: All C2 committee members are assigned `Role::Active`
3. **Update committee ID**: The worker now considers C2 as the current committee
4. **Clean buffers**: Remove messages from the old committee to prevent interference

**Critical Insight**: This role promotion is what enables C2 to start receiving broadcast messages (consensus vertices) that were previously only sent to C1 as active peers.


### 4.3 Cross-Committee Message Routing with Role-Based Delivery

The RBC layer handles messages crossing committee boundaries with intelligent routing:

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

**Why C2 Does NOT Receive Consensus Vertices During Transition:**

1. **Early Passive Addition**: C2 nodes are added as passive peers when the committee is first announced
2. **Broadcast Exclusion**: Passive peers are excluded from broadcasts, so C2 does NOT receive consensus vertices during transition
3. **Handover Messages Only**: C1 sends only handover messages to C2 via multicast (handover messages contain round info, not vertices)
4. **Role Promotion**: Once handover completes, C2 members are promoted to active role
5. **Broadcast Reception**: Only AFTER promotion does C2 start receiving broadcast consensus vertices as the new active committee

**Message Delivery Strategy by Type:**
- **Consensus vertices (same committee)**: Broadcast to active peers only - C2 excluded until promotion
- **Handover messages (cross-committee)**: Multicast to specific committee members (bypasses role filtering)
- **Timeout/NoVote messages**: Broadcast to active peers or unicast to specific leaders
- **Certificates**: Broadcast to active peers or multicast to target committee


---

## 5. Handover Process

### 5.1 Handover Initiation and Setup

The consensus layer initiates and sets up the handover when a committee change is detected:

```rust
// From sailfish-consensus/src/lib.rs:139-145
pub fn set_next_committee(&mut self, start: ConsensusTime, c: CommitteeId) {
    self.next_committee = Some(NextCommittee { start, id: c })
}

pub fn set_handover_committee(&mut self, c: Committee) {
    self.handovers = Some(VoteAccumulator::new(c))
}
```

### 5.2 State Reconstruction: The Reality of Committee Handover

**Key Insight**: C2 does not receive a state snapshot from C1, but this is **NOT** because C2 was receiving consensus vertices during the transition. The actual mechanism is more nuanced.

**What Actually Happens:**

1. **Passive Peer Phase**: When C2 is first added to the network:
   - C2 members are added as **passive peers** to the network
   - Passive peers are excluded from broadcasts (including consensus vertex broadcasts)
   - C2 can establish network connections but does **NOT** receive regular consensus vertices
   - C2 waits in `AwaitHandover` state until receiving handover messages

2. **Handover Messages Only**: During the handover period:
   - C1 sends **handover messages** specifically to C2 via multicast
   - **Handover messages contain only round number and committee ID** - no vertices!
   ```rust
   pub struct Handover {
       round: Round,        // Last committed round by C1
       next: CommitteeId,   // C2's committee ID
   }
   ```
   - These handover messages do NOT contain consensus vertices or state data

3. **Role Promotion Triggers State Sync**: After handover certificate formation:
   - C2 members are promoted to **active peer** role via `use_committee()`
   - **Only AFTER promotion** does C2 start receiving broadcast consensus vertices
   - C2 must reconstruct state from its **own consensus operation**, not from received vertices

**State Reconstruction Reality:**

```rust
// From sailfish-consensus/src/lib.rs:1133-1165
fn start_committee(&mut self, cert: Certificate<Handover>) -> Vec<Action<T>> {
    let r = cert.data().round().num();
    self.state = State::Running;
    self.committed_round = r;  // Set from handover certificate
    self.round = r + 1;       // Start from next round
    
    // Create first vertex with handover evidence
    let vertex = Vertex::new(
        Round::new(self.round, self.committee.id()),
        Evidence::Handover(cert),  // Use handover cert as evidence
        self.datasource.next(self.round),
        &self.keypair,
    );
}
```

**Why No State Snapshot is Needed:**
- C2 doesn't reconstruct C1's state - it **starts fresh** from the handover round
- The handover certificate provides cryptographic proof of C1's last committed round
- C2 uses this as **evidence** for its first vertex, bootstrapping a new consensus history
- C2 builds its own DAG starting from the handover point, not from reconstructing C1's DAG
- The consensus protocol is designed so committees can hand off at round boundaries without full state transfer

### 5.3 DAG State Persistence and SMR Guarantees

**Critical Understanding**: The confusion about DAG state persistence arises from conflating consensus-layer state with application-layer state. Sailfish provides SMR (State Machine Replication) guarantees, but the committee change mechanism operates at different layers:

**Layer Separation:**

1. **Consensus Layer (DAG vertices)**: Committee-specific
   - Each committee maintains its own DAG structure
   - DAG vertices are not transferred between committees
   - Handover only provides cryptographic proof of the last committed round

2. **Application Layer (SMR state)**: Committee-independent
   - The application state machine (e.g., transaction ordering, balance updates) persists across committees
   - Historical data accessibility is maintained at the application layer, not consensus layer
   - SMR guarantees are preserved through proper application state management

**How Timeboost Sequencer State Persists Across Committees:**

The actual mechanism is through the `BundleQueue` which contains the sequencer's application state:

```rust
// From timeboost-sequencer/src/lib.rs:224 and timeboost-sequencer/src/queue.rs
// The BundleQueue is cloned and passed to the new committee
self.commands
    .send(Command::NextCommittee(t, a, self.bundles.clone()))
    .await

// BundleQueue contains the persistent sequencer state
struct Inner {
    priority_addr: Address,
    time: Timestamp,
    index: DelayedInboxIndex,
    priority: BTreeMap<Epoch, BTreeMap<SeqNo, SignedPriorityBundle>>,  // Persists across committees
    regular: VecDeque<(Instant, Bundle)>,                              // Persists across committees  
    dkg: Option<DkgBundle>,                                            // Persists across committees
    // ... other fields
}

// When new committee is created, it receives the same BundleQueue
let cons = Consensus::new(self.kpair.clone(), a.committee().clone(), b);  // 'b' is the cloned BundleQueue
```

**SMR Guarantee Preservation:**
- **Safety**: All committees agree on the same sequence of committed operations up to the handover point
- **Liveness**: New committee can continue processing after handover
- **Persistence**: Application state is maintained independently of consensus DAG structure
- **Accessibility**: Historical data remains available through application layer storage/indexing

**Why This Design Works:**
- The consensus layer provides **ordering** guarantees, not storage guarantees
- The application layer is responsible for **persistent state** and **historical data**
- Committee handover transfers the **authority to continue ordering**, not the entire state
- SMR properties are maintained because both committees agree on the committed sequence up to handover

**Practical Implications:**
- **Bundle continuity**: Pending priority and regular bundles are preserved across committee changes via BundleQueue cloning
- **Sequencer state persistence**: The new committee inherits the exact same transaction pool state (priority bundles, regular bundles, DKG state)
- **No transaction loss**: Bundles submitted before committee change remain available for inclusion by the new committee
- **Seamless transition**: Users don't need to resubmit transactions during committee changes
- **DAG vs Application State**: The consensus DAG is committee-specific, but the transaction sequencing state (BundleQueue) persists across committees


### 5.4 Handover Message Processing

The consensus handles `HandoverMessage` from the previous committee, ensuring that signatures and evidence are verified:

```rust
// From sailfish-types/src/message.rs:649-673
pub struct HandoverMessage {
    handover: Signed<Handover>,
    evidence: Evidence,
}
pub struct Handover {
    round: Round,
    next: CommitteeId,
}
```

The process ensures smooth transition by adequately handling the incoming data:

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


### 5.5 Committee Change Announcement

**External Signal Source**: The committee change is announced through an external signal (not originating from the consensus layer itself):

```rust
// From tests/src/tests/timeboost/handover.rs:251-253
// Inform about upcoming committee change:
let t = ConsensusTime(Timestamp::now() + NEXT_COMMITTEE_DELAY);
bcast.send(Cmd::NextCommittee(t, a2)).unwrap();
```

**Announcement Flow:**
1. **External Module**: A higher-level coordinator or admin module triggers the committee change
2. **Timestamp Publishing**: The change timestamp is made publicly available to all nodes
3. **Committee Setup**: Both C1 and C2 nodes receive the announcement and prepare for transition
4. **Delayed Execution**: The actual handover waits until the announced timestamp

### 5.6 Committee Overlap Constraints

**Critical Timing Requirements:**

**C2 Start Timing:**
- C2 must start **before** the announced handover timestamp
- C2 needs time to connect to the network and sync DAG state
- Early start ensures C2 is ready to receive handover messages

**C1 Shutdown Timing:**
- C1 enters `State::Shutdown` when handover begins but continues operating
- C1 must remain active **until** handover completion (quorum of handover messages)
- C1 ignores messages with rounds > shutdown round to prevent interference

```rust
// From sailfish-consensus/src/lib.rs:1121-1129
fn handover(&mut self) -> Option<Handover> {
    let next = self.next_committee.as_mut()?;
    if self.state.is_shutdown() || next.start > self.clock {
        return None;  // Wait for announced time
    }
    // Start handover process
    self.state = State::Shutdown(self.committed_round);
    Some(Handover::new(r, next.id))
}
```

**Overlap Period:**
- Both committees run simultaneously during handover
- C1 sends handover messages while still processing its own consensus
- C2 waits in `AwaitHandover` state until receiving sufficient handover votes

### 5.7 Message Routing During Transition

**Message Types and Routing:**

**Broadcast to All (Same Committee):**
- ✓ `Vertex` proposals (within committee)
- ✓ `Timeout` messages (within committee) 
- ✓ `TimeoutCert` certificates (within committee)

**Multicast to Specific Committee:**
- ✓ `Handover` messages (C1 → C2 committee members)
- ✓ `HandoverCert` certificates (C1 → C2 committee members)

```rust
// From sailfish-rbc/src/abraham/worker.rs:411-424
// Messages not directed to the current committee will be multicasted
if committee_id != self.config.committee_id {
    let dest = committee.parties().copied().collect();
    self.comm.multicast(dest, *msg.round().num(), data).await?;
} else {
    self.comm.broadcast(*msg.round().num(), data).await?;
}
```

**Point-to-Point (Unicast):**
- ✓ `NoVote` messages (to specific round leader)

**Messages Ignored by Whom:**

**C1 (Current Committee) Ignores:**
- ✗ Messages with rounds > shutdown round (after handover starts)
- ✗ Handover messages directed to C2
- ✗ Messages from unknown/future committees

**C2 (Next Committee) Behavior:**
- ✗ Does NOT receive normal consensus vertex broadcasts (passive peer role excludes from broadcasts)
- ✓ Receives handover messages via multicast from C1
- ✗ Ignores messages from old committees (previous to C1)
- ✗ Ignores duplicate handover messages from same signer
- ✓ Starts receiving broadcasts only AFTER promotion to active role

**Coordinator-Level Buffering:**
```rust
// From sailfish/src/coordinator.rs:259-267
if !(m.is_handover() || m.is_handover_cert()) {
    return Ok(Vec::new())  // Ignore non-handover messages for unknown committees
}
if self.previous_committees.contains(&c) {
    return Ok(Vec::new())  // Ignore messages from old committees
}
self.buffer.insert(m.signing_key().copied(), m);  // Buffer handover messages
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
│  4. Initiate Handover                │                                  │
│     └─> SendHandover(evidence)       │                                  │
│                                      │                                  │
│  5. Handover Messages                │  ← Receive Handover              │
│     └─> Multicast to C2              │                                  │
│                                      │                                  │
│  6. Handover Certificate             │  ← Process Handover Votes        │
│     └─> Certificate formed           │                                  │
│                                      │                                  │
│  7. Committee Switch                 │  ← Use Committee                 │
│     └─> use_committee(C2)            │     └─> State: Running           │
│                                      │                                  │
│  8. Cleanup Old Committee            │  ← Active Committee              │
│     └─> Remove old peers             │                                  │
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

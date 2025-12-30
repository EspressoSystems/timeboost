#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::future::pending;
use std::iter::repeat;
use std::sync::Arc;
use std::time::Duration;

use bimap::BiHashMap;
use bytes::{Bytes, BytesMut};
use multisig::{PublicKey, x25519};
use parking_lot::Mutex;
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Interval, MissedTickBehavior, sleep, timeout};
use tokio::{
    spawn,
    task::{self, AbortHandle, JoinHandle, JoinSet},
};
use tracing::{debug, error, info, trace, warn};

use crate::chan;
use crate::error::Empty;
use crate::frame::{Header, Type};
use crate::tcp::{self, Stream};
use crate::time::{Countdown, Timestamp};
use crate::{Address, Id, MAX_MESSAGE_SIZE, NetworkError, PEER_CAPACITY, Role};

#[cfg(feature = "metrics")]
use crate::metrics::NetworkMetrics;

type Result<T> = std::result::Result<T, NetworkError>;

/// Max. message size using noise handshake.
const MAX_NOISE_HANDSHAKE_SIZE: usize = 1024;

/// Max. message size using noise protocol.
const MAX_NOISE_MESSAGE_SIZE: usize = 64 * 1024;

/// Max. number of bytes for payload data.
const MAX_PAYLOAD_SIZE: usize = 63 * 1024;

/// Noise parameters to initialize the builders.
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Interval between ping protocol.
const PING_INTERVAL: Duration = Duration::from_secs(15);

/// Max. allowed duration of a single TCP connect attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Max. allowed duration of a Noise handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max. allowed duration to wait for a peer to answer.
///
/// This is started when we have sent a ping. Unless we receive
/// some data back within this duration, the connection times
/// out and is dropped.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// `Network` is the API facade of this crate.
#[derive(Debug)]
pub struct Network {
    /// Name of this network.
    name: &'static str,

    /// Log label.
    label: PublicKey,

    /// The network participants.
    parties: HashMap<PublicKey, Role>,

    /// MPSC sender of server task instructions.
    tx: Sender<Command>,

    /// MPSC receiver of messages from a remote party.
    ///
    /// The public key identifies the remote.
    rx: Receiver<(PublicKey, Bytes, Option<OwnedSemaphorePermit>)>,

    /// Handle of the server task that has been spawned by `Network`.
    srv: JoinHandle<Result<Empty>>,
}

impl Drop for Network {
    fn drop(&mut self) {
        self.srv.abort()
    }
}

/// Server task instructions.
#[derive(Debug)]
pub(crate) enum Command {
    /// Add the given peers.
    Add(Vec<(PublicKey, x25519::PublicKey, Address)>),
    /// Remove the given peers.
    Remove(Vec<PublicKey>),
    /// Assign a `Role` to the given peers.
    Assign(Role, Vec<PublicKey>),
    /// Send a message to one peer.
    Unicast(PublicKey, Option<Id>, Bytes),
    /// Send a message to some peers.
    Multicast(Vec<PublicKey>, Option<Id>, Bytes),
    /// Send a message to all peers with `Role::Active`.
    Broadcast(Option<Id>, Bytes),
}

/// The `Server` is accepting connections and also establishing and
/// maintaining connections with all parties.
#[derive(Debug)]
struct Server<T: tcp::Listener> {
    /// Network name.
    name: &'static str,

    /// This server's public key.
    key: PublicKey,

    /// This server's role.
    role: Role,

    /// The X25519 keypair, used with Noise.
    keypair: x25519::Keypair,

    /// MPSC sender for messages received over a connection to a party.
    ///
    /// (see `Network` for the accompanying receiver).
    ibound: Sender<(PublicKey, Bytes, Option<OwnedSemaphorePermit>)>,

    /// MPSC receiver for server task instructions.
    ///
    /// (see `Network` for the accompanying sender).
    obound: Receiver<Command>,

    /// All parties of the network and their addresses.
    peers: HashMap<PublicKey, Peer>,

    /// Bi-directional mapping of Ed25519 and X25519 keys to identify
    /// remote parties.
    index: BiHashMap<PublicKey, x25519::PublicKey>,

    /// Find the public key given a tokio task ID.
    task2key: HashMap<task::Id, PublicKey>,

    /// Currently active connect attempts.
    connecting: HashMap<PublicKey, ConnectTask>,

    /// Currently active connections (post handshake).
    active: HashMap<PublicKey, IoTask>,

    /// Tasks performing a handshake with a remote party.
    handshake_tasks: JoinSet<Result<(T::Stream, TransportState)>>,

    /// Tasks connecting to a remote party and performing a handshake.
    connect_tasks: JoinSet<(T::Stream, TransportState)>,

    /// Active I/O tasks, exchanging data with remote parties.
    io_tasks: JoinSet<Result<()>>,

    /// Interval at which to ping peers.
    ping_interval: Interval,

    /// For gathering network metrics.
    #[cfg(feature = "metrics")]
    metrics: Arc<NetworkMetrics>,
}

#[derive(Debug)]
struct Peer {
    addr: Address,
    role: Role,
}

/// A connect task.
#[derive(Debug)]
struct ConnectTask {
    h: AbortHandle,
}

// Make sure the task is stopped when `ConnectTask` is dropped.
impl Drop for ConnectTask {
    fn drop(&mut self) {
        self.h.abort();
    }
}

/// An I/O task, reading data from and writing data to a remote party.
#[derive(Debug)]
struct IoTask {
    /// Abort handle of the read-half of the connection.
    rh: AbortHandle,

    /// Abort handle of the write-half of the connection.
    wh: AbortHandle,

    /// MPSC sender of outgoing messages to the remote.
    tx: chan::Sender<Message>,
}

// Make sure all tasks are stopped when `IoTask` is dropped.
impl Drop for IoTask {
    fn drop(&mut self) {
        self.rh.abort();
        self.wh.abort();
    }
}

/// Unify the various data types we want to send to the writer task.
#[derive(Debug)]
enum Message {
    Data(Bytes),
    Ping(Timestamp),
    Pong(Timestamp),
}

impl Network {
    /// Create a new `Network`.
    pub async fn create<P, A1, A2>(
        name: &'static str,
        bind_to: A1,
        label: PublicKey,
        xp: x25519::Keypair,
        group: P,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, x25519::PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
    {
        Self::generic_create::<tokio::net::TcpListener, _, _, _>(name, bind_to, label, xp, group)
            .await
    }

    /// Create a new `Network` for tests with [`turmoil`].
    ///
    /// *Requires feature* `"turmoil"`.
    #[cfg(feature = "turmoil")]
    pub async fn create_turmoil<P, A1, A2>(
        name: &'static str,
        bind_to: A1,
        label: PublicKey,
        xp: x25519::Keypair,
        group: P,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, x25519::PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
    {
        Self::generic_create::<turmoil::net::TcpListener, _, _, _>(name, bind_to, label, xp, group)
            .await
    }

    async fn generic_create<T, P, A1, A2>(
        name: &'static str,
        bind_to: A1,
        label: PublicKey,
        xp: x25519::Keypair,
        group: P,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, x25519::PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
        T: tcp::Listener + Send + 'static,
        T::Stream: Unpin + Send,
    {
        let bind_addr = bind_to.into();
        let listener = T::bind(&bind_addr)
            .await
            .map_err(|e| NetworkError::Bind(bind_addr, e))?;

        debug!(%name, node = %label, addr = %listener.local_addr()?, "listening");

        let mut parties = HashMap::new();
        let mut peers = HashMap::new();
        let mut index = BiHashMap::new();

        for (k, x, a) in group {
            parties.insert(k, Role::Active);
            index.insert(k, x);
            peers.insert(
                k,
                Peer {
                    addr: a.into(),
                    role: Role::Active,
                },
            );
        }

        // Command channel from application to network.
        let (otx, orx) = mpsc::channel(PEER_CAPACITY * peers.len());

        // Channel of messages from peers to the application.
        //
        // Inbound messages from each peer are allowed to accumulate up to
        // 2 * PEER_CAPACITY (see `spawn_io` below), leading to a total
        // allowed inbound capacity of c = (n - 1) * 2 * PEER_CAPACITY
        // (where n is the number of parties).
        //
        // This leaves room for n * 3 * PEER_CAPACITY - c messages we
        // receive from ourselves.
        let (itx, irx) = mpsc::channel(PEER_CAPACITY * peers.len() * 3);

        let mut interval = tokio::time::interval(PING_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let server = Server {
            name,
            keypair: xp,
            key: label,
            role: Role::Active,
            ibound: itx,
            obound: orx,
            peers,
            index,
            connecting: HashMap::new(),
            active: HashMap::new(),
            task2key: HashMap::new(),
            handshake_tasks: JoinSet::new(),
            connect_tasks: JoinSet::new(),
            io_tasks: JoinSet::new(),
            ping_interval: interval,
            #[cfg(feature = "metrics")]
            metrics: Arc::new(
                NetworkMetrics::new(name, parties.keys().copied().filter(|k| *k != label))
                    .expect("valid metrics definitions"),
            ),
        };

        Ok(Self {
            name,
            label,
            parties,
            rx: irx,
            tx: otx,
            srv: spawn(server.run(listener)),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.label
    }

    pub fn parties(&self) -> impl Iterator<Item = (&PublicKey, &Role)> {
        self.parties.iter()
    }

    /// Send a message to a party, identified by the given public key.
    pub async fn unicast(&self, to: PublicKey, msg: Bytes) -> Result<()> {
        if msg.len() > MAX_MESSAGE_SIZE {
            warn!(
                name = %self.name,
                node = %self.label,
                %to,
                len = %msg.len(),
                "message too large to send"
            );
            return Err(NetworkError::MessageTooLarge);
        }
        self.tx
            .send(Command::Unicast(to, None, msg))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Send a message to all parties.
    pub async fn broadcast(&self, msg: Bytes) -> Result<()> {
        if msg.len() > MAX_MESSAGE_SIZE {
            warn!(
                name = %self.name,
                node = %self.label,
                len = %msg.len(),
                "message too large to broadcast"
            );
            return Err(NetworkError::MessageTooLarge);
        }
        self.tx
            .send(Command::Broadcast(None, msg))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Receive a message from a remote party.
    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
        let (k, b, _) = self.rx.recv().await.ok_or(NetworkError::ChannelClosed)?;
        Ok((k, b))
    }

    /// Add the given peers to the network.
    ///
    /// NB that peers added here are passive. See `Network::assign` for
    /// giving peers a different `Role`.
    pub async fn add(&mut self, peers: Vec<(PublicKey, x25519::PublicKey, Address)>) -> Result<()> {
        self.parties
            .extend(peers.iter().map(|(p, ..)| (*p, Role::Passive)));
        self.tx
            .send(Command::Add(peers))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Remove the given peers from the network.
    pub async fn remove(&mut self, peers: Vec<PublicKey>) -> Result<()> {
        for p in &peers {
            self.parties.remove(p);
        }
        self.tx
            .send(Command::Remove(peers))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Assign the given role to the given peers.
    pub async fn assign(&mut self, r: Role, peers: Vec<PublicKey>) -> Result<()> {
        for p in &peers {
            if let Some(role) = self.parties.get_mut(p) {
                *role = r
            }
        }
        self.tx
            .send(Command::Assign(r, peers))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Get a clone of the MPSC sender.
    pub(crate) fn sender(&self) -> Sender<Command> {
        self.tx.clone()
    }
}

impl<T> Server<T>
where
    T: tcp::Listener + Send + 'static,
    T::Stream: Unpin + Send,
{
    /// Runs the main loop of this network node.
    ///
    /// This function:
    ///
    /// - Tries to connect to each remote peer in the committee.
    /// - Handles tasks that have been completed or terminated.
    /// - Processes new messages we received on the network.
    async fn run(mut self, listener: T) -> Result<Empty> {
        self.handshake_tasks.spawn(pending());
        self.io_tasks.spawn(pending());

        // Connect to all peers.
        for k in self
            .peers
            .keys()
            .filter(|k| **k != self.key)
            .copied()
            .collect::<Vec<_>>()
        {
            self.spawn_connect(k)
        }

        loop {
            trace!(
                name       = %self.name,
                node       = %self.key,
                active     = %self.active.len(),
                connects   = %self.connect_tasks.len(),
                handshakes = %self.handshake_tasks.len().saturating_sub(1), // -1 for `pending()`
                io_tasks   = %self.io_tasks.len().saturating_sub(1), // -1 for `pending()`
                tasks_ids  = %self.task2key.len(),
                iqueue     = %self.ibound.capacity(),
                oqueue     = %self.obound.capacity(),
            );

            #[cfg(feature = "metrics")]
            {
                self.metrics.iqueue.set(self.ibound.capacity() as i64);
                self.metrics.oqueue.set(self.obound.capacity() as i64);
            }

            tokio::select! {
                // Accepted a new connection.
                i = listener.accept() => match i {
                    Ok((s, a)) => {
                        debug!(name = %self.name, node = %self.key, addr = %a, "accepted connection");
                        self.spawn_handshake(s)
                    }
                    Err(e) => {
                        warn!(name = %self.name, node = %self.key, err = %e, "error accepting connection")
                    }
                },
                // The handshake of an inbound connection completed.
                Some(h) = self.handshake_tasks.join_next() => match h {
                    Ok(Ok((s, t))) => {
                        let Some(k) = self.lookup_peer(&t) else {
                            info!(
                                name = %self.name,
                                node = %self.key,
                                peer = ?t.get_remote_static().and_then(|k| x25519::PublicKey::try_from(k).ok()),
                                addr = ?s.peer_addr().ok(),
                                "unknown peer"
                            );
                            continue
                        };
                        if !self.is_valid_ip(&k, &s) {
                            warn!(
                                name = %self.name,
                                node = %self.key,
                                peer = %k,
                                addr = ?s.peer_addr().ok(), "invalid peer ip addr"
                            );
                            continue
                        }
                        // We only accept connections whose party has a public key that
                        // is larger than ours, or if we do not have a connection for
                        // that key at the moment.
                        if k > self.key || !self.active.contains_key(&k) {
                            self.spawn_io(k, s, t)
                        } else {
                            debug!(
                                name = %self.name,
                                node = %self.key,
                                peer = %k,
                                "dropping accepted connection"
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(name = %self.name, node = %self.key, err = %e, "handshake failed")
                    }
                    Err(e) => {
                        if !e.is_cancelled() {
                            error!(
                                name = %self.name,
                                node = %self.key,
                                err = %e,
                                "handshake task panic"
                            );
                        }
                    }
                },
                // One of our connection attempts completed.
                Some(tt) = self.connect_tasks.join_next_with_id() => {
                    match tt {
                        Ok((id, (s, t))) => {
                            self.on_connect_task_end(id);
                            let Some(k) = self.lookup_peer(&t) else {
                                warn!(
                                    name = %self.name,
                                    node = %self.key,
                                    peer = ?t.get_remote_static().and_then(|k| x25519::PublicKey::try_from(k).ok()),
                                    addr = ?s.peer_addr().ok(),
                                    "connected to unknown peer"
                                );
                                continue
                            };
                            // We only keep the connection if our key is larger than the remote,
                            // or if we do not have a connection for that key at the moment.
                            if k < self.key || !self.active.contains_key(&k) {
                                self.spawn_io(k, s, t)
                            } else {
                                debug!(
                                    name = %self.name,
                                    node = %self.key,
                                    peer = %k,
                                    "dropping new connection"
                                );
                            }
                        }
                        Err(e) => {
                            if !e.is_cancelled() {
                                error!(
                                    name = %self.name,
                                    node = %self.key,
                                    err = %e,
                                    "connect task panic"
                                );
                            }
                            self.on_connect_task_end(e.id());
                        }
                    }
                },
                // A read or write task completed.
                Some(io) = self.io_tasks.join_next_with_id() => {
                    match io {
                        Ok((id, r)) => {
                            if let Err(e) = r {
                                warn!(name = %self.name, node = %self.key, err = %e, "i/o error")
                            }
                            self.on_io_task_end(id);
                        }
                        Err(e) => {
                            if e.is_cancelled() {
                                // If one half completes we cancel the other, so there is
                                // nothing else to do here, except to remove the cancelled
                                // tasks's ID. Same if we kill the connection, both tasks
                                // get cancelled.
                                self.task2key.remove(&e.id());
                                continue
                            }
                            // If the task has not been cancelled, it must have panicked.
                            error!(name = %self.name, node = %self.key, err = %e, "i/o task panic");
                            self.on_io_task_end(e.id())
                        }
                    };
                },
                cmd = self.obound.recv() => match cmd {
                    Some(Command::Add(peers)) => {
                        for (k, x, a) in peers {
                            if self.peers.contains_key(&k) {
                                warn!(
                                    name = %self.name,
                                    node = %self.key,
                                    peer = %k,
                                    "peer to add already exists"
                                );
                                continue
                            }
                            info!(
                                name = %self.name,
                                node = %self.key,
                                peer = %k,
                                "adding peer"
                            );
                            let p = Peer { addr: a, role: Role::Passive };
                            self.peers.insert(k, p);
                            self.index.insert(k, x);
                            self.spawn_connect(k)
                        }
                    }
                    Some(Command::Remove(peers)) => {
                        for k in &peers {
                            info!(
                                name = %self.name,
                                node = %self.key,
                                peer = %k,
                                "removing peer"
                            );
                            self.peers.remove(k);
                            self.index.remove_by_left(k);
                            self.connecting.remove(k);
                            self.active.remove(k);
                        }
                    }
                    Some(Command::Assign(role, peers)) => {
                        for k in &peers {
                            if let Some(p) = self.peers.get_mut(k) {
                                p.role = role
                            } else {
                                warn!(
                                    name = %self.name,
                                    node = %self.key,
                                    peer = %k,
                                    role = ?role,
                                    "peer to assign role to not found"
                                );
                            }
                        }
                    }
                    Some(Command::Unicast(to, id, m)) => {
                        if to == self.key {
                            trace!(
                                name  = %self.name,
                                node  = %self.key,
                                to    = %to,
                                len   = %m.len(),
                                queue = self.ibound.capacity(),
                                "sending message"
                            );
                            if self.ibound.try_send((self.key, m, None)).is_err() {
                                warn!(
                                    name = %self.name,
                                    node = %self.key,
                                    cap  = %self.ibound.capacity(),
                                    "channel full => dropping unicast message"
                                )
                            }
                            continue
                        }
                        if let Some(task) = self.active.get(&to) {
                            trace!(
                                name  = %self.name,
                                node  = %self.key,
                                to    = %to,
                                len   = %m.len(),
                                queue = task.tx.capacity(),
                                "sending message"
                            );
                            #[cfg(feature = "metrics")]
                            self.metrics.set_peer_oqueue_cap(&to, task.tx.capacity());
                            task.tx.send(id, Message::Data(m))
                        }
                    }
                    Some(Command::Multicast(peers, id, m)) => {
                        if peers.contains(&self.key) {
                            trace!(
                                name  = %self.name,
                                node  = %self.key,
                                to    = %self.key,
                                len   = %m.len(),
                                queue = self.ibound.capacity(),
                                "sending message"
                            );
                            if self.ibound.try_send((self.key, m.clone(), None)).is_err() {
                                warn!(
                                    name = %self.name,
                                    node = %self.key,
                                    cap  = %self.ibound.capacity(),
                                    "channel full => dropping multicast message"
                                )
                            }
                        }
                        for (to, task) in &self.active {
                            if !peers.contains(to) {
                                continue
                            }
                            trace!(
                                name  = %self.name,
                                node  = %self.key,
                                to    = %to,
                                len   = %m.len(),
                                queue = task.tx.capacity(),
                                "sending message"
                            );
                            #[cfg(feature = "metrics")]
                            self.metrics.set_peer_oqueue_cap(to, task.tx.capacity());
                            task.tx.send(id, Message::Data(m.clone()))
                        }
                    }
                    Some(Command::Broadcast(id, m)) => {
                        if self.role.is_active() {
                            trace!(
                                name  = %self.name,
                                node  = %self.key,
                                to    = %self.key,
                                len   = %m.len(),
                                queue = self.ibound.capacity(),
                                "sending message"
                            );
                            if self.ibound.try_send((self.key, m.clone(), None)).is_err() {
                                warn!(
                                    name = %self.name,
                                    node = %self.key,
                                    cap  = %self.ibound.capacity(),
                                    "channel full => dropping broadcast message"
                                )
                            }
                        }
                        for (to, task) in &self.active {
                            if Some(Role::Active) != self.peers.get(to).map(|p| p.role) {
                                continue
                            }
                            trace!(
                                name  = %self.name,
                                node  = %self.key,
                                to    = %to,
                                len   = %m.len(),
                                queue = task.tx.capacity(),
                                "sending message"
                            );
                            #[cfg(feature = "metrics")]
                            self.metrics.set_peer_oqueue_cap(to, task.tx.capacity());
                            task.tx.send(id, Message::Data(m.clone()))
                        }
                    }
                    None => {
                        return Err(NetworkError::ChannelClosed)
                    }
                },
                _ = self.ping_interval.tick() => {
                    let now = Timestamp::now();
                    for task in self.active.values() {
                        task.tx.send(None, Message::Ping(now))
                    }
                }
            }
        }
    }

    /// Handles a completed connect task.
    fn on_connect_task_end(&mut self, id: task::Id) {
        let Some(k) = self.task2key.remove(&id) else {
            error!(name = %self.name, node = %self.key, "no key for connect task");
            return;
        };
        self.connecting.remove(&k);
    }

    /// Handles a completed I/O task.
    ///
    /// This function will get the public key of the task that was terminated
    /// and then cleanly removes the associated I/O task data and re-connects
    /// to the peer node it was interacting with.
    fn on_io_task_end(&mut self, id: task::Id) {
        let Some(k) = self.task2key.remove(&id) else {
            error!(name = %self.name, node = %self.key, "no key for i/o task");
            return;
        };
        let Some(task) = self.active.get(&k) else {
            return;
        };
        if task.rh.id() == id {
            debug!(
                name = %self.name,
                node = %self.key,
                peer = %k,
                "read-half closed => dropping connection"
            );
            self.active.remove(&k);
            self.spawn_connect(k)
        } else if task.wh.id() == id {
            debug!(
                name = %self.name,
                node = %self.key,
                peer = %k,
                "write-half closed => dropping connection"
            );
            self.active.remove(&k);
            self.spawn_connect(k)
        } else {
            debug!(
                name = %self.name,
                node = %self.key,
                peer = %k,
                "i/o task was previously replaced"
            );
        }
    }

    /// Spawns a new connection task to a peer identified by public key.
    ///
    /// This function will look up the x25519 public key of the ed25519 key
    /// and the remote address and then spawn a connection task.
    fn spawn_connect(&mut self, k: PublicKey) {
        if self.connecting.contains_key(&k) {
            debug!(name = %self.name, node = %self.key, peer = %k, "connect task already started");
            return;
        }
        let x = self.index.get_by_left(&k).expect("known public key");
        let p = self.peers.get(&k).expect("known peer");
        let h = self.connect_tasks.spawn(connect(
            self.name,
            (self.key, self.keypair.clone()),
            (k, *x),
            p.addr.clone(),
            #[cfg(feature = "metrics")]
            self.metrics.clone(),
        ));
        assert!(self.task2key.insert(h.id(), k).is_none());
        self.connecting.insert(k, ConnectTask { h });
    }

    /// Spawns a new `Noise` responder handshake task using the IK pattern.
    ///
    /// This function will create the responder handshake machine using its
    /// own private key and then spawn a task that awaits an initiator handshake
    /// to which it will respond.
    fn spawn_handshake(&mut self, s: T::Stream) {
        let h = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(&self.keypair.secret_key().as_bytes())
            .expect("valid private key")
            .prologue(self.name.as_bytes())
            .expect("1st time we set the prologue")
            .build_responder()
            .expect("valid noise params yield valid handshake state");
        self.handshake_tasks.spawn(async move {
            timeout(HANDSHAKE_TIMEOUT, on_handshake(h, s))
                .await
                .or(Err(NetworkError::Timeout))?
        });
    }

    /// Spawns a new I/O task for handling communication with a remote peer over
    /// a TCP connection using the noise framework to create an authenticated
    /// secure link.
    fn spawn_io(&mut self, k: PublicKey, s: T::Stream, t: TransportState) {
        debug!(
            name = %self.name,
            node = %self.key,
            peer = %k,
            addr = ?s.peer_addr().ok(),
            "starting i/o tasks"
        );
        let (to_remote, from_remote) = chan::channel(PEER_CAPACITY);
        let (r, w) = s.into_split();
        let t1 = Arc::new(Mutex::new(t));
        let t2 = t1.clone();
        let ibound = self.ibound.clone();
        let to_write = to_remote.clone();
        let countdown = Countdown::new();
        let budget = Arc::new(Semaphore::new(2 * PEER_CAPACITY));
        let rh = self.io_tasks.spawn(recv_loop(
            self.name,
            k,
            r,
            t1,
            ibound,
            to_write,
            #[cfg(feature = "metrics")]
            self.metrics.clone(),
            budget,
            countdown.clone(),
        ));
        let wh = self
            .io_tasks
            .spawn(send_loop(w, t2, from_remote, countdown));
        assert!(self.task2key.insert(rh.id(), k).is_none());
        assert!(self.task2key.insert(wh.id(), k).is_none());
        let io = IoTask {
            rh,
            wh,
            tx: to_remote,
        };
        self.active.insert(k, io);
        #[cfg(feature = "metrics")]
        self.metrics.connections.set(self.active.len() as i64);
    }

    /// Get the public key of a party by their static X25519 public key.
    fn lookup_peer(&self, t: &TransportState) -> Option<PublicKey> {
        let k = t.get_remote_static()?;
        let k = x25519::PublicKey::try_from(k).ok()?;
        self.index.get_by_right(&k).copied()
    }

    /// Check if the socket's peer IP address corresponds to the configured one.
    fn is_valid_ip(&self, k: &PublicKey, s: &T::Stream) -> bool {
        self.peers
            .get(k)
            .map(|p| {
                let Address::Inet(ip, _) = p.addr else {
                    return true;
                };
                Some(ip) == s.peer_addr().ok().map(|a| a.ip())
            })
            .unwrap_or(false)
    }
}

/// Connect to the given socket address.
///
/// This function will only return, when a connection has been established and the handshake
/// has been completed.
async fn connect<T: tcp::Stream + Unpin>(
    name: &'static str,
    this: (PublicKey, x25519::Keypair),
    to: (PublicKey, x25519::PublicKey),
    addr: Address,
    #[cfg(feature = "metrics")] metrics: Arc<NetworkMetrics>,
) -> (T, TransportState) {
    use rand::prelude::*;

    let new_handshake_state = || {
        Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(this.1.secret_key().as_slice())
            .expect("valid private key")
            .remote_public_key(to.1.as_slice())
            .expect("valid remote pub key")
            .prologue(name.as_bytes())
            .expect("1st time we set the prologue")
            .build_initiator()
            .expect("valid noise params yield valid handshake state")
    };

    let i = rand::rng().random_range(0..=1000);

    for d in [i, 1000, 3000, 6000, 10_000, 15_000]
        .into_iter()
        .chain(repeat(30_000))
    {
        sleep(Duration::from_millis(d)).await;
        debug!(%name, node = %this.0, peer = %to.0, %addr, "connecting");
        #[cfg(feature = "metrics")]
        metrics.add_connect_attempt(&to.0);
        match timeout(CONNECT_TIMEOUT, T::connect(&addr)).await {
            Ok(Ok(s)) => {
                if let Err(err) = s.set_nodelay(true) {
                    error!(%name, node = %this.0, %err, "failed to set NO_DELAY socket option");
                    continue;
                }
                match timeout(HANDSHAKE_TIMEOUT, handshake(new_handshake_state(), s)).await {
                    Ok(Ok(x)) => {
                        debug!(%name, node = %this.0, peer = %to.0, %addr, "connection established");
                        return x;
                    }
                    Ok(Err(err)) => {
                        warn!(%name, node = %this.0, peer = %to.0, %addr, %err, "handshake failure");
                    }
                    Err(_) => {
                        warn!(%name, node = %this.0, peer = %to.0, %addr, "handshake timeout");
                    }
                }
            }
            Ok(Err(err)) => {
                warn!(%name, node = %this.0, peer = %to.0, %addr, %err, "failed to connect");
            }
            Err(_) => {
                warn!(%name, node = %this.0, peer = %to.0, %addr, "connect timeout");
            }
        }
    }

    unreachable!("for loop repeats forever")
}

/// Perform a noise handshake as initiator with the remote party.
async fn handshake<T: tcp::Stream + Unpin>(
    mut hs: HandshakeState,
    mut stream: T,
) -> Result<(T, TransportState)> {
    let mut b = vec![0; MAX_NOISE_HANDSHAKE_SIZE];
    let n = hs.write_message(&[], &mut b)?;
    send_frame(&mut stream, Header::data(n as u16), &b[..n]).await?;
    let (h, m) = recv_frame(&mut stream).await?;
    if !h.is_data() || h.is_partial() {
        return Err(NetworkError::InvalidHandshakeMessage);
    }
    hs.read_message(&m, &mut b)?;
    Ok((stream, hs.into_transport_mode()?))
}

/// Perform a noise handshake as responder with a remote party.
async fn on_handshake<T: tcp::Stream + Unpin>(
    mut hs: HandshakeState,
    mut stream: T,
) -> Result<(T, TransportState)> {
    stream.set_nodelay(true)?;
    let (h, m) = recv_frame(&mut stream).await?;
    if !h.is_data() || h.is_partial() {
        return Err(NetworkError::InvalidHandshakeMessage);
    }
    let mut b = vec![0; MAX_NOISE_HANDSHAKE_SIZE];
    hs.read_message(&m, &mut b)?;
    let n = hs.write_message(&[], &mut b)?;
    send_frame(&mut stream, Header::data(n as u16), &b[..n]).await?;
    Ok((stream, hs.into_transport_mode()?))
}

/// Read messages from the remote by assembling frames together.
///
/// Once complete the message will be handed over to the given MPSC sender.
#[allow(clippy::too_many_arguments)]
async fn recv_loop<R>(
    name: &'static str,
    id: PublicKey,
    mut reader: R,
    state: Arc<Mutex<TransportState>>,
    to_deliver: Sender<(PublicKey, Bytes, Option<OwnedSemaphorePermit>)>,
    to_writer: chan::Sender<Message>,
    #[cfg(feature = "metrics")] metrics: Arc<NetworkMetrics>,
    budget: Arc<Semaphore>,
    mut countdown: Countdown,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0; MAX_NOISE_MESSAGE_SIZE];
    loop {
        #[cfg(feature = "metrics")]
        metrics.set_peer_iqueue_cap(&id, budget.available_permits());
        let permit = budget
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| NetworkError::BudgetClosed)?;
        let mut msg = BytesMut::new();
        loop {
            tokio::select! {
                val = recv_frame(&mut reader) => {
                    countdown.stop();
                    match val {
                        Ok((h, f)) => {
                            match h.frame_type() {
                                Ok(Type::Ping) => {
                                    // Received ping message; sending pong to writer
                                    let n = state.lock().read_message(&f, &mut buf)?;
                                    if let Some(ping) = Timestamp::try_from_slice(&buf[..n]) {
                                        to_writer.send(None, Message::Pong(ping))
                                    }
                                }
                                Ok(Type::Pong) => {
                                    // Received pong message; measure elapsed time
                                    let _n = state.lock().read_message(&f, &mut buf)?;
                                    #[cfg(feature = "metrics")]
                                    if let Some(ping) = Timestamp::try_from_slice(&buf[.._n]) {
                                        if let Some(delay) = Timestamp::now().diff(ping) {
                                            metrics.set_latency(&id, delay)
                                        }
                                    }
                                }
                                Ok(Type::Data) => {
                                    let n = state.lock().read_message(&f, &mut buf)?;
                                    msg.extend_from_slice(&buf[..n]);
                                    if !h.is_partial() {
                                        break;
                                    }
                                    if msg.len() > MAX_MESSAGE_SIZE {
                                        return Err(NetworkError::MessageTooLarge);
                                    }
                                }
                                Err(t) => return Err(NetworkError::UnknownFrameType(t)),
                            }
                        }
                        Err(e) => return Err(e)
                    }
                },
                () = &mut countdown => {
                    warn!(%name, node = %id, "timeout waiting for peer");
                    return Err(NetworkError::Timeout)
                }
            }
        }
        if to_deliver
            .send((id, msg.freeze(), Some(permit)))
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

/// Consume messages to be delivered to remote parties and send them.
///
/// The function automatically splits large messages into chunks that fit into
/// a noise package.
async fn send_loop<W>(
    mut writer: W,
    state: Arc<Mutex<TransportState>>,
    rx: chan::Receiver<Message>,
    countdown: Countdown,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; MAX_NOISE_MESSAGE_SIZE];

    while let Some(msg) = rx.recv().await {
        match msg {
            Message::Ping(ping) => {
                let n = state.lock().write_message(&ping.to_bytes()[..], &mut buf)?;
                let h = Header::ping(n as u16);
                send_frame(&mut writer, h, &buf[..n]).await?;
                countdown.start(REPLY_TIMEOUT)
            }
            Message::Pong(pong) => {
                let n = state.lock().write_message(&pong.to_bytes()[..], &mut buf)?;
                let h = Header::pong(n as u16);
                send_frame(&mut writer, h, &buf[..n]).await?;
            }
            Message::Data(msg) => {
                let mut it = msg.chunks(MAX_PAYLOAD_SIZE).peekable();
                while let Some(m) = it.next() {
                    let n = state.lock().write_message(m, &mut buf)?;
                    let h = if it.peek().is_some() {
                        Header::data(n as u16).partial()
                    } else {
                        Header::data(n as u16)
                    };
                    send_frame(&mut writer, h, &buf[..n]).await?
                }
            }
        }
    }
    Ok(())
}

/// Read a single frame (header + payload) from the remote.
async fn recv_frame<R>(r: &mut R) -> Result<(Header, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let b = r.read_u32().await?;
    let h = Header::try_from(b.to_be_bytes())?;
    let mut v = vec![0; h.len().into()];
    r.read_exact(&mut v).await?;
    Ok((h, v))
}

/// Write a single frame (header + payload) to the remote.
async fn send_frame<W>(w: &mut W, hdr: Header, msg: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    debug_assert_eq!(usize::from(hdr.len()), msg.len());
    w.write_all(&hdr.to_bytes()).await?;
    w.write_all(msg).await?;
    Ok(())
}

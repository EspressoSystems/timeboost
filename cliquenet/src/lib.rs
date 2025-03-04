#![doc = include_str!("../README.md")]

mod addr;
mod error;
mod frame;
mod metrics;
mod tcp;
mod time;

use std::collections::HashMap;
use std::future::pending;
use std::iter::repeat;
use std::sync::Arc;
use std::time::Duration;

use bimap::BiHashMap;
use bytes::{Bytes, BytesMut};
use multisig::{x25519, Keypair, PublicKey};
use parking_lot::Mutex;
use snow::{Builder, HandshakeState, TransportState};
use time::{Countdown, Timestamp};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{sleep, timeout, Interval, MissedTickBehavior};
use tokio::{
    spawn,
    task::{self, AbortHandle, JoinHandle, JoinSet},
};
use tracing::{debug, error, info, trace, warn};

use frame::{Header, Type};
use tcp::Stream;

use error::Empty;

pub use addr::{Address, InvalidAddress};
pub use error::NetworkError;
pub use metrics::NetworkMetrics;

type Result<T> = std::result::Result<T, NetworkError>;

/// Max. message size using noise handshake.
const MAX_NOISE_HANDSHAKE_SIZE: usize = 1024;

/// Max. message size using noise protocol.
const MAX_NOISE_MESSAGE_SIZE: usize = 64 * 1024;

/// Max. number of bytes for payload data.
const MAX_PAYLOAD_SIZE: usize = 63 * 1024;

/// Max. number of bytes for a message (potentially consisting of several frames).
const MAX_TOTAL_SIZE: usize = 5 * 1024 * 1024;

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
    /// MPSC sender of messages to be sent to remote parties.
    ///
    /// If a public key is present, it will result in a uni-cast,
    /// otherwise the message will be sent to all parties.
    tx: Sender<(Option<PublicKey>, Bytes)>,

    /// MPSC receiver of messages from a remote party.
    ///
    /// The public key identifies the remote.
    rx: Receiver<(PublicKey, Bytes)>,

    /// Handle of the server task that has been spawned by `Network`.
    srv: JoinHandle<Result<Empty>>,
}

impl Drop for Network {
    fn drop(&mut self) {
        self.srv.abort()
    }
}

/// Optionally, implement sailfish's `RawComm` trait.
///
/// *Requires feature* `"sailfish"`.
#[cfg(feature = "sailfish")]
#[async_trait::async_trait]
impl sailfish_types::RawComm for Network {
    type Err = NetworkError;

    async fn broadcast(&mut self, msg: Bytes) -> Result<()> {
        trace!(len = %msg.len(), "broadcasting message");
        self.multicast(msg).await
    }

    async fn send(&mut self, to: PublicKey, msg: Bytes) -> Result<()> {
        trace!(len = %msg.len(), %to, "sending message");
        self.unicast(to, msg).await
    }

    async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
        self.receive().await
    }
}

/// The `Server` is accepting connections and also establishing and
/// maintaining connections with all parties.
#[derive(Debug)]
struct Server<T: tcp::Listener> {
    /// This server's public key.
    key: PublicKey,

    /// The X25519 keypair, used with Noise.
    keypair: x25519::Keypair,

    /// MPSC sender for messages received over a connection to a party.
    ///
    /// (see `Network` for the accompanying receiver).
    ibound: Sender<(PublicKey, Bytes)>,

    /// MPSC receiver for messages to be sent to remote parties.
    ///
    /// (see `Network` for the accompanying sender).
    obound: Receiver<(Option<PublicKey>, Bytes)>,

    /// All parties of the network and their addresses.
    peers: HashMap<PublicKey, Address>,

    /// Bi-directional mapping of Ed25519 and X25519 keys to identify
    /// remote parties.
    index: BiHashMap<PublicKey, x25519::PublicKey>,

    /// Find the public key given a tokio task ID.
    task2key: HashMap<task::Id, PublicKey>,

    /// Currently active connections (post handshake).
    active: HashMap<PublicKey, IoTask>,

    /// Tasks performing a handshake with a remote party.
    handshake_tasks: JoinSet<Result<(T::Stream, TransportState)>>,

    /// Tasks connecting to a remote party and performing a handshake.
    connect_tasks: JoinSet<(T::Stream, TransportState)>,

    /// Active I/O tasks, exchanging data with remote parties.
    io_tasks: JoinSet<Result<()>>,

    /// For gathering network metrics.
    metrics: Arc<NetworkMetrics>,

    /// Interval at which to ping peers.
    ping_interval: Interval,
}

/// An I/O task, reading data from and writing data to a remote party.
#[derive(Debug)]
struct IoTask {
    /// Abort handle of the read-half of the connection.
    rh: AbortHandle,

    /// Abort handle of the write-half of the connection.
    wh: AbortHandle,

    /// MPSC sender of outgoing messages to the remote.
    tx: Sender<Message>,
}

// Make sure all tasks are stopped when `IoTask` is dropped.
impl Drop for IoTask {
    fn drop(&mut self) {
        self.rh.abort();
        self.wh.abort();
    }
}

/// Unify the various data types we want to send to the writer task.
enum Message {
    Data(Bytes),
    Ping(Timestamp),
    Pong(Timestamp),
}

impl Network {
    /// Create a new `Network`.
    pub async fn create<P, A1, A2>(
        bind_to: A1,
        kp: Keypair,
        group: P,
        metrics: NetworkMetrics,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
    {
        Self::generic_create::<tokio::net::TcpListener, _, _, _>(bind_to, kp, group, metrics).await
    }

    /// Create a new `Network` for tests with [`turmoil`].
    ///
    /// *Requires feature* `"turmoil"`.
    #[cfg(feature = "turmoil")]
    pub async fn create_turmoil<P, A1, A2>(
        bind_to: A1,
        kp: Keypair,
        group: P,
        metrics: NetworkMetrics,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
    {
        Self::generic_create::<turmoil::net::TcpListener, _, _, _>(bind_to, kp, group, metrics)
            .await
    }

    async fn generic_create<T, P, A1, A2>(
        bind_to: A1,
        kp: Keypair,
        group: P,
        metrics: NetworkMetrics,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, A2)>,
        A1: Into<Address>,
        A2: Into<Address>,
        T: tcp::Listener + Send + 'static,
        T::Stream: Unpin + Send,
    {
        let label = kp.public_key();
        let keys = x25519::Keypair::try_from(kp).expect("ed25519 -> x25519");

        let listener = T::bind(&bind_to.into()).await?;

        debug!(n = %label, a = %listener.local_addr()?, "listening");

        let (otx, orx) = mpsc::channel(10_000);
        let (itx, irx) = mpsc::channel(10_000);

        let mut peers = HashMap::new();
        let mut index = BiHashMap::new();

        for (k, a) in group {
            index.insert(k, x25519::PublicKey::try_from(k)?);
            peers.insert(k, a.into());
        }

        let mut interval = tokio::time::interval(PING_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let server = Server {
            keypair: keys,
            key: label,
            ibound: itx,
            obound: orx,
            peers,
            index,
            active: HashMap::new(),
            task2key: HashMap::new(),
            handshake_tasks: JoinSet::new(),
            connect_tasks: JoinSet::new(),
            io_tasks: JoinSet::new(),
            metrics: Arc::new(metrics),
            ping_interval: interval,
        };

        Ok(Self {
            rx: irx,
            tx: otx,
            srv: spawn(server.run(listener)),
        })
    }

    /// Send a message to a party, identified by the given public key.
    pub async fn unicast(&self, to: PublicKey, msg: Bytes) -> Result<()> {
        self.tx
            .send((Some(to), msg))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Send a message to all parties.
    pub async fn multicast(&self, msg: Bytes) -> Result<()> {
        self.tx
            .send((None, msg))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    /// Receive a message from a remote party.
    pub async fn receive(&mut self) -> Result<(PublicKey, Bytes)> {
        self.rx.recv().await.ok_or(NetworkError::ChannelClosed)
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

        for (k, a) in &self.peers {
            if *k == self.key {
                continue;
            }
            let x = self.index.get_by_left(k).expect("known public key");
            self.connect_tasks.spawn(connect(
                (self.key, self.keypair.clone()),
                (*k, *x),
                a.clone(),
                self.metrics.clone(),
            ));
        }

        loop {
            trace!(
                node       = %self.key,
                active     = %self.active.len(),
                connects   = %self.connect_tasks.len(),
                handshakes = %self.handshake_tasks.len().saturating_sub(1), // -1 for `pending()`
                io_tasks   = %self.io_tasks.len().saturating_sub(1), // -1 for `pending()`
                tasks_ids  = %self.task2key.len()
            );

            tokio::select! {
                // Accepted a new connection.
                i = listener.accept() => match i {
                    Ok((s, a)) => {
                        debug!(node = %self.key, addr = %a, "accepted connection");
                        self.spawn_handshake(s)
                    }
                    Err(e) => {
                        warn!(node = %self.key, err = %e, "error accepting connection")
                    }
                },
                // The handshake of an inbound connection completed.
                Some(h) = self.handshake_tasks.join_next() => match h {
                    Ok(Ok((s, t))) => {
                        let Some(k) = self.lookup_peer(&t) else {
                            info!(
                                node = %self.key,
                                peer = ?t.get_remote_static().and_then(|k| x25519::PublicKey::try_from(k).ok()),
                                addr = ?s.peer_addr().ok(),
                                "unknown peer"
                            );
                            continue
                        };
                        if !self.is_valid_ip(&k, &s) {
                            warn!(node = %self.key, peer = %k, addr = ?s.peer_addr().ok(), "invalid peer ip addr");
                            continue
                        }
                        // We only accept connections whose party has a public key that
                        // is larger than ours, or if we do not have a connection for
                        // that key at the moment.
                        if k > self.key || !self.active.contains_key(&k) {
                            self.spawn_io(k, s, t)
                        } else {
                            warn!(node = %self.key, peer = %k, "dropping accepted connection");
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(node = %self.key, err = %e, "handshake failed")
                    }
                    Err(e) => {
                        if !e.is_cancelled() {
                            error!(node = %self.key, err = %e, "handshake task panic");
                        }
                    }
                },
                // One of our connection attempts completed.
                Some(tt) = self.connect_tasks.join_next() => match tt {
                    Ok((s, t)) => {
                        let Some(k) = self.lookup_peer(&t) else {
                            continue
                        };
                        // We only keep the connection if our key is larger than the remote,
                        // or if we do not have a connection for that key at the moment.
                        if k < self.key || !self.active.contains_key(&k) {
                            self.spawn_io(k, s, t)
                        } else {
                            warn!(node = %self.key, peer = %k, "dropping new connection");
                        }
                    }
                    Err(e) => {
                        if !e.is_cancelled() {
                            error!(node = %self.key, err = %e, "connect task panic");
                        }
                    }
                },
                // A read or write task completed.
                Some(io) = self.io_tasks.join_next_with_id() => {
                    match io {
                        Ok((id, r)) => {
                            if let Err(e) = r {
                                warn!(node = %self.key, err = %e, "i/o error")
                            }
                            self.on_io_task_end(id);
                        }
                        Err(e) => {
                            if e.is_cancelled() {
                                // If one half completes we cancel the other, so there is
                                // nothing else to do here, except to remove the cancelled
                                // tasks's ID.
                                self.task2key.remove(&e.id());
                                continue
                            }
                            // If the task has not been cancelled, it must have panicked.
                            error!(node = %self.key, err = %e, "i/o task panic");
                            self.on_io_task_end(e.id())
                        }
                    };
                },
                // A new message to send out has been given to us:
                msg = self.obound.recv() => match msg {
                    // Uni-cast
                    Some((Some(to), m)) => {
                        if to == self.key {
                            let _ = self.ibound.try_send((self.key, m));
                            continue
                        }
                        if let Some(task) = self.active.get(&to) {
                            if task.tx.try_send(Message::Data(m)).is_err() {
                                warn!(node = %self.key, peer = %to, "channel full => reconnecting");
                                self.spawn_connect(to)
                            }
                        }
                    }
                    // Multi-cast
                    Some((None, m)) => {
                        let _ = self.ibound.try_send((self.key, m.clone()));
                        let mut reconnect = Vec::new();
                        for (k, task) in &self.active {
                            if task.tx.try_send(Message::Data(m.clone())).is_err() {
                                warn!(node = %self.key, peer = %k, "channel full => reconnecting");
                                reconnect.push(*k);
                            }
                        }
                        for k in reconnect {
                            self.spawn_connect(k)
                        }
                    }
                    None => {
                        return Err(NetworkError::ChannelClosed)
                    }
                },
                _ = self.ping_interval.tick() => {
                    let now = Timestamp::now();
                    for task in self.active.values() {
                        let _ = task.tx.try_send(Message::Ping(now));
                    }
                }
            }
        }
    }

    /// Handles a completed I/O task.
    ///
    /// This function will get the public key of the task that was terminated
    /// and then cleanly removes the associated I/O task data and re-connects
    /// to the peer node it was interacting with.
    fn on_io_task_end(&mut self, id: task::Id) {
        let Some(k) = self.task2key.remove(&id) else {
            error!(node = %self.key, "no key for task");
            return;
        };
        let Some(task) = self.active.get(&k) else {
            return;
        };
        if task.rh.id() == id {
            debug!(node = %self.key, peer = %k, "read-half closed => dropping connection");
            self.active.remove(&k);
            self.spawn_connect(k)
        } else if task.wh.id() == id {
            debug!(node = %self.key, peer = %k, "write-half closed => dropping connection");
            self.active.remove(&k);
            self.spawn_connect(k)
        } else {
            debug!(node = %self.key, peer = %k, "i/o task was previously replaced");
        }
    }

    /// Spawns a new connection task to a peer identified by public key.
    ///
    /// This function will look up the x25519 public key of the ed25519 key
    /// and the remote address and then spawn a connection task.
    fn spawn_connect(&mut self, k: PublicKey) {
        let x = self.index.get_by_left(&k).expect("known public key");
        let a = self.peers.get(&k).expect("known address");
        self.connect_tasks.spawn(connect(
            (self.key, self.keypair.clone()),
            (k, *x),
            a.clone(),
            self.metrics.clone(),
        ));
    }

    /// Spawns a new `Noise` responder handshake task using the IK pattern.
    ///
    /// This function will create the responder handshake machine using its
    /// own private key and then spawn a task that awaits an initiator handshake
    /// to which it will respond.
    fn spawn_handshake(&mut self, s: T::Stream) {
        let h = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(&self.keypair.secret_key().as_bytes())
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
        debug!(node = %self.key, peer = %k, addr = ?s.peer_addr().ok(), "starting i/o tasks");
        let (to_remote, from_remote) = mpsc::channel(256);
        let (r, w) = s.into_split();
        let t1 = Arc::new(Mutex::new(t));
        let t2 = t1.clone();
        let ibound = self.ibound.clone();
        let to_write = to_remote.clone();
        let countdown = Countdown::new();
        let rh = self.io_tasks.spawn(recv_loop(
            k,
            r,
            t1,
            ibound,
            to_write,
            self.metrics.clone(),
            countdown.clone(),
        ));
        let wh = self.io_tasks.spawn(send_loop(
            w,
            t2,
            from_remote,
            self.metrics.clone(),
            countdown,
        ));
        assert!(self.task2key.insert(rh.id(), k).is_none());
        assert!(self.task2key.insert(wh.id(), k).is_none());
        let io = IoTask {
            rh,
            wh,
            tx: to_remote.clone(),
        };
        self.active.insert(k, io);
        self.metrics.connections.set(self.active.len());
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
            .map(|a| {
                let Address::Inet(ip, _) = a else { return true };
                Some(*ip) == s.peer_addr().ok().map(|a| a.ip())
            })
            .unwrap_or(false)
    }
}

/// Connect to the given socket address.
///
/// This function will only return, when a connection has been established and the handshake
/// has been completed.
async fn connect<T: tcp::Stream + Unpin>(
    this: (PublicKey, x25519::Keypair),
    to: (PublicKey, x25519::PublicKey),
    addr: Address,
    metrics: Arc<NetworkMetrics>,
) -> (T, TransportState) {
    use rand::prelude::*;

    let new_handshake_state = || {
        Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(this.1.secret_key().as_slice())
            .remote_public_key(to.1.as_slice())
            .build_initiator()
            .expect("valid noise params yield valid handshake state")
    };

    let i = rand::rng().random_range(0..=1000);

    for d in [i, 1000, 3000, 6000, 10_000, 15_000]
        .into_iter()
        .chain(repeat(30_000))
    {
        sleep(Duration::from_millis(d)).await;
        debug!(node = %this.0, peer = %to.0, %addr, "connecting");
        metrics.add_connect_attempt(&to.0);
        match timeout(CONNECT_TIMEOUT, T::connect(&addr)).await {
            Ok(Ok(s)) => {
                if let Err(err) = s.set_nodelay(true) {
                    error!(node = %this.0, %err, "failed to set NO_DELAY socket option");
                    continue;
                }
                match timeout(HANDSHAKE_TIMEOUT, handshake(new_handshake_state(), s)).await {
                    Ok(Ok(x)) => {
                        debug!(node = %this.0, peer = %to.0, %addr, "connection established");
                        return x;
                    }
                    Ok(Err(err)) => {
                        warn!(node = %this.0, peer = %to.0, %addr, %err, "handshake failure");
                    }
                    Err(_) => {
                        warn!(node = %this.0, peer = %to.0, %addr, "handshake timeout");
                    }
                }
            }
            Ok(Err(err)) => {
                warn!(node = %this.0, peer = %to.0, %addr, %err, "failed to connect");
            }
            Err(_) => {
                warn!(node = %this.0, peer = %to.0, %addr, "connect timeout");
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
async fn recv_loop<R>(
    id: PublicKey,
    mut reader: R,
    state: Arc<Mutex<TransportState>>,
    to_deliver: Sender<(PublicKey, Bytes)>,
    to_writer: Sender<Message>,
    metrics: Arc<NetworkMetrics>,
    mut countdown: Countdown,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0; MAX_NOISE_MESSAGE_SIZE];
    loop {
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
                                        let _ = to_writer.try_send(Message::Pong(ping));
                                    }
                                }
                                Ok(Type::Pong) => {
                                    // Received pong message; measure elapsed time
                                    let n = state.lock().read_message(&f, &mut buf)?;
                                    if let Some(ping) = Timestamp::try_from_slice(&buf[..n]) {
                                        if let Some(delay) = Timestamp::now().diff(ping) {
                                            metrics.latency.add_point(delay.as_secs_f64() * 1000.0);
                                        }
                                    }
                                }
                                Ok(Type::Data) => {
                                    let n = state.lock().read_message(&f, &mut buf)?;
                                    msg.extend_from_slice(&buf[..n]);
                                    if !h.is_partial() {
                                        break;
                                    }
                                    if msg.len() > MAX_TOTAL_SIZE {
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
                    warn!(node = %id, "timeout waiting for peer");
                    return Err(NetworkError::Timeout)
                }
            }
        }
        if to_deliver.send((id, msg.freeze())).await.is_err() {
            break;
        }
        metrics.received.add(1);
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
    mut rx: Receiver<Message>,
    metrics: Arc<NetworkMetrics>,
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
                metrics.sent.add(1);
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

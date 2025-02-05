mod error;
mod frame;
pub mod metrics;
mod time;

use std::future::pending;
use std::iter::repeat;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};

use bimap::BiHashMap;
use bytes::{Bytes, BytesMut};
use metrics::NetworkMetrics;
use multisig::{x25519, Keypair, PublicKey};
use parking_lot::Mutex;
use snow::{Builder, HandshakeState, TransportState};
use time::Timestamp;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::{sleep, Interval, MissedTickBehavior};
use tokio::{
    spawn,
    task::{self, AbortHandle, JoinHandle, JoinSet},
};
use tracing::{debug, error, info, trace, warn};

use frame::{Header, Type};

pub use error::{Empty, NetworkError};

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
const PING_INTERVAL: Duration = Duration::from_secs(30);

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

/// The `Server` is accepting connections and also establishing and
/// maintaining connections with all parties.
#[derive(Debug)]
struct Server {
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
    peers: HashMap<PublicKey, SocketAddr>,

    /// Bi-directional mapping of Ed25519 and X25519 keys to identify
    /// remote parties.
    index: BiHashMap<PublicKey, x25519::PublicKey>,

    /// Find the public key given a tokio task ID.
    task2key: HashMap<task::Id, PublicKey>,

    /// Currently active connections (post handshake).
    active: HashMap<PublicKey, IoTask>,

    /// Tasks performing a handshake with a remote party.
    handshake_tasks: JoinSet<Result<(TcpStream, TransportState)>>,

    /// Tasks connecting to a remote party and performing a handshake.
    connect_tasks: JoinSet<(TcpStream, TransportState)>,

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
    pub async fn create<P>(
        bind_to: SocketAddr,
        kp: Keypair,
        group: P,
        metrics: NetworkMetrics,
    ) -> Result<Self>
    where
        P: IntoIterator<Item = (PublicKey, SocketAddr)>,
    {
        let label = kp.public_key();
        let keys = x25519::Keypair::try_from(kp).expect("ed25519 -> x25519");

        let listener = TcpListener::bind(bind_to).await?;

        debug!(n = %label, a = %listener.local_addr()?, "listening");

        let (otx, orx) = mpsc::channel(10_000);
        let (itx, irx) = mpsc::channel(10_000);

        let mut peers = HashMap::new();
        let mut index = BiHashMap::new();

        for (k, a) in group {
            index.insert(k, x25519::PublicKey::try_from(k)?);
            peers.insert(k, a);
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

impl Server {
    /// Handles the main loop for a the nodes network, this will last the lifetime of the app
    /// 
    /// This function:
    /// - Tries to connect to each remote peer in the committee
    /// - Handles tasks that have been completed or terminated
    /// - Processes new messages we received on the network
    /// 
    /// # Panics
    /// 
    /// This function panics if:
    /// - We are unable to get the x25519 public key from ed25519 public key
    async fn run(mut self, listener: TcpListener) -> Result<Empty> {
        self.handshake_tasks.spawn(pending());
        self.io_tasks.spawn(pending());

        for (k, a) in &self.peers {
            if *k == self.key {
                continue;
            }
            let x = self.index.get_by_left(k).expect("known public key");
            self.connect_tasks
                .spawn(connect(self.keypair.clone(), *x, *a));
        }

        loop {
            trace!(n = %self.key, a = %self.active.len(), t = %self.task2key.len());

            tokio::select! {
                // Accepted a new connection.
                i = listener.accept() => match i {
                    Ok((s, a)) => {
                        debug!(n = %self.key, %a, "accepted connection");
                        self.spawn_handshake(s)
                    }
                    Err(e) => {
                        warn!(n = %self.key, %e, "error accepting connection")
                    }
                },
                // The handshake of an inbound connection completed.
                Some(h) = self.handshake_tasks.join_next() => match h {
                    Ok(Ok((s, t))) => {
                        let Some(k) = self.lookup_peer(&t) else {
                            info!(
                                n = %self.key,
                                k = ?t.get_remote_static().and_then(|k| x25519::PublicKey::try_from(k).ok()),
                                a = ?s.peer_addr().ok(),
                                "unknown peer"
                            );
                            continue
                        };
                        if !self.is_valid_ip(&k, &s) {
                            warn!(n = %self.key, %k, a = ?s.peer_addr().ok(), "invalid peer ip addr");
                            continue
                        }
                        // We only accept connections whose party has a public key that
                        // is larger than ours, or if we do not have a connection for
                        // that key at the moment.
                        if k > self.key || !self.active.contains_key(&k) {
                            self.spawn_io(k, s, t)
                        } else {
                            warn!(n = %self.key, %k, "dropping accepted connection");
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(n = %self.key, %e, "handshake failed")
                    }
                    Err(e) => {
                        if !e.is_cancelled() {
                            error!(n = %self.key, %e, "handshake task panic");
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
                            warn!(n = %self.key, %k, "dropping new connection");
                        }
                    }
                    Err(e) => {
                        if !e.is_cancelled() {
                            error!(n = %self.key, %e, "connect task panic");
                        }
                    }
                },
                // A read or write task completed.
                Some(io) = self.io_tasks.join_next_with_id() => {
                    match io {
                        Ok((id, r)) => {
                            if let Err(e) = r {
                                warn!(n = %self.key, %e, "i/o error")
                            }
                            self.on_io_task_end(id);
                        }
                        Err(e) => {
                            if e.is_cancelled() {
                                // If one half completes we cancel the other, so there is
                                // nothing else to do here.
                                continue
                            }
                            // If the task has not been cancelled, it must have panicked.
                            error!(n = %self.key, %e, "i/o task panic");
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
                                warn!(n = %self.key, k = %to, "channel full => reconnecting");
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
                                warn!(n = %self.key, %k, "channel full => reconnecting");
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

    /// Handles when I/O task has been completed
    /// 
    /// This function will get the Public Key of the task that was terminated
    /// Then cleanly remove the active I/O task and call `spawn_connect` to recreate the connection
    fn on_io_task_end(&mut self, id: task::Id) {
        let Some(k) = self.task2key.remove(&id) else {
            error!(n = %self.key, "no key for task");
            return;
        };
        let Some(task) = self.active.get(&k) else {
            return;
        };
        if task.rh.id() == id {
            debug!(n = %self.key, %k, "read-half closed => dropping connection");
            self.active.remove(&k);
            self.spawn_connect(k)
        } else if task.wh.id() == id {
            debug!(n = %self.key, %k, "write-half closed => dropping connection");
            self.active.remove(&k);
            self.spawn_connect(k)
        } else {
            debug!(n = %self.key, %k, "i/o task was previously replaced");
        }
    }

    /// Spawns a new connection task to a peer identified by public key
    /// 
    /// This function will look up the x25519 Public Key from ed25519 key and the remote address then spawn a connection task
    /// 
    /// # Panics
    ///
    /// This function will panic if:
    /// - If we do not have a mapping from remote peers ed25519 public key to x25519 public key
    /// - If we do not have a mapping from remote peers ed25519 public key to remote peer address
    fn spawn_connect(&mut self, k: PublicKey) {
        let x = self.index.get_by_left(&k).expect("known public key");
        let a = self.peers.get(&k).expect("known address");
        self.connect_tasks
            .spawn(connect(self.keypair.clone(), *x, *a));
    }

    /// Spawns a new `Noise` responder handshake task, this is using `Noise` IK Handshake
    /// 
    /// This function will create the responders handshake machine using its own private key
    /// Then spawn a task that listens for incoming initiator handshakes and responds
    /// 
    /// # Panics
    ///
    /// This function will panic if:
    /// - If the `NOISE_PARAMS` are invalid
    /// - If we are unable to initialize our `HandshakeState` machine
    fn spawn_handshake(&mut self, s: TcpStream) {
        let h = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(&self.keypair.secret_key().as_bytes())
            .build_responder()
            .expect("valid noise params yield valid handshake state");
        self.handshake_tasks.spawn(on_handshake(h, s));
    }

    /// Spawns a new I/O task for handling communication with a remote peer over a TCP connection
    /// That is also using `Noise` for encryption and decryption
    /// 
    /// This function will split the TCP stream into read and write halves for a TCP connection and spawn a task for each
    fn spawn_io(&mut self, k: PublicKey, s: TcpStream, t: TransportState) {
        debug!(n = %self.key, a = ?s.peer_addr().ok(), "starting i/o tasks");
        let (to_remote, from_remote) = mpsc::channel(256);
        let (r, w) = s.into_split();
        let t1 = Arc::new(Mutex::new(t));
        let t2 = t1.clone();
        let ibound = self.ibound.clone();
        let to_write = to_remote.clone();
        let rh = self
            .io_tasks
            .spawn(recv_loop(k, r, t1, ibound, to_write, self.metrics.clone()));
        let wh = self.io_tasks.spawn(send_loop(w, t2, from_remote));
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
    fn is_valid_ip(&self, k: &PublicKey, s: &TcpStream) -> bool {
        self.peers.get(k).map(|a| a.ip()) == s.peer_addr().ok().map(|a| a.ip())
    }
}

/// Connect to the given socket address.
///
/// This function will only return, when a connection has been established and the handshake
/// has been completed.
async fn connect(
    this: x25519::Keypair,
    to: x25519::PublicKey,
    addr: SocketAddr,
) -> (TcpStream, TransportState) {
    use rand::prelude::*;

    let new_handshake_state = || {
        Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(this.secret_key().as_slice())
            .remote_public_key(to.as_slice())
            .build_initiator()
            .expect("valid noise params yield valid handshake state")
    };

    let i = rand::rng().random_range(0..=1000);

    for d in [i, 1000, 3000, 6000, 10_000, 15_000]
        .into_iter()
        .chain(repeat(30_000))
    {
        sleep(Duration::from_millis(d)).await;
        debug!(a = %addr, "connecting");
        match TcpStream::connect(addr).await {
            Ok(s) => {
                if let Err(e) = s.set_nodelay(true) {
                    error!(%e, "failed to set NO_DELAY socket option");
                    continue;
                }
                match handshake(new_handshake_state(), s).await {
                    Ok(x) => {
                        debug!(%to, a = %addr, "connection established");
                        return x;
                    }
                    Err(e) => {
                        warn!(%e, %addr, "handshake failure");
                    }
                }
            }
            Err(e) => {
                warn!(%e, %addr, "failed to connect");
            }
        }
    }

    unreachable!("for loop repeats forever")
}

/// Perform a noise handshake as initiator with the remote party.
async fn handshake(
    mut hs: HandshakeState,
    mut stream: TcpStream,
) -> Result<(TcpStream, TransportState)> {
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
async fn on_handshake(
    mut hs: HandshakeState,
    mut stream: TcpStream,
) -> Result<(TcpStream, TransportState)> {
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
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0; MAX_NOISE_MESSAGE_SIZE];
    loop {
        let mut msg = BytesMut::new();
        loop {
            let (h, f) = recv_frame(&mut reader).await?;

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
        if to_deliver.send((id, msg.freeze())).await.is_err() {
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
    mut rx: Receiver<Message>,
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

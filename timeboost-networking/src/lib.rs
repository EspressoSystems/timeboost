mod error;
mod frame;

use std::future::pending;
use std::iter::repeat;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};

use bimap::BiHashMap;
use multisig::{x25519, Keypair, PublicKey};
use parking_lot::Mutex;
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;
use tokio::{
    spawn,
    task::{AbortHandle, JoinHandle, JoinSet},
};
use tracing::{debug, error, trace, warn};

use frame::Header;

pub use error::{Empty, NetworkError};

type Result<T> = std::result::Result<T, NetworkError>;

/// Max message size using noise protocol
const MAX_NOISE_MESSAGE_SIZE: usize = 64 * 1024;

/// Number of bytes for payload data.
const MAX_PAYLOAD_SIZE: usize = 63 * 1024;

/// Noise parameters to initialize the builders
const NOISE_PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[derive(Debug)]
pub struct Network {
    tx: Sender<(Option<PublicKey>, Vec<u8>)>,
    rx: Receiver<(PublicKey, Vec<u8>)>,
    srv: JoinHandle<Result<Empty>>,
}

impl Drop for Network {
    fn drop(&mut self) {
        self.srv.abort()
    }
}

#[derive(Debug)]
struct Server {
    key: PublicKey,
    keypair: x25519::Keypair,
    ibound: Sender<(PublicKey, Vec<u8>)>,
    obound: Receiver<(Option<PublicKey>, Vec<u8>)>,
    peers: HashMap<PublicKey, SocketAddr>,
    index: BiHashMap<PublicKey, x25519::PublicKey>,
    task2key: HashMap<tokio::task::Id, PublicKey>,
    active: HashMap<PublicKey, IoTask>,
    handshake_tasks: JoinSet<Result<(TcpStream, TransportState)>>,
    connect_tasks: JoinSet<(TcpStream, TransportState)>,
    io_tasks: JoinSet<Result<()>>,
}

#[derive(Debug)]
struct IoTask {
    rh: AbortHandle,
    wh: AbortHandle,
    tx: mpsc::Sender<Vec<u8>>,
}

impl Drop for IoTask {
    fn drop(&mut self) {
        self.rh.abort();
        self.wh.abort();
    }
}

impl Network {
    pub async fn create<P>(bind_to: SocketAddr, kp: Keypair, group: P) -> Result<Self>
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
        };

        Ok(Self {
            rx: irx,
            tx: otx,
            srv: spawn(server.run(listener)),
        })
    }

    pub async fn unicast(&self, to: PublicKey, msg: Vec<u8>) -> Result<()> {
        self.tx
            .send((Some(to), msg))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    pub async fn multicast(&self, msg: Vec<u8>) -> Result<()> {
        self.tx
            .send((None, msg))
            .await
            .map_err(|_| NetworkError::ChannelClosed)
    }

    pub async fn receive(&mut self) -> Result<(PublicKey, Vec<u8>)> {
        self.rx.recv().await.ok_or(NetworkError::ChannelClosed)
    }
}

impl Server {
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
                i = listener.accept() => match i {
                    Ok((s, a)) => {
                        debug!(n = %self.key, %a, "accepted connection");
                        self.spawn_handshake(s)
                    }
                    Err(e) => {
                        warn!(n = %self.key, %e, "error accepting connection")
                    }
                },
                Some(h) = self.handshake_tasks.join_next() => match h {
                    Ok(Ok((s, t))) => {
                        let Some(k) = self.lookup_peer(&t) else {
                            continue
                        };
                        if k > self.key || !self.active.contains_key(&k) {
                            self.spawn_io(s, t)
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
                Some(tt) = self.connect_tasks.join_next() => match tt {
                    Ok((s, t)) => {
                        let Some(k) = self.lookup_peer(&t) else {
                            continue
                        };
                        if k < self.key || !self.active.contains_key(&k) {
                            self.spawn_io(s, t)
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
                Some(io) = self.io_tasks.join_next_with_id() => {
                    match io {
                        Ok((id, r)) => {
                            if let Err(e) = r {
                                warn!(n = %self.key, %e, "i/o error")
                            }
                            let Some(k) = self.task2key.remove(&id) else {
                                error!(n = %self.key, "no key for task");
                                continue
                            };
                            if let Some(task) = self.active.get(&k) {
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
                        }
                        Err(e) => {
                            if e.is_cancelled() {
                                continue
                            }
                            error!(n = %self.key, %e, "i/o task panic");
                            let Some(k) = self.task2key.remove(&e.id()) else {
                                error!(n = %self.key, "no key for task");
                                continue
                            };
                            if let Some(task) = self.active.get(&k) {
                                if task.rh.id() == e.id() {
                                    debug!(n = %self.key, %k, "read-half closed => dropping connection");
                                    self.active.remove(&k);
                                    self.spawn_connect(k)
                                } else if task.wh.id() == e.id() {
                                    debug!(n = %self.key, %k, "write-half closed => dropping connection");
                                    self.active.remove(&k);
                                    self.spawn_connect(k)
                                } else {
                                    debug!(n = %self.key, %k, "i/o task was previously replaced");
                                }
                            }
                        }
                    };
                },
                msg = self.obound.recv() => match msg {
                    Some((Some(to), m)) => {
                        if to == self.key {
                            let _ = self.ibound.try_send((self.key, m));
                            continue
                        }
                        if let Some(task) = self.active.get_mut(&to) {
                            if task.tx.try_send(m).is_err() {
                                warn!(n = %self.key, k = %to, "channel full => reconnecting");
                                self.spawn_connect(to)
                            }
                        }
                    }
                    Some((None, m)) => {
                        let _ = self.ibound.try_send((self.key, m.clone()));
                        let mut reconnect = Vec::new();
                        for (k, task) in &mut self.active {
                            if task.tx.try_send(m.clone()).is_err() {
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
                }
            }
        }
    }

    fn spawn_connect(&mut self, k: PublicKey) {
        let x = self.index.get_by_left(&k).expect("known public key");
        let a = self.peers.get(&k).expect("known address");
        self.connect_tasks
            .spawn(connect(self.keypair.clone(), *x, *a));
    }

    fn spawn_handshake(&mut self, s: TcpStream) {
        let h = Builder::new(NOISE_PARAMS.parse().expect("valid noise params"))
            .local_private_key(&self.keypair.secret_key().as_bytes())
            .build_responder()
            .expect("valid noise params yield valid handshake state");
        self.handshake_tasks.spawn(on_handshake(h, s));
    }

    fn spawn_io(&mut self, s: TcpStream, t: TransportState) {
        let Some(k) = self.lookup_peer(&t) else {
            debug!(n = %self.key, a = ?s.peer_addr().ok(), "unknown peer");
            return;
        };
        debug!(n = %self.key, a = ?s.peer_addr().ok(), "starting i/o tasks");
        let (to_remote, from_remote) = mpsc::channel(256);
        let (r, w) = s.into_split();
        let t1 = Arc::new(Mutex::new(t));
        let t2 = t1.clone();
        let ibound = self.ibound.clone();
        let rh = self.io_tasks.spawn(recv_loop(k, r, t1, ibound));
        let wh = self.io_tasks.spawn(send_loop(w, t2, from_remote));
        assert!(self.task2key.insert(rh.id(), k).is_none());
        assert!(self.task2key.insert(wh.id(), k).is_none());
        let io = IoTask {
            rh,
            wh,
            tx: to_remote,
        };
        self.active.insert(k, io);
    }

    fn lookup_peer(&self, t: &TransportState) -> Option<PublicKey> {
        let k = t.get_remote_static()?;
        let k = x25519::PublicKey::try_from(k).ok()?;
        self.index.get_by_right(&k).copied()
    }
}

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

    let i = rand::thread_rng().gen_range(0..=1000);

    for d in [i, 1000, 3000, 6000, 10_000, 15_000]
        .into_iter()
        .chain(repeat(30_000))
    {
        sleep(Duration::from_millis(d)).await;
        debug!(%to, a = %addr, "connecting");
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

async fn handshake(
    mut hs: HandshakeState,
    mut stream: TcpStream,
) -> Result<(TcpStream, TransportState)> {
    let mut b = vec![0; MAX_NOISE_MESSAGE_SIZE];
    let n = hs.write_message(&[], &mut b)?;
    send_frame(&mut stream, Header::data(n as u16), &b[..n]).await?;
    let (h, m) = recv_frame(&mut stream).await?;
    if !h.is_data() || h.is_partial() {
        return Err(NetworkError::InvalidHandshakeMessage);
    }
    hs.read_message(&m, &mut b)?;
    Ok((stream, hs.into_transport_mode()?))
}

async fn on_handshake(
    mut hs: HandshakeState,
    mut stream: TcpStream,
) -> Result<(TcpStream, TransportState)> {
    stream.set_nodelay(true)?;
    let (h, m) = recv_frame(&mut stream).await?;
    if !h.is_data() || h.is_partial() {
        return Err(NetworkError::InvalidHandshakeMessage);
    }
    let mut b = vec![0; MAX_NOISE_MESSAGE_SIZE];
    hs.read_message(&m, &mut b)?;
    let n = hs.write_message(&[], &mut b)?;
    send_frame(&mut stream, Header::data(n as u16), &b[..n]).await?;
    Ok((stream, hs.into_transport_mode()?))
}

async fn recv_loop<R>(
    k: PublicKey,
    mut r: R,
    t: Arc<Mutex<TransportState>>,
    tx: Sender<(PublicKey, Vec<u8>)>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0; MAX_NOISE_MESSAGE_SIZE];
    loop {
        let mut msg = Vec::new();
        loop {
            let (h, f) = recv_frame(&mut r).await?;
            if !h.is_data() {
                continue;
            }
            let n = t.lock().read_message(&f, &mut buf)?;
            msg.extend_from_slice(&buf[..n]);
            if !h.is_partial() {
                break;
            }
            if msg.len() > MAX_PAYLOAD_SIZE {
                return Err(NetworkError::MessageTooLarge);
            }
        }
        if tx.send((k, msg)).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn send_loop<W>(
    mut w: W,
    t: Arc<Mutex<TransportState>>,
    mut rx: Receiver<Vec<u8>>,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0; MAX_NOISE_MESSAGE_SIZE];
    while let Some(msg) = rx.recv().await {
        let mut it = msg.chunks(MAX_PAYLOAD_SIZE).peekable();
        while let Some(m) = it.next() {
            let n = t.lock().write_message(m, &mut buf)?;
            let h = if it.peek().is_some() {
                Header::data(n as u16).partial()
            } else {
                Header::data(n as u16)
            };
            send_frame(&mut w, h, &buf[..n]).await?
        }
    }
    Ok(())
}

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

async fn send_frame<W>(w: &mut W, hdr: Header, msg: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    debug_assert_eq!(usize::from(hdr.len()), msg.len());
    w.write_all(&hdr.to_bytes()[..]).await?;
    w.write_all(msg).await?;
    Ok(())
}

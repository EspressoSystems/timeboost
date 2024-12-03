use std::collections::HashMap;
use std::fmt::Display;
use std::future::pending;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use futures::SinkExt;
use timeboost_core::traits::comm::RawComm;
use timeboost_core::types::PublicKey;
use timeboost_crypto::traits::signature_key::SignatureKey;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::{JoinHandle, JoinSet};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, error, trace, warn};
use turmoil::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use turmoil::net::{TcpListener, TcpStream};
use turmoil::ToSocketAddrs;

type Reader = FramedRead<OwnedReadHalf, LengthDelimitedCodec>;
type Writer = FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>;

#[derive(Debug)]
pub struct TurmoilComm {
    tx: UnboundedSender<(Option<PublicKey>, Vec<u8>)>,
    rx: UnboundedReceiver<Vec<u8>>,
    jh: JoinHandle<()>,
}

impl Drop for TurmoilComm {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl TurmoilComm {
    pub async fn create<A, S, I>(key: PublicKey, addr: A, peers: I) -> io::Result<Self>
    where
        A: ToSocketAddrs,
        S: Display,
        I: IntoIterator<Item = (PublicKey, (S, u16))>,
    {
        let listener = TcpListener::bind(addr).await?;
        let (to_worker, from_comm) = mpsc::unbounded_channel();
        let (to_comm, from_worker) = mpsc::unbounded_channel();
        let w = Worker {
            key,
            config: peers
                .into_iter()
                .map(|(k, (s, p))| (k, (s.to_string(), p)))
                .collect(),
            peers: HashMap::new(),
            tx: to_comm,
            rx: from_comm,
            listener,
            identify_tasks: JoinSet::new(),
            reader_tasks: JoinSet::new(),
            connect_tasks: JoinSet::new(),
        };
        Ok(Self {
            tx: to_worker,
            rx: from_worker,
            jh: tokio::spawn(w.go()),
        })
    }
}

#[async_trait]
impl RawComm for TurmoilComm {
    type Err = io::Error;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.tx
            .send((None, msg))
            .map_err(|_| io::Error::from(ErrorKind::WriteZero))?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.tx
            .send((Some(to), msg))
            .map_err(|_| io::Error::from(ErrorKind::WriteZero))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        if let Some(msg) = self.rx.recv().await {
            return Ok(msg);
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        Ok(())
    }
}

enum Connection {
    Identity,
    Remote(Writer),
}

struct Worker {
    key: PublicKey,
    config: HashMap<PublicKey, (String, u16)>,
    peers: HashMap<PublicKey, Connection>,
    tx: UnboundedSender<Vec<u8>>,
    rx: UnboundedReceiver<(Option<PublicKey>, Vec<u8>)>,
    listener: TcpListener,
    identify_tasks: JoinSet<io::Result<(PublicKey, Reader, Writer)>>,
    reader_tasks: JoinSet<io::Result<PublicKey>>,
    connect_tasks: JoinSet<io::Result<(PublicKey, Reader, Writer)>>,
}

impl Worker {
    async fn go(mut self) {
        self.identify_tasks.spawn(pending());
        self.reader_tasks.spawn(pending());
        self.connect_tasks.spawn(pending());
        self.peers.insert(self.key, Connection::Identity);
        loop {
            tokio::select! {
                i = self.listener.accept() => match i {
                    Ok((s, _)) => {
                        debug!("accepted connection");
                        self.identify_tasks.spawn(identify(s));
                    }
                    Err(err) => {
                        warn!(%err, "error accepting connection")
                    }
                },
                Some(a) = self.identify_tasks.join_next() => match a {
                    Ok(Ok((k, r, w))) => {
                        if self.peers.contains_key(&k) && !keep_it() {
                            debug!("rejecting inbound connection");
                            continue
                        }
                        if self.peers.insert(k, Connection::Remote(w)).is_some() {
                            debug!("dropped existing connection");
                        }
                        let tx = self.tx.clone();
                        self.reader_tasks.spawn(read_loop(k, r, tx));
                    }
                    Ok(Err(err)) => {
                        error!(%err, "task errored while identifying peer")
                    }
                    Err(err) => {
                        warn!(%err, "error identifying peer")
                    }
                },
                Some(a) = self.connect_tasks.join_next() => match a {
                    Ok(Ok((k, r, w))) => {
                        trace!("connection established");
                        if self.peers.contains_key(&k) && keep_it() {
                            debug!("connection already established");
                            continue
                        }
                        self.peers.insert(k, Connection::Remote(w));
                        let tx = self.tx.clone();
                        self.reader_tasks.spawn(read_loop(k, r, tx));
                    }
                    Ok(Err(err)) => {
                        error!(%err, "task errored while connecting to peer")
                    }
                    Err(err) => {
                        warn!(%err, "error identifying peer")
                    }
                },
                Some(a) = self.reader_tasks.join_next() => match a {
                    Ok(Ok(k)) => {
                        let a = self.resolve(&k);
                        warn!("connection lost");
                        if self.peers.remove(&k).is_some() {
                            debug!("dropping lost connection");
                        }
                        if self.key <= k {
                            continue
                        }
                        self.connect_tasks.spawn(connect(a, self.key, k));
                    }
                    Ok(Err(err)) => {
                        error!(%err, "task errored while reading from peer")
                    }
                    Err(err) => {
                        warn!(%err, "error identifying peer")
                    }
                },
                Some(o) = self.rx.recv() => {
                    match o {
                        (None, msg) => {
                            trace!("broadcasting message");
                            let bytes = Bytes::from(msg);
                            for &k in self.config.keys() {
                                match self.peers.get_mut(&k) {
                                    Some(Connection::Identity) => {
                                        self.tx.send(bytes.to_vec()).unwrap()
                                    }
                                    Some(Connection::Remote(w)) => {
                                        if let Err(err) = w.send(bytes.clone()).await {
                                            warn!(%err, "error sending message to peer");
                                            if self.peers.remove(&k).is_some() {
                                                debug!("dropping lost connection");
                                            }
                                        }
                                    }
                                    None => {
                                        if self.key <= k {
                                            continue
                                        }
                                        let bytes = bytes.clone();
                                        let addr = self.resolve(&k);
                                        let ours = self.key;
                                        debug!("establishing connection");
                                        self.connect_tasks.spawn(async move {
                                            let (k, r, mut w) = connect(addr, ours, k).await?;
                                            w.send(bytes).await?;
                                            Ok((k, r, w))
                                        });
                                    }
                                }
                            }
                        }
                        (Some(to), msg) => {
                            trace!("sending message");
                            let bytes = Bytes::from(msg);
                            match self.peers.get_mut(&to) {
                                Some(Connection::Identity) => {
                                    self.tx.send(bytes.to_vec()).unwrap()
                                }
                                Some(Connection::Remote(w)) => {
                                    if let Err(err) = w.send(bytes.clone()).await {
                                        warn!(%err, "error sending message");
                                        if self.peers.remove(&to).is_some() {
                                            debug!("dropping lost connection");
                                        }
                                    }
                                }
                                None => {
                                    if self.key <= to {
                                        continue
                                    }
                                    let addr = self.resolve(&to);
                                    let ours = self.key;
                                    debug!("establishing connection");
                                    self.connect_tasks.spawn(async move {
                                        let (k, r, mut w) = connect(addr, ours, to).await?;
                                        w.send(bytes).await?;
                                        Ok((k, r, w))
                                    });
                                }
                            }
                        }
                    }
                },
                else => {
                    break
                }
            }
        }
    }

    fn resolve(&self, k: &PublicKey) -> SocketAddr {
        let (name, port) = self.config.get(k).unwrap();
        SocketAddr::from((turmoil::lookup(name.as_str()), *port))
    }
}

async fn connect(
    a: SocketAddr,
    ours: PublicKey,
    theirs: PublicKey,
) -> io::Result<(PublicKey, Reader, Writer)> {
    let s = TcpStream::connect(a).await?;
    trace!(addr = %a, "connected to");
    let (r, mut w) = codec(s);
    w.send(Bytes::from(ours.to_bytes())).await?;
    Ok((theirs, r, w))
}

async fn identify(s: TcpStream) -> io::Result<(PublicKey, Reader, Writer)> {
    let (mut r, w) = codec(s);
    if let Some(b) = r.try_next().await? {
        let k = PublicKey::from_bytes(&b).map_err(|_| io::Error::other("invalid public key"))?;
        return Ok((k, r, w));
    }
    Err(ErrorKind::UnexpectedEof.into())
}

fn codec(sock: TcpStream) -> (Reader, Writer) {
    let (r, w) = sock.into_split();
    let c = LengthDelimitedCodec::builder();
    let r = c.new_read(r);
    let w = c.new_write(w);
    (r, w)
}

fn keep_it() -> bool {
    rand::random()
}

async fn read_loop(
    k: PublicKey,
    mut r: Reader,
    tx: UnboundedSender<Vec<u8>>,
) -> io::Result<PublicKey> {
    loop {
        match r.try_next().await {
            Ok(Some(x)) => {
                if tx.send(x.to_vec()).is_err() {
                    return Ok(k);
                }
            }
            Ok(None) => return Ok(k),
            Err(err) => {
                error!(%err, "error receiving message");
                return Ok(k);
            }
        }
    }
}

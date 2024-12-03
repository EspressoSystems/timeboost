use std::collections::HashMap;
use std::fmt::Display;
use std::future::pending;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use futures::SinkExt;
use hotshot::types::SignatureKey;
use timeboost_core::traits::comm::RawComm;
use timeboost_core::types::PublicKey;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{error, warn};
use turmoil::ToSocketAddrs;
use turmoil::net::{TcpListener, TcpStream};
use turmoil::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

type Reader = FramedRead<OwnedReadHalf, LengthDelimitedCodec>;
type Writer = FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>;

#[derive(Debug)]
pub struct TurmoilComm {
    tx: mpsc::UnboundedSender<(Option<PublicKey>, Vec<u8>)>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    jh: JoinHandle<()>,
}

impl Drop for TurmoilComm {
    fn drop(&mut self) {
        self.jh.abort()
    }
}

impl TurmoilComm {
    pub async fn create<A, S, I>(addr: A, peers: I) -> io::Result<Self>
    where
        A: ToSocketAddrs,
        S: Display,
        I: IntoIterator<Item = (PublicKey, (S, u16))>
    {
        let listener = TcpListener::bind(addr).await?;
        let (to_worker, from_comm) = mpsc::unbounded_channel();
        let (to_comm, from_worker) = mpsc::unbounded_channel();
        let w = Worker {
            config: peers.into_iter().map(|(k, (s, p))| (k, (s.to_string(), p))).collect(),
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
            jh: tokio::spawn(w.go())
        })
    }
}

#[async_trait]
impl RawComm for TurmoilComm {
    type Err = io::Error;

    async fn broadcast(&mut self, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.tx.send((None, msg)).map_err(|_| io::Error::from(ErrorKind::WriteZero))?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Vec<u8>) -> Result<(), Self::Err> {
        self.tx.send((Some(to), msg)).map_err(|_| io::Error::from(ErrorKind::WriteZero))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Err> {
        if let Some(msg) = self.rx.recv().await {
            return Ok(msg)
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }

    async fn shutdown(&mut self) -> Result<(), Self::Err> {
        Ok(())
    }
}

struct Worker {
    config: HashMap<PublicKey, (String, u16)>,
    peers: HashMap<PublicKey, Writer>,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<(Option<PublicKey>, Vec<u8>)>,
    listener: TcpListener,
    identify_tasks: JoinSet<io::Result<(PublicKey, Reader, Writer)>>,
    reader_tasks: JoinSet<io::Result<PublicKey>>,
    connect_tasks: JoinSet<io::Result<(PublicKey, Reader, Writer)>>
}

impl Worker {
    async fn go(mut self) {
        self.identify_tasks.spawn(pending());
        self.reader_tasks.spawn(pending());
        self.connect_tasks.spawn(pending());
        loop {
            tokio::select! {
                i = self.listener.accept() => match i {
                    Ok((s, _)) => {
                        self.identify_tasks.spawn(identify(s));
                    }
                    Err(err) => {
                        warn!(%err, "error accepting connection")
                    }
                },
                Some(a) = self.identify_tasks.join_next() => match a {
                    Ok(Ok((k, mut r, w))) => {
                        let tx = self.tx.clone();
                        self.reader_tasks.spawn(async move {
                            while let Ok(Some(x)) = r.try_next().await {
                                if tx.send(x.to_vec()).is_err() {
                                    break
                                }
                            }
                            Ok(k)
                        });
                        self.peers.insert(k, w);
                    }
                    Ok(Err(err)) => {
                        error!(%err, "task errored while identifying peer")
                    }
                    Err(err) => {
                        warn!(%err, "error identifying peer")
                    }
                },
                Some(a) = self.connect_tasks.join_next() => match a {
                    Ok(Ok((k, mut r, w))) => {
                        let tx = self.tx.clone();
                        self.reader_tasks.spawn(async move {
                            while let Ok(Some(x)) = r.try_next().await {
                                if tx.send(x.to_vec()).is_err() {
                                    break
                                }
                            }
                            Ok(k)
                        });
                        self.peers.insert(k, w);
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
                        warn!(addr = %a, "connection lost");
                        self.connect_tasks.spawn(connect(a, k));
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
                            let bytes = Bytes::from(msg);
                            for &k in self.config.keys() {
                                if let Some(w) = self.peers.get_mut(&k) {
                                    if let Err(err) = w.send(bytes.clone()).await {
                                        warn!(%err, "error sending message to peer")
                                    }
                                } else {
                                    let bytes = bytes.clone();
                                    let addr = self.resolve(&k);
                                    self.connect_tasks.spawn(async move {
                                        let (k, r, mut w) = connect(addr, k).await?;
                                        w.send(bytes).await?;
                                        Ok((k, r, w))
                                    });
                                }
                            }
                        }
                        (Some(to), msg) => {
                            let bytes = Bytes::from(msg);
                            if let Some(w) = self.peers.get_mut(&to) {
                                if let Err(err) = w.send(bytes.clone()).await {
                                    warn!(%err, "error sending message to peer")
                                }
                            } else {
                                let addr = self.resolve(&to);
                                self.connect_tasks.spawn(async move {
                                    let (k, r, mut w) = connect(addr, to).await?;
                                    w.send(bytes).await?;
                                    Ok((k, r, w))
                                });
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

async fn connect(a: SocketAddr, k: PublicKey) -> io::Result<(PublicKey, Reader, Writer)> {
    let s = TcpStream::connect(a).await?;
    let (r, mut w) = codec(s);
    w.send(Bytes::from(k.to_bytes())).await?;
    Ok((k, r, w))
}

async fn identify(s: TcpStream) -> io::Result<(PublicKey, Reader, Writer)> {
    let (mut r, w) = codec(s);
    if let Some(b) = r.try_next().await? {
        let k = PublicKey::from_bytes(&b).map_err(|_| io::Error::other("invalid public key"))?;
        return Ok((k, r, w))
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

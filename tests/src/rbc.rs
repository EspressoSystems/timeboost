use std::collections::HashMap;
use std::fmt::Display;
use std::future::pending;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;
use futures::SinkExt;
use multisig::PublicKey;
use timeboost_core::traits::comm::RawComm;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::{JoinHandle, JoinSet};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, trace, warn};
use turmoil::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use turmoil::net::{TcpListener, TcpStream};
use turmoil::ToSocketAddrs;

type Reader = FramedRead<OwnedReadHalf, LengthDelimitedCodec>;
type Writer = FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>;

#[derive(Debug)]
pub struct TurmoilComm {
    tx: UnboundedSender<(Option<PublicKey>, Bytes)>,
    rx: UnboundedReceiver<Bytes>,
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
        I: IntoIterator<Item = (PublicKey, (S, u16))>,
    {
        let listener = TcpListener::bind(addr).await?;
        let (to_worker, from_comm) = mpsc::unbounded_channel();
        let (to_comm, from_worker) = mpsc::unbounded_channel();
        let w = Worker {
            config: peers
                .into_iter()
                .map(|(k, (s, p))| (k, (s.to_string(), p)))
                .collect(),
            tx: to_comm,
            rx: from_comm,
            listener,
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

    async fn broadcast(&mut self, msg: Bytes) -> Result<(), Self::Err> {
        self.tx
            .send((None, msg))
            .map_err(|_| io::Error::from(ErrorKind::WriteZero))?;
        Ok(())
    }

    async fn send(&mut self, to: PublicKey, msg: Bytes) -> Result<(), Self::Err> {
        self.tx
            .send((Some(to), msg))
            .map_err(|_| io::Error::from(ErrorKind::WriteZero))?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Bytes, Self::Err> {
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

struct Worker {
    config: HashMap<PublicKey, (String, u16)>,
    tx: UnboundedSender<Bytes>,
    rx: UnboundedReceiver<(Option<PublicKey>, Bytes)>,
    listener: TcpListener,
    reader_tasks: JoinSet<io::Result<()>>,
    connect_tasks: JoinSet<io::Result<(Reader, Writer)>>,
}

impl Worker {
    async fn go(mut self) {
        self.reader_tasks.spawn(pending());
        self.connect_tasks.spawn(pending());
        loop {
            tokio::select! {
                i = self.listener.accept() => match i {
                    Ok((s, _)) => {
                        debug!("accepted connection");
                        let (r, _) = codec(s);
                        let tx = self.tx.clone();
                        self.reader_tasks.spawn(read_loop(r, tx));
                    }
                    Err(err) => {
                        warn!(%err, "error accepting connection")
                    }
                },
                Some(a) = self.connect_tasks.join_next() => match a {
                    Ok(Ok((r, _))) => {
                        trace!("connection established");
                        let tx = self.tx.clone();
                        self.reader_tasks.spawn(read_loop(r, tx));
                    }
                    Ok(Err(err)) => {
                        warn!(%err, "task errored while connecting to peer")
                    }
                    Err(err) => {
                        warn!(%err, "error identifying peer")
                    }
                },
                Some(a) = self.reader_tasks.join_next() => match a {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        warn!(%err, "task errored while reading from peer")
                    }
                    Err(err) => {
                        warn!(%err, "error identifying peer")
                    }
                },
                Some(o) = self.rx.recv() => {
                    match o {
                        (None, bytes) => {
                            trace!("broadcasting message");
                            for &k in self.config.keys() {
                                debug!("establishing connection");
                                let bytes = bytes.clone();
                                let addr = self.resolve(&k);
                                self.connect_tasks.spawn(async move {
                                    let (r, mut w) = connect(addr).await?;
                                    w.send(bytes).await?;
                                    Ok((r, w))
                                });
                            }
                        }
                        (Some(to), bytes) => {
                            trace!("sending message");
                            let addr = self.resolve(&to);
                            self.connect_tasks.spawn(async move {
                                let (r, mut w) = connect(addr).await?;
                                w.send(bytes).await?;
                                Ok((r, w))
                            });
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

async fn connect(a: SocketAddr) -> io::Result<(Reader, Writer)> {
    let s = TcpStream::connect(a).await?;
    trace!(addr = %a, "connected to");
    Ok(codec(s))
}

fn codec(sock: TcpStream) -> (Reader, Writer) {
    let (r, w) = sock.into_split();
    let c = LengthDelimitedCodec::builder();
    let r = c.new_read(r);
    let w = c.new_write(w);
    (r, w)
}

async fn read_loop(mut r: Reader, tx: UnboundedSender<Bytes>) -> io::Result<()> {
    loop {
        match r.try_next().await {
            Ok(Some(x)) => {
                if tx.send(x.freeze()).is_err() {
                    return Ok(());
                }
            }
            Ok(None) => return Ok(()),
            Err(err) => {
                warn!(%err, "error receiving message");
                return Ok(());
            }
        }
    }
}

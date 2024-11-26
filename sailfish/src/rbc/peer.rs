#![allow(unused)] // TODO

use std::future::ready;
use std::io;
use std::iter::repeat;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::SinkExt;
use timeboost_core::types::envelope::Validated;
use tokio::{select, spawn};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, error, warn};

use super::Protocol;

mod ringbuf;

pub type Consumer = ringbuf::Consumer<Bytes>;
pub type Producer = ringbuf::Producer<Bytes>;

type Reader = FramedRead<OwnedReadHalf, LengthDelimitedCodec>;
type Writer = FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>;

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Peer {
    addr: SocketAddr,
    obox: Consumer,
    ibox: mpsc::Sender<Bytes>,
}

impl Peer {
    pub fn new(addr: SocketAddr, cap: NonZeroUsize, tx: mpsc::Sender<Bytes>) -> (Producer, Self) {
        let (p, c) = ringbuf::ringbuf(cap);
        let this = Self { addr, obox: c, ibox: tx };
        (p, this)
    }

    pub async fn go(mut self, sock: Option<TcpStream>) {
        let (mut reader, mut writer) = if let Some(s) = sock {
            assert_eq!(Some(self.addr.ip()), s.peer_addr().ok().map(|a| a.ip()));
            codec(s)
        } else {
            self.connect().await
        };

        let mut reader_task = spawn(inbound(self.addr, reader, self.ibox.clone()));

        loop {
            select! {
                item = &mut reader_task => {
                    (reader, writer) = self.connect().await;
                    reader_task = spawn(inbound(self.addr, reader, self.ibox.clone()))
                },
                item = self.obox.next() => {
                    loop {
                        match timeout(WRITE_TIMEOUT, writer.send(item.clone())).await {
                            Ok(Ok(())) => break,
                            Ok(Err(err)) => {
                                warn!(addr = %self.addr, %err, "write error");
                                reader_task.abort();
                                (reader, writer) = self.connect().await;
                                reader_task = spawn(inbound(self.addr, reader, self.ibox.clone()));
                                break
                            }
                            Err(_) => {
                                debug!(addr = %self.addr, "write timeout");
                                if self.obox.is_full() {
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn connect(&mut self) -> (Reader, Writer) {
        for d in [1, 1, 1, 1, 3, 5, 6, 7, 10, 15].into_iter().chain(repeat(30)) {
            debug!(addr = %self.addr, "connecting ...");
            if let Ok(sock) = TcpStream::connect(self.addr).await {
                debug!(addr = %self.addr, "connection established");
                return codec(sock)
            }
            sleep(Duration::from_secs(d)).await
        }
        unreachable!("for loop uses `repeat`")
    }
}

fn codec(mut sock: TcpStream) -> (Reader, Writer) {
    let (r, w) = sock.into_split();
    let c = LengthDelimitedCodec::builder();
    let r = c.new_read(r);
    let w = c.new_write(w);
    (r, w)
}

async fn inbound(addr: SocketAddr, mut r: Reader, ibox: mpsc::Sender<Bytes>) {
    loop {
        match r.try_next().await {
            Ok(Some(x)) => {
                if ibox.send(x.into()).await.is_err() {
                    break
                }
            }
            Ok(None) => {
                warn!(%addr, "connection lost");
                break
            }
            Err(err) => {
                warn!(%addr, %err, "read error");
                break
            }
        }
    }
}


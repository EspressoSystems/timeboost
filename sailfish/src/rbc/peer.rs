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
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::time::{sleep, timeout};
use tokio::{select, spawn};
use tokio_stream::StreamExt;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};
use tracing::{debug, error, warn};

use super::Protocol;

mod ringbuf;

pub type Consumer = ringbuf::Consumer<Bytes>;
pub type Producer = ringbuf::Producer<Bytes>;

type Reader = FramedRead<OwnedReadHalf, LengthDelimitedCodec>;
type Writer = FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>;

#[derive(Debug)]
pub struct Peer {
    addr: SocketAddr,
    obox: Consumer,
    ibox: mpsc::Sender<Bytes>,
}

impl Peer {
    pub fn new(addr: SocketAddr, cap: NonZeroUsize, tx: mpsc::Sender<Bytes>) -> (Producer, Self) {
        let (p, c) = ringbuf::ringbuf(cap);
        let this = Self {
            addr,
            obox: c,
            ibox: tx,
        };
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
        let mut writer_task = spawn(outbound(self.addr, writer, self.obox.clone()));

        loop {
            select! {
                _ = &mut reader_task => {
                    writer_task.abort();
                    (reader, writer) = self.connect().await;
                    reader_task = spawn(inbound(self.addr, reader, self.ibox.clone()));
                    writer_task = spawn(outbound(self.addr, writer, self.obox.clone()));
                },
                _ = &mut writer_task => {
                    reader_task.abort();
                    (reader, writer) = self.connect().await;
                    reader_task = spawn(inbound(self.addr, reader, self.ibox.clone()));
                    writer_task = spawn(outbound(self.addr, writer, self.obox.clone()));
                }
            }
        }
    }

    async fn connect(&mut self) -> (Reader, Writer) {
        for d in [1, 1, 1, 3, 5, 10, 15].into_iter().chain(repeat(30)) {
            debug!(addr = %self.addr, "connecting ...");
            if let Ok(sock) = TcpStream::connect(self.addr).await {
                debug!(addr = %self.addr, "connection established");
                return codec(sock);
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
                    break;
                }
            }
            Ok(None) => {
                warn!(%addr, "connection lost");
                break;
            }
            Err(err) => {
                warn!(%addr, %err, "read error");
                break;
            }
        }
    }
}

async fn outbound(addr: SocketAddr, mut w: Writer, obox: Consumer) {
    loop {
        let (v, item) = obox.peek().await;
        for d in [1, 1, 1, 3, 5, 10, 15].into_iter().chain(repeat(30)) {
            if let Err(err) = w.send(item.clone()).await {
                debug!(%addr, %err, "write error");
                if obox.head_version() != Some(v) {
                    debug!(%addr, "moving on to next item");
                    break;
                }
                sleep(Duration::from_secs(d)).await
            } else {
                obox.drop_head_if(v);
                break;
            }
        }
    }
}

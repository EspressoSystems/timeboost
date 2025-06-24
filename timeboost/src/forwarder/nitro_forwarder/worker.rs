use std::{
    future::pending,
    io::{Error, ErrorKind},
    iter::repeat,
    time::Duration,
};

use cliquenet::Address;
use futures::future::Either;
use multisig::PublicKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    select,
    sync::mpsc::Receiver,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{error, info, warn};

use crate::forwarder::data::Data;

/// Expected ack value from nitro node
const ACK_FLAG: u8 = 0xc0;

/// Max. allowed duration of a single TCP connect attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Max. nitro acknowledgement read timeout
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Worker {
    key: PublicKey,
    stream: TcpStream,
    nitro_addr: Address,
    incls_rx: Receiver<Data>,
    pending: Option<Data>,
    connect_task: Option<JoinHandle<TcpStream>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(h) = self.connect_task.take() {
            h.abort();
        }
    }
}

impl Worker {
    pub async fn connect(
        key: PublicKey,
        addr: &Address,
        incls_rx: Receiver<Data>,
    ) -> Result<Self, Error> {
        let stream = Self::try_connect(addr).await?;
        stream.set_nodelay(true)?;
        Ok(Self {
            key,
            stream,
            nitro_addr: addr.clone(),
            incls_rx,
            pending: None,
            connect_task: None,
        })
    }

    pub async fn go(mut self) {
        loop {
            let connect = if let Some(f) = &mut self.connect_task {
                Either::Right(f)
            } else {
                Either::Left(pending())
            };
            select! {
                val = self.incls_rx.recv(), if self.pending.is_none() => match val {
                    Some(d) => {
                        self.send(d).await
                    }
                    None => {
                        warn!(node = %self.key, "disconnected inclusion list receiver");
                        break;
                    }
                },
                val = connect => match val {
                    Ok(s) => {
                        self.stream = s;
                        self.connect_task = None;
                        if let Some(d) = self.pending.take() {
                            self.send(d).await
                        }
                    }
                    Err(err) => {
                        error!(node = %self.key, %err, "disconnected stream receiver");
                        break;
                    }
                }
            }
        }
    }

    async fn send(&mut self, d: Data) {
        if let Err(err) = self.write(&d).await {
            warn!(node = %self.key, %err, "failed to forward data to nitro");
            debug_assert!(self.pending.is_none());
            self.pending = Some(d);
            self.spawn_reconnect();
        }
    }

    async fn write(&mut self, d: &Data) -> Result<(), Error> {
        self.stream.write_u32(d.len()).await?;
        self.stream.write_all(d.bytes()).await?;

        let mut ack = [0u8; 1];
        match timeout(ACK_TIMEOUT, self.stream.read_exact(&mut ack)).await {
            Ok(r) => {
                r?;
                if ack[0] != ACK_FLAG {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "received unexpected acknowledgement flag from server",
                    ));
                }
                Ok(())
            }
            Err(_) => Err(Error::new(
                ErrorKind::TimedOut,
                "ack read operation timed out",
            )),
        }
    }

    fn spawn_reconnect(&mut self) {
        info!(node = %self.key, "spawning nitro reconnect task");
        let addr = self.nitro_addr.clone();
        let node = self.key;
        debug_assert!(self.connect_task.is_none());
        self.connect_task = Some(tokio::spawn(async move {
            for d in [0, 1, 3, 6, 10, 15].into_iter().chain(repeat(20)) {
                match Self::try_connect(&addr).await {
                    Ok(s) => {
                        if let Err(err) = s.set_nodelay(true) {
                            warn!(%node, %err, "failed to set nodelay");
                        } else {
                            info!(%node, %addr, "reconnected successfully to nitro node");
                            return s;
                        }
                    }
                    Err(err) => {
                        warn!(%node, %err, interval = %d, "failed to reconnect to nitro server");
                    }
                }
                sleep(Duration::from_secs(d)).await;
            }
            unreachable!("for-loop repeats forever")
        }))
    }

    async fn try_connect(addr: &Address) -> Result<TcpStream, Error> {
        match addr {
            Address::Inet(a, p) => timeout(CONNECT_TIMEOUT, TcpStream::connect((*a, *p))).await?,
            Address::Name(h, p) => {
                timeout(CONNECT_TIMEOUT, TcpStream::connect((h.as_ref(), *p))).await?
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };

    use cliquenet::Address;
    use multisig::Keypair;
    use prost::Message;
    use timeboost_proto::proto_types::{InclusionList, Transaction};
    use timeboost_types::Timestamp;
    use timeboost_utils::types::logging::init_logging;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::mpsc::channel,
        time::sleep,
    };

    use super::{ACK_FLAG, Worker};
    use crate::forwarder::data::Data;

    #[test]
    fn simple_encode_and_decode() {
        let old = Transaction {
            encoded_txn: Vec::new(),
            address: "0x00".as_bytes().to_vec(),
            timestamp: *Timestamp::now(),
        };
        let bytes = old.encode_to_vec();

        let new = Transaction::decode(bytes.as_slice()).unwrap();

        assert_eq!(new, old);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_forward() {
        init_logging();

        let p = portpicker::pick_unused_port().expect("available port");
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p));
        let l = TcpListener::bind(a).await.expect("socket to be bound");
        let cap = 10;
        let (tx, rx) = channel(cap);
        let keypair = Keypair::generate();
        let w = Worker::connect(keypair.public_key(), &Address::from(a), rx)
            .await
            .expect("forwarder connection to succeed");
        let jh = tokio::spawn(w.go());
        let (mut s, _) = l.accept().await.expect("connection to be established");

        // after successful connection simulate nitro going down, close socket
        s.shutdown().await.expect("disconnect");
        drop(s);
        drop(l);

        // we should fail
        let max = 3;
        for i in 0..max {
            let d = Data::encode(i, i, Vec::new()).expect("data to be encoded");
            let r = tx.send(d).await;
            assert!(r.is_ok());
            assert_eq!(tx.capacity(), cap - (i + 1) as usize);
        }

        let l = TcpListener::bind(a).await.expect("listener to start");
        let (mut s, _) = l.accept().await.expect("connection to be established");

        // wait for reconnect
        sleep(Duration::from_millis(100)).await;

        let server = async {
            let mut buf = [0u8; 1024];
            for i in 0..=max {
                let size = s.read_u32().await.expect("size to be read") as usize;
                s.read_exact(&mut buf[..size])
                    .await
                    .expect("encoded bytes to be read");
                let incl =
                    InclusionList::decode(&buf[..size]).expect("inclusion list to be decoded");
                assert_eq!(incl.round, i);
                assert_eq!(incl.consensus_timestamp, i);
                s.write_all(&[ACK_FLAG]).await.expect("ack to be sent");
            }

            // wait to ensure client receives ack before we teriminate future
            sleep(Duration::from_millis(100)).await;
        };

        let d = Data::encode(max, max, Vec::new()).expect("data to be encoded");
        let (r, _) = tokio::join!(tx.send(d), server);
        assert!(r.is_ok());
        // all data should be processed from channel, back to max cap
        assert_eq!(tx.capacity(), cap);
        jh.abort();
    }
}

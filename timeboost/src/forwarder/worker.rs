use std::{
    collections::VecDeque,
    io::{Error, ErrorKind},
    iter::repeat,
    time::Duration,
};

use cliquenet::Address;
use multisig::PublicKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc::{Receiver, Sender, channel},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::forwarder::{data::Data, nitro_forwarder::Command};

/// Expected ack value from nitro node
const ACK_FLAG: u8 = 0xc0;

/// Max. allowed duration of a single TCP connect attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Max. nitro acknowledgement read timeout
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

enum WorkerState {
    Connected,
    Reconnecting,
}

pub struct Worker {
    key: PublicKey,
    stream: TcpStream,
    state: WorkerState,
    nitro_addr: Address,
    incls_rx: Receiver<Command>,
    stream_rx: Receiver<TcpStream>,
    stream_tx: Sender<TcpStream>,
    retry_cache: VecDeque<Data>,
    jh: JoinHandle<()>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.jh.abort();
    }
}

impl Worker {
    pub(crate) async fn connect(
        key: PublicKey,
        addr: &Address,
        incls_rx: Receiver<Command>,
    ) -> Result<Self, Error> {
        let stream = Self::try_get_stream(addr).await?;
        stream.set_nodelay(true)?;
        let (tx, rx) = channel(1);
        Ok(Self {
            key,
            stream,
            state: WorkerState::Connected,
            nitro_addr: addr.clone(),
            incls_rx,
            stream_rx: rx,
            stream_tx: tx,
            retry_cache: VecDeque::new(),
            jh: tokio::spawn(async {}),
        })
    }

    pub(crate) async fn go(mut self) {
        loop {
            tokio::select! {
                val = self.incls_rx.recv() => match val {
                    Some(Command::Send(d)) => {
                        if let Err(err) = self.send(d).await {
                            warn!(node = %self.key, %err, "failed sending inclusion list");
                        }
                    }
                    None => {
                        warn!(node = %self.key, "disconnected inclusion list receiver");
                        break;
                    }
                },
                val = self.stream_rx.recv() => match val {
                    Some(s) => {
                        self.stream = s;
                        self.state = WorkerState::Connected;
                    }
                    None => {
                        warn!(node = %self.key, "disconnected stream receiver");
                        break;
                    }
                }
            }
        }
    }

    async fn send(&mut self, d: Data) -> Result<(), Error> {
        if matches!(self.state, WorkerState::Reconnecting) {
            self.retry_cache.push_back(d);
            return Err(Error::new(
                ErrorKind::NotConnected,
                "worker not connected to nitro",
            ));
        }

        while let Some(retry) = self.retry_cache.pop_front() {
            if let Err(e) = self.write_and_wait_for_ack(&retry).await {
                self.retry_cache.push_front(retry);
                self.retry_cache.push_back(d);
                self.spawn_reconnect();
                return Err(e);
            }
        }

        if let Err(e) = self.write_and_wait_for_ack(&d).await {
            self.retry_cache.push_back(d);
            self.spawn_reconnect();
            return Err(e);
        }
        Ok(())
    }

    async fn write_and_wait_for_ack(&mut self, d: &Data) -> Result<(), Error> {
        self.stream.write_u32(d.len()).await?;
        self.stream.write_all(d.bytes()).await?;

        let mut ack = [0u8; 1];
        match timeout(ACK_TIMEOUT, self.stream.read_exact(&mut ack)).await {
            Ok(r) => {
                r?;
                if *ack.first().expect("index to be present") != ACK_FLAG {
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

    async fn try_get_stream(addr: &Address) -> Result<TcpStream, Error> {
        match addr {
            Address::Inet(a, p) => timeout(CONNECT_TIMEOUT, TcpStream::connect((*a, *p))).await?,
            Address::Name(h, p) => {
                timeout(CONNECT_TIMEOUT, TcpStream::connect((h.as_ref(), *p))).await?
            }
        }
    }

    fn spawn_reconnect(&mut self) {
        info!(node = %self.key, "spawning nitro reconnect task");
        self.state = WorkerState::Reconnecting;
        let addr = self.nitro_addr.clone();
        let tx = self.stream_tx.clone();
        let node = self.key;
        self.jh = tokio::spawn(async move {
            for d in [0, 1000, 3000, 6000, 10_000, 15_000]
                .into_iter()
                .chain(repeat(20_000))
            {
                let r = Self::try_get_stream(&addr).await;
                match r {
                    Ok(s) => {
                        if let Err(err) = s.set_nodelay(true) {
                            warn!(%node, %err, "failed to set nodelay");
                            continue;
                        }

                        if let Err(err) = tx.send(s).await {
                            warn!(%node, %err, "failed to send tcp stream");
                            continue;
                        }
                        info!(%node, "reconnected successfully to nitro node");
                        break;
                    }
                    Err(err) => {
                        warn!(%node, %err, interval = %d, "failed to reconnect to nitro server");
                        sleep(Duration::from_millis(d)).await;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {

    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        time::Duration,
    };

    use crate::forwarder::{
        data::Data,
        worker::{ACK_FLAG, Command, Worker},
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
        let (tx, rx) = channel(10);
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

        // we should fail, so push onto our retry queue
        let max = 3;
        for i in 0..max {
            let d = Data::encode(i, i, Vec::new()).expect("data to be encoded");
            let r = tx.send(Command::Send(d)).await;
            assert!(r.is_ok());
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
        let (r, _) = tokio::join!(tx.send(Command::Send(d)), server);
        assert!(r.is_ok());
        jh.abort();
    }
}

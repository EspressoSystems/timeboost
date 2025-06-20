use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use cliquenet::Address;
use std::io::{Error, ErrorKind};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tracing::{info, warn};

use crate::forwarder::data::Data;

pub struct NitroForwarder {
    retry_cache: VecDeque<Data>,
    stream: Arc<Mutex<TcpStream>>,
    addr: Address,
    jh: JoinHandle<()>,
}

impl NitroForwarder {
    pub async fn connect(addr: &Address) -> Result<Self, Error> {
        let s = Self::try_get_stream(addr).await?;
        s.set_nodelay(true)?;
        Ok(Self {
            retry_cache: VecDeque::new(),
            stream: Arc::new(Mutex::new(s)),
            addr: addr.clone(),
            jh: tokio::spawn(async {}),
        })
    }

    pub async fn send(&mut self, d: Data) -> Result<(), Error> {
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
        let mut s = self.stream.lock().await;
        s.write_u32(d.len()).await?;
        s.write_all(d.bytes()).await?;

        let mut buf = [0u8; 1];
        match timeout(Duration::from_secs(5), s.read_exact(&mut buf)).await {
            Ok(r) => r.map(|_| ()),
            Err(_) => Err(Error::new(ErrorKind::TimedOut, "read operation timed out")),
        }
    }

    async fn try_get_stream(addr: &Address) -> Result<TcpStream, Error> {
        match addr {
            Address::Inet(a, p) => {
                timeout(Duration::from_secs(5), TcpStream::connect((*a, *p))).await?
            }
            Address::Name(h, p) => {
                timeout(Duration::from_secs(5), TcpStream::connect((h.as_ref(), *p))).await?
            }
        }
    }

    fn spawn_reconnect(&mut self) {
        if !self.jh.is_finished() {
            return;
        }
        let addr = self.addr.clone();
        let old = Arc::clone(&self.stream);
        self.jh = tokio::spawn(async move {
            for time in [0, 1, 3, 5] {
                let r = Self::try_get_stream(&addr).await;
                match r {
                    Ok(s) => {
                        if let Err(e) = s.set_nodelay(true) {
                            warn!("failed to set nodelay: {}", e);
                            continue;
                        }
                        info!("reconnected successfully to nitro node");
                        let mut stream = old.lock().await;
                        *stream = s;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "reconnect attempt timed out. next retry in: {}, error: {}",
                            time, e
                        );
                        sleep(Duration::from_secs(time)).await;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {

    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        time::Duration,
    };

    use crate::forwarder::data::Data;

    use super::NitroForwarder;
    use cliquenet::Address;
    use prost::Message;
    use timeboost_proto::proto_types::{InclusionList, Transaction};
    use timeboost_types::Timestamp;
    use timeboost_utils::types::logging::init_logging;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
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
        let a = std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p));
        let addr = &Address::from(a);
        let l = TcpListener::bind(a).await.expect("socket to be bound");
        let mut f = NitroForwarder::connect(addr)
            .await
            .expect("forwarder connection to succeed");
        let (mut s, _) = l.accept().await.expect("connection to be established");

        // After successful connection simulate nitro going down, close socket
        s.shutdown().await.expect("disconnect");
        drop(s);
        drop(l);

        // We should fail, so push onto our retry queue
        let max = 3;
        for i in 0..max {
            let d = Data::encode(i, i, Vec::new()).expect("data to be encoded");
            let r = f.send(d).await;
            assert!(r.is_err());
            assert_eq!(f.retry_cache.len() as u64, i + 1);
        }

        let l = TcpListener::bind(a).await.expect("listener to start");
        let (mut s, _) = l.accept().await.expect("connection to be established");

        // wait for reconnect
        sleep(Duration::from_millis(50)).await;

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

                let ack = [0u8; 1];
                s.write_all(&ack).await.expect("ack to be sent");
            }

            // wait to ensure client receives ack
            sleep(Duration::from_millis(500)).await;
        };

        let d = Data::encode(max, max, Vec::new()).expect("data to be encoded");
        let (r, _) = tokio::join!(f.send(d), server);
        assert!(r.is_ok());

        assert_eq!(f.retry_cache.len(), 0);
        let _ = f.stream.lock().await.shutdown().await;
    }
}

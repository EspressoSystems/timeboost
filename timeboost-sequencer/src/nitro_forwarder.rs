use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddrV4},
};

use alloy_eips::eip2718::Encodable2718;
use prost::Message;
use std::io::{Error, ErrorKind};
use timeboost_proto::inclusion_list::{InclusionList, Transaction};
use timeboost_types::Timestamp;
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub struct NitroForwarder {
    retry_cache: BTreeMap<u64, InclusionList>,
    stream: Option<TcpStream>,
    nitro_port: u16,
}

impl NitroForwarder {
    pub fn new(nitro_port: u16) -> Self {
        Self {
            retry_cache: BTreeMap::new(),
            stream: None,
            nitro_port,
        }
    }

    pub async fn send(
        &mut self,
        txs: &[timeboost_types::Transaction],
        round: u64,
        time: Timestamp,
        delayed_messages_read: u64,
    ) -> Result<(), Error> {
        let encoded_txns: Vec<Transaction> = txs
            .iter()
            .map(|tx| Transaction {
                encoded_txn: tx.encoded_2718(),
                address: tx.address().as_slice().to_vec(),
                timestamp: **tx.time(),
            })
            .collect();
        let inclusion = InclusionList {
            round,
            encoded_txns,
            consensus_timestamp: *time,
            delayed_messages_read,
        };

        while let Some((_, retry)) = self.retry_cache.pop_first() {
            if let Err(e) = self.write(&retry).await {
                self.on_failure(vec![retry, inclusion]).await?;
                return Err(e);
            }
        }

        if let Err(e) = self.write(&inclusion).await {
            self.on_failure(vec![inclusion]).await?;
            return Err(e);
        }
        Ok(())
    }

    async fn connect(&mut self) -> Result<(), Error> {
        if self.stream.is_none() {
            let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.nitro_port);
            self.stream = Some(TcpStream::connect(addr).await?);
        }

        Ok(())
    }

    async fn write(&mut self, inclusion: &InclusionList) -> Result<(), Error> {
        self.connect().await?;

        let len = u32::try_from(inclusion.encoded_len())
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "length exceeds u32 max"))?;

        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::NotConnected, "tcp stream not established"))?;
        stream.write_u32(len).await?;
        stream.write_all(&inclusion.encode_to_vec()).await?;
        Ok(())
    }

    async fn on_failure(&mut self, incls: Vec<InclusionList>) -> Result<(), Error> {
        for i in incls {
            self.retry_cache.insert(i.round, i);
        }
        if let Some(stream) = &mut self.stream.take() {
            // in case of bad tcp connection close stream and create new one
            self.stream = None;
            stream.shutdown().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{
        collections::BTreeMap,
        io::Read,
        net::{Ipv4Addr, SocketAddrV4, TcpListener},
    };

    use super::NitroForwarder;
    use prost::Message;
    use timeboost_proto::inclusion_list::{InclusionList, Transaction};
    use timeboost_types::Timestamp;
    use timeboost_utils::types::logging::init_logging;
    use tokio::io::AsyncWriteExt;
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

    #[tokio::test]
    async fn test_forward() {
        let p = portpicker::pick_unused_port().unwrap();
        let mut f = NitroForwarder {
            nitro_port: p,
            retry_cache: BTreeMap::new(),
            stream: None,
        };
        let r = f.connect().await;
        assert!(r.is_err());

        let mut i = InclusionList {
            encoded_txns: Vec::new(),
            round: 0,
            consensus_timestamp: 0,
            delayed_messages_read: 0,
        };
        let r = f
            .send(
                &Vec::new(),
                i.round,
                i.consensus_timestamp.into(),
                i.delayed_messages_read,
            )
            .await;
        assert!(r.is_err());
        assert_eq!(f.retry_cache.len(), 1);
        let l = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, f.nitro_port)).unwrap();

        i.round = 1;
        i.delayed_messages_read = 10;
        let r = f
            .send(
                &Vec::new(),
                i.round,
                i.consensus_timestamp.into(),
                i.delayed_messages_read,
            )
            .await;
        assert!(r.is_ok());

        let mut a = l.accept().unwrap();

        let mut size_buf = [0u8; 4];
        let mut buf = [0u8; 1024];

        a.0.read_exact(&mut size_buf).unwrap();
        let size = u32::from_be_bytes(size_buf) as usize;
        a.0.read_exact(&mut buf[..size]).unwrap();
        let first = InclusionList::decode(&buf[..size]).unwrap();
        assert_eq!(first.round, 0);
        assert_eq!(first.delayed_messages_read, 0);
        assert_eq!(f.retry_cache.len(), 0);

        a.0.read_exact(&mut size_buf).unwrap();
        let size = u32::from_be_bytes(size_buf) as usize;
        a.0.read_exact(&mut buf[..size]).unwrap();
        let second = InclusionList::decode(&buf[..size]).unwrap();
        assert_eq!(second.round, 1);
        assert_eq!(second.delayed_messages_read, 10);
        assert_eq!(f.retry_cache.len(), 0);
        let _ = f.stream.unwrap().shutdown().await;
        drop(l);
    }
}

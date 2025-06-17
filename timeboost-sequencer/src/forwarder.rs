use std::collections::BTreeMap;

use alloy_eips::eip2718::Encodable2718;
use prost::Message;
use std::io::{Error, ErrorKind};
use timeboost_proto::inclusion_list::{ProtoAddress, ProtoInclusionList, ProtoTransaction};
use timeboost_types::{Timestamp, Transaction};
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[allow(unused)]
pub struct Forwarder {
    retry_cache: BTreeMap<u64, ProtoInclusionList>,
    stream: Option<TcpStream>,
}

impl Forwarder {
    pub fn new() -> Self {
        Self {
            retry_cache: BTreeMap::new(),
            stream: None,
        }
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        self.stream = match TcpStream::connect("127.0.0.1:55000").await {
            Ok(s) => Some(s),
            Err(e) => return Err(e),
        };
        Ok(())
    }

    pub async fn try_send(
        &mut self,
        txs: Vec<Transaction>,
        round: u64,
        time: Timestamp,
    ) -> Result<(), Error> {
        let encoded_txns: Vec<ProtoTransaction> = txs
            .iter()
            .map(|tx| {
                let p = ProtoTransaction {
                    encoded_txn: tx.encoded_2718(),
                    address: Some(ProtoAddress::from(*tx.address())),
                    timestamp: **tx.time(),
                };
                p
            })
            .collect();
        let list = ProtoInclusionList {
            round,
            encoded_txns,
            consensus_timestamp: *time,
        };
        if self.stream.is_none() {
            if let Err(e) = self.connect().await {
                self.retry_cache.insert(round, list);
                return Err(e);
            }
        }

        self.retry().await?;

        self.send(list).await?;
        Ok(())
    }

    async fn send(&mut self, inclusion: ProtoInclusionList) -> Result<(), Error> {
        if let Some(s) = &mut self.stream {
            let len = u32::try_from(inclusion.encoded_len())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "length exceeds u32::MAX"))?;
            
            if let Err(e) = s.write_u32(len).await {
                self.retry_cache.insert(inclusion.round, inclusion);
                return Err(e);
            }
            if let Err(e) = s.write_all(&inclusion.encode_to_vec()).await {
                self.retry_cache.insert(inclusion.round, inclusion);
                return Err(e);
            };
        }
        Ok(())
    }

    async fn retry(&mut self) -> Result<(), Error> {
        if self.retry_cache.is_empty() {
            return Ok(());
        }
        let (_, i) = self.retry_cache.pop_first().unwrap();
        self.send(i).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::{collections::BTreeMap, io::Read, net::TcpListener};

    use super::Forwarder;
    use prost::Message;
    use timeboost_proto::inclusion_list::{ProtoAddress, ProtoInclusionList};
    use timeboost_utils::types::logging::init_logging;
    use tokio::io::AsyncWriteExt;
    #[test]
    fn simple_encode_and_decode() {
        let v = vec![0];
        let old = ProtoAddress {
            raw: v,
            hex: "0x0".to_string(),
        };
        let bytes = old.encode_to_vec();

        let new = ProtoAddress::decode(bytes.as_slice()).unwrap();

        assert_eq!(new, old);
    }

    #[tokio::test]
    async fn test_forward() {
        init_logging();
        let mut f = Forwarder {
            retry_cache: BTreeMap::new(),
            stream: None,
        };
        let r = f.connect().await;
        assert!(r.is_err());

        let mut i = ProtoInclusionList {
            encoded_txns: Vec::new(),
            round: 0,
            consensus_timestamp: 0,
        };
        let r = f
            .try_send(Vec::new(), i.round, i.consensus_timestamp.into())
            .await;
        assert!(r.is_err());
        assert_eq!(f.retry_cache.len(), 1);

        let l = TcpListener::bind("127.0.0.1:55000").unwrap();

        i.round = 1;
        let r = f
            .try_send(Vec::new(), i.round, i.consensus_timestamp.into())
            .await;
        assert!(r.is_ok());

        let mut a = l.accept().unwrap();

        let mut size_buf = [0u8; 4];
        let mut buf = [0u8; 1024];

        a.0.read_exact(&mut size_buf).unwrap();
        let size = u32::from_be_bytes(size_buf);
        a.0.read_exact(&mut buf[..size as usize]).unwrap();
        let first = ProtoInclusionList::decode(&buf[..size as usize]).unwrap();
        assert_eq!(first.round, 0);
        assert_eq!(f.retry_cache.len(), 0);

        a.0.read_exact(&mut size_buf).unwrap();
        let size = u32::from_be_bytes(size_buf);
        a.0.read_exact(&mut buf[..i.encoded_len()]).unwrap();
        let second = ProtoInclusionList::decode(&buf[..size as usize]).unwrap();
        assert_eq!(second.round, 1);
        assert_eq!(f.retry_cache.len(), 0);
        let _ = f.stream.unwrap().shutdown().await;
        drop(l);
    }
}

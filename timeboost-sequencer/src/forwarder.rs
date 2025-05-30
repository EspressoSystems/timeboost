use std::collections::BTreeMap;

use prost::Message;
use timeboost_proto::inclusion_list::InclusionList;
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[allow(unused)]
pub struct Forwarder {
    retry_cache: BTreeMap<u64, InclusionList>,
    stream: Option<TcpStream>,
}

impl Forwarder {
    #[allow(unused)]
    pub async fn connect(&mut self) -> Result<(), std::io::Error> {
        self.stream = match TcpStream::connect("127.0.0.1:11000").await {
            Ok(s) => Some(s),
            Err(e) => return Err(e),
        };
        Ok(())
    }

    #[allow(unused)]
    pub async fn try_send(&mut self, include: InclusionList) -> Result<(), std::io::Error> {
        if self.stream.is_none() {
            if let Err(e) = self.connect().await {
                self.retry_cache.insert(include.round, include);
                return Err(e);
            }
        }

        self.retry().await?;

        self.send(include).await?;
        Ok(())
    }

    #[allow(unused)]
    async fn send(&mut self, include: InclusionList) -> Result<(), std::io::Error> {
        if let Some(s) = &mut self.stream {
            if let Err(e) = s.write_all(&include.encode_to_vec()).await {
                self.retry_cache.insert(include.round, include);
                return Err(e);
            };
        }
        Ok(())
    }

    #[allow(unused)]
    async fn retry(&mut self) -> Result<(), std::io::Error> {
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
    use timeboost_proto::inclusion_list::{Address, InclusionList, Transaction};
    use timeboost_utils::types::logging::init_logging;
    use tokio::io::AsyncWriteExt;
    #[test]
    fn simple_encode_and_decode() {
        let v = vec![0];
        let old = Address {
            raw: v,
            hex: "0x0".to_string(),
        };
        let bytes = old.encode_to_vec();

        let new = Address::decode(bytes.as_slice()).unwrap();

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

        let t = Transaction {
            tx: None,
            addr: None,
            time: None,
        };
        let mut i = InclusionList {
            transactions: [t].to_vec(),
            round: 0,
        };
        let r = f.try_send(i.clone()).await;
        assert!(r.is_err());
        assert_eq!(f.retry_cache.len(), 1);

        let l = TcpListener::bind("127.0.0.1:11000").unwrap();

        let length = i.encoded_len();
        i.round = 1;
        let r = f.try_send(i.clone()).await;
        assert!(r.is_ok());

        let mut a = l.accept().unwrap();

        let mut buf = vec![0u8; 1024];
        a.0.read_exact(&mut buf[..length]).unwrap();
        let first = InclusionList::decode(&buf[..length]).unwrap();
        assert_eq!(first.round, 0);
        assert_eq!(f.retry_cache.len(), 0);

        a.0.read_exact(&mut buf[..i.encoded_len()]).unwrap();
        let second = InclusionList::decode(&buf[..i.encoded_len()]).unwrap();
        assert_eq!(second.round, 1);
        assert_eq!(f.retry_cache.len(), 0);
        let _ = f.stream.unwrap().shutdown().await;
        drop(l);
    }
}

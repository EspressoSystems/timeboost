use std::{iter::repeat, time::Duration};

use multisig::PublicKey;
use timeboost_proto::{forward::forward_api_client::ForwardApiClient, inclusion::InclusionList};
use tokio::{sync::mpsc::Receiver, time::sleep};
use tonic::transport::Channel;
use tracing::warn;

pub struct Worker {
    key: PublicKey,
    client: ForwardApiClient<Channel>,
    incls_rx: Receiver<InclusionList>,
}

impl Worker {
    pub fn new(
        key: PublicKey,
        client: ForwardApiClient<Channel>,
        incls_rx: Receiver<InclusionList>,
    ) -> Self {
        Self {
            key,
            client,
            incls_rx,
        }
    }

    pub async fn go(mut self) {
        let delays = || [1, 1, 1, 3, 5, 10].into_iter().chain(repeat(15));
        while let Some(incl) = self.incls_rx.recv().await {
            let mut d = delays();
            while let Err(err) = self.client.submit_inclusion_list(incl.clone()).await {
                warn!(node = %self.key, %err, "failed to forward data to nitro");
                let t = Duration::from_secs(d.next().expect("iterator repeats endlessly"));
                sleep(t).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use multisig::Keypair;
    use prost::{Message, bytes::Bytes};
    use timeboost_proto::{
        forward::{
            forward_api_client::ForwardApiClient,
            forward_api_server::{ForwardApi, ForwardApiServer},
        },
        inclusion::{InclusionList, Transaction},
    };
    use timeboost_utils::{ports::alloc_port, types::logging::init_logging};
    use tokio::{
        sync::mpsc::channel,
        time::{sleep, timeout},
    };
    use tonic::{
        Request, Response, Status,
        transport::{Channel, Server},
    };

    use crate::types::Timestamp;

    use super::Worker;

    #[test]
    fn simple_encode_and_decode() {
        let old = Transaction {
            encoded_txn: Bytes::new(),
            address: "0x00".as_bytes().to_vec(),
            timestamp: *Timestamp::now(),
        };
        let bytes = old.encode_to_vec();

        let new = Transaction::decode(bytes.as_slice()).unwrap();

        assert_eq!(new, old);
    }

    struct ForwarderApiService {
        counter: Arc<AtomicU64>,
    }
    impl ForwarderApiService {
        pub fn new(counter: Arc<AtomicU64>) -> Self {
            Self { counter }
        }
    }

    #[tonic::async_trait]
    impl ForwardApi for ForwarderApiService {
        async fn submit_inclusion_list(
            &self,
            req: Request<InclusionList>,
        ) -> Result<Response<()>, Status> {
            let incl = req.into_inner();
            let current = self.counter.load(Ordering::Relaxed);
            assert_eq!(incl.round, current);
            assert_eq!(incl.consensus_timestamp, current);
            self.counter.fetch_add(1, Ordering::Relaxed);
            return Ok(Response::new(()));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_forward() {
        init_logging();

        let p = alloc_port().await.unwrap();
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p));
        let cap = 10;
        let (tx, rx) = channel(cap);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // start server and wait for up
        let counter = Arc::new(AtomicU64::new(0));
        let svc = ForwarderApiService::new(counter.clone());
        let sh = tokio::spawn(async move {
            Server::builder()
                .add_service(ForwardApiServer::new(svc))
                .serve_with_shutdown(a, async {
                    shutdown_rx.await.ok();
                })
                .await
        });
        sleep(Duration::from_millis(10)).await;

        let inner = Channel::from_shared(format!("http://{a}"))
            .expect("valid url")
            .connect()
            .await
            .expect("connection");
        let c = ForwardApiClient::new(inner);
        let w = Worker::new(Keypair::generate().public_key(), c, rx);
        let wh = tokio::spawn(w.go());

        // shutdown server
        shutdown_tx.send(()).ok();
        sh.abort();
        sleep(Duration::from_millis(10)).await;

        // we should fail, server is down
        let max = 3;
        for i in 0..max {
            let incl = InclusionList {
                round: i,
                consensus_timestamp: i,
                encoded_txns: Vec::new(),
                delayed_messages_read: 0,
            };
            tx.send(incl).await.expect("inclusion to be sent");
            sleep(Duration::from_millis(10)).await;
            assert_eq!(tx.capacity(), cap - i as usize);
            assert_eq!(0, counter.load(Ordering::Relaxed));
        }

        // restart server
        let svc = ForwarderApiService::new(counter.clone());
        let sh = tokio::spawn(
            Server::builder()
                .add_service(ForwardApiServer::new(svc))
                .serve(a),
        );

        let incl = InclusionList {
            round: max,
            encoded_txns: Vec::new(),
            consensus_timestamp: max,
            delayed_messages_read: 0,
        };
        tx.send(incl).await.expect("inclusion to be sent");
        let f = async {
            loop {
                let c = counter.load(Ordering::Relaxed);
                if c == max + 1 {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        };
        // wait for processing to be complete
        timeout(Duration::from_secs(1), f)
            .await
            .expect("data to be processed");
        // all data should be processed from channel, back to max cap
        assert_eq!(tx.capacity(), cap);
        assert_eq!(max, counter.load(Ordering::Relaxed) - 1);
        sh.abort();
        wh.abort();
    }
}

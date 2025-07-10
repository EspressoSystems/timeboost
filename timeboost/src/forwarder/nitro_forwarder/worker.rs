use multisig::PublicKey;
use timeboost_proto::{forward::forward_api_client::ForwardApiClient, inclusion::InclusionList};
use tokio::sync::mpsc::Receiver;
use tonic::{Request, transport::Channel};
use tracing::{error, warn};

pub struct Worker {
    key: PublicKey,
    client: ForwardApiClient<Channel>,
    incls_rx: Receiver<InclusionList>,
    pending: Option<InclusionList>,
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
            pending: None,
        }
    }

    pub async fn go(mut self) {
        loop {
            if let Some(incl) = self.pending.take() {
                self.send(incl).await;
                continue;
            };
            match self.incls_rx.recv().await {
                Some(d) => {
                    self.send(d).await;
                }
                None => {
                    warn!(node = %self.key, "disconnected inclusion list receiver");
                    break;
                }
            }
        }
    }

    async fn send(&mut self, incl: InclusionList) {
        let req = Request::new(incl.clone());
        if let Err(err) = self.client.submit_inclusion_list(req).await {
            error!(node = %self.key, %err, "failed to forward data to nitro");
            debug_assert!(self.pending.is_none());
            self.pending = Some(incl);
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
    use prost::Message;
    use timeboost_proto::{
        forward::{
            forward_api_client::ForwardApiClient,
            forward_api_server::{ForwardApi, ForwardApiServer},
        },
        inclusion::InclusionList,
    };
    use timeboost_utils::types::logging::init_logging;
    use tokio::{
        sync::mpsc::channel,
        time::{sleep, timeout},
    };
    use tonic::{
        Request, Response, Status,
        transport::{Channel, Server},
    };

    use crate::proto::inclusion as proto;
    use crate::types::Timestamp;

    use super::Worker;

    #[test]
    fn simple_encode_and_decode() {
        let old = proto::Transaction {
            encoded_txn: Vec::new(),
            address: "0x00".as_bytes().to_vec(),
            timestamp: *Timestamp::now(),
        };
        let bytes = old.encode_to_vec();

        let new = proto::Transaction::decode(bytes.as_slice()).unwrap();

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
            req: Request<proto::InclusionList>,
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

        let p = portpicker::pick_unused_port().expect("available port");
        let a = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, p));
        let cap = 10;
        let (tx, rx) = channel(cap);
        let keypair = Keypair::generate();

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
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

        let uri = format!("http://{}", a);
        let inner = Channel::from_shared(uri)
            .expect("valid url")
            .connect()
            .await
            .expect("connection");
        let c = ForwardApiClient::new(inner);
        let w = Worker::new(keypair.public_key(), c, rx);
        let wh = tokio::spawn(w.go());
        shutdown_tx.send(()).ok();
        sh.abort();
        sleep(Duration::from_millis(10)).await;

        // we should fail
        let max = 3;
        for i in 0..max {
            let incl = InclusionList {
                round: i,
                consensus_timestamp: i,
                encoded_txns: Vec::new(),
                delayed_messages_read: 0,
            };
            let r = tx.send(incl).await;
            assert!(r.is_ok());
            sleep(Duration::from_millis(20)).await;
            assert_eq!(tx.capacity(), cap - i as usize);
        }

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
        let r = tx.send(incl).await;
        assert!(r.is_ok());
        let f = async {
            loop {
                let count = counter.load(Ordering::Relaxed);
                if count == max + 1 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        // wait for processing to be complete or timeout
        let r = timeout(Duration::from_secs(1), f).await;
        assert!(r.is_ok());
        // all data should be processed from channel, back to max cap
        assert_eq!(tx.capacity(), cap);
        assert_eq!(max, counter.load(Ordering::Relaxed) - 1);
        sh.abort();
        wh.abort();
    }
}

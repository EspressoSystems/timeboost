use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use multisig::PublicKey;
use prost::Message;
use quick_cache::sync::Cache;
use sailfish::types::RoundNumber;
use timeboost::config::CommitteeConfig;
use timeboost::proto::block::Block;
use timeboost::proto::forward::forward_api_server::{ForwardApi, ForwardApiServer};
use timeboost::proto::inclusion::InclusionList;
use timeboost::proto::internal::internal_api_client::InternalApiClient;
use timeboost_utils::types::logging::init_logging;
use tokio::sync::Mutex;
use tonic::metadata::AsciiMetadataValue;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Response, Status};
use tracing::error;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    bind: SocketAddr,

    #[clap(long, short)]
    committee: PathBuf,

    #[clap(long, short)]
    max_nodes: usize,

    #[clap(long, default_value_t = 10_000)]
    capacity: usize,
}

/// GRPC service that accepts inclusion lists and broadcasts them to clients.
struct Service {
    next_block: AtomicU64,
    cache: Cache<RoundNumber, (Bytes, u64)>,
    clients: HashMap<AsciiMetadataValue, Mutex<InternalApiClient<Channel>>>,
}

impl Service {
    fn new() -> Self {
        Self {
            next_block: AtomicU64::new(1),
            cache: Cache::new(20_000),
            clients: HashMap::new(),
        }
    }

    fn register(&mut self, key: PublicKey, to: Uri) {
        let client = InternalApiClient::new(Endpoint::from(to.clone()).connect_lazy());
        let mut k = key.to_string();
        k.retain(|c| c.is_ascii());
        let ascii = AsciiMetadataValue::try_from(k).expect("`k` is valid ASCII string");
        self.clients.insert(ascii, Mutex::new(client));
    }

    async fn serve(self, addr: SocketAddr) -> Result<()> {
        tonic::transport::Server::builder()
            .add_service(ForwardApiServer::new(self))
            .serve(addr)
            .await
            .map_err(From::from)
    }
}

#[tonic::async_trait]
impl ForwardApi for Service {
    async fn submit_inclusion_list(
        &self,
        r: Request<InclusionList>,
    ) -> Result<Response<()>, Status> {
        let Some(sender) = r.metadata().get("src") else {
            error!("missing 'src' metadata");
            exit(1)
        };
        let round = RoundNumber::from(r.get_ref().round);
        let bytes = Bytes::from(r.get_ref().encode_to_vec());
        let (prev, bnum) = self
            .cache
            .get_or_insert_with(&round, || -> Result<_, Infallible> {
                Ok((
                    bytes.clone(),
                    self.next_block.fetch_add(1, Ordering::Relaxed),
                ))
            })
            .expect("infallible insert");
        if bytes != prev {
            error!(%round, "inclusion list mismatch");
            exit(1)
        }
        let block = Block {
            number: bnum,
            round: *round,
            payload: bytes,
        };
        let Some(client) = self.clients.get(sender) else {
            error!("unknown sender {sender:?}");
            exit(1)
        };
        let mut c = client.lock().await;
        if let Err(err) = c.submit_block(block).await {
            error!(%err, "failed to send block to {sender:?}");
            exit(1)
        }
        Ok(Response::new(()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let args = Args::parse();
    let mut committee = CommitteeConfig::read(&args.committee).await?;
    committee.members.truncate(args.max_nodes);
    let mut srv = Service::new();
    for member in committee.members {
        let uri: Uri = format!("http://{}", member.internal_api).parse()?;
        srv.register(member.signing_key, uri)
    }
    srv.serve(args.bind).await
}

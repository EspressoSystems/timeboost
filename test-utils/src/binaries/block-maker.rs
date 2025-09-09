use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use bytes::Bytes;
use clap::Parser;
use prost::Message;
use quick_cache::sync::Cache;
use timeboost_config::CommitteeConfig;
use timeboost_proto::block::Block;
use timeboost_proto::forward::forward_api_server::{ForwardApi, ForwardApiServer};
use timeboost_proto::inclusion::InclusionList;
use timeboost_proto::internal::internal_api_client::InternalApiClient;
use timeboost_utils::types::logging::init_logging;
use tokio::spawn;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tonic::transport::{Endpoint, Uri};
use tonic::{Request, Response, Status};
use tracing::error;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short)]
    port: u16,

    #[clap(long, short)]
    committee: PathBuf,

    #[clap(long, default_value_t = 10_000)]
    capacity: usize,
}

/// GRPC service that accepts inclusion lists and broadcasts them to clients.
struct Service {
    next_block: AtomicU64,
    cache: Cache<Bytes, u64>,
    output: broadcast::Sender<Block>,
}

impl Service {
    fn new(tx: broadcast::Sender<Block>) -> Self {
        Self {
            next_block: AtomicU64::new(1),
            cache: Cache::new(20_000),
            output: tx,
        }
    }

    async fn serve(self, port: u16) -> Result<()> {
        tonic::transport::Server::builder()
            .add_service(ForwardApiServer::new(self))
            .serve((Ipv4Addr::UNSPECIFIED, port).into())
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
        let list = r.into_inner();
        let bytes = Bytes::from(list.encode_to_vec());
        let bnum = self
            .cache
            .get_or_insert_with(&bytes, || -> Result<u64, Infallible> {
                Ok(self.next_block.fetch_add(1, Ordering::Relaxed))
            })
            .expect("infallible insert");
        let block = Block {
            number: bnum,
            round: list.round,
            payload: bytes,
        };
        if let Err(err) = self.output.send(block) {
            return Err(Status::internal(err.to_string()));
        }
        Ok(Response::new(()))
    }
}

/// Delivers broadcasted blocks to the given endpoint.
async fn deliver(to: Uri, mut rx: broadcast::Receiver<Block>) {
    let mut client = InternalApiClient::new(Endpoint::from(to.clone()).connect_lazy());
    loop {
        match rx.recv().await {
            Ok(b) => {
                if let Err(err) = client.submit_block(b).await {
                    error!(%err, %to, "block-maker could not submit block");
                }
            }
            Err(RecvError::Closed) => break,
            Err(RecvError::Lagged(n)) => {
                error!(%to, %n, "block-maker lagging behind");
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();
    let args = Args::parse();
    let committee = CommitteeConfig::read(&args.committee).await?;
    let (tx, _) = broadcast::channel(args.capacity);
    for member in committee.members {
        let uri: Uri = format!("http://{}", member.internal_api).parse()?;
        spawn(deliver(uri, tx.subscribe()));
    }
    Service::new(tx).serve(args.port).await
}

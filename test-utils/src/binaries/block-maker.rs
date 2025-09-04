use std::collections::HashMap;
use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

use adapters::bytes::BytesWriter;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use clap::Parser;
use minicbor::{Encoder, encode};
use parking_lot::Mutex;
use timeboost_proto::block::Block;
use timeboost_proto::forward::forward_api_server::{ForwardApi, ForwardApiServer};
use timeboost_proto::inclusion::{InclusionList, Transaction};
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

    #[clap(long, short, use_value_delimiter = true, value_delimiter = ',')]
    connect: Vec<Uri>,

    #[clap(long, default_value_t = 16_000)]
    capacity: usize,
}

/// GRPC service that accepts inclusion lists and broadcasts them to clients.
struct Service {
    next_block: AtomicU64,
    cache: Mutex<Cache>,
    output: broadcast::Sender<Block>,
}

#[derive(Default)]
struct Cache {
    // (Round, Part) -> (InclusionList, Block number)
    lists: HashMap<(u64, u8), (InclusionList, u64)>
}

impl Service {
    fn new(tx: broadcast::Sender<Block>) -> Self {
        Self {
            next_block: AtomicU64::new(1),
            cache: Mutex::new(Cache::default()),
            output: tx,
        }
    }

    async fn serve(self, port: u16) -> Result<()> {
        tonic::transport::Server::builder()
            .add_service(ForwardApiServer::new(self))
            .serve((Ipv4Addr::LOCALHOST, port).into())
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
        let Some(part) : Option<u8> = list.part.try_into().ok() else {
            return Err(Status::internal("invalid part number"))
        };
        let bnum = {
            let mut cache = self.cache.lock();
            if let Some((prev, bnum)) = cache.lists.get(&(list.round, part)) {
                if prev != &list {
                    return Err(Status::internal("inclusion list mismatch"))
                }
                *bnum
            } else {
                let bnum = self.next_block.fetch_add(1, Ordering::Relaxed);
                cache.lists.insert((list.round, part), (list.clone(), bnum));
                bnum
            }
        };
        let block = Block {
            number: bnum,
            round: list.round,
            payload: match encode_txs(&list.encoded_txns) {
                Ok(bytes) => bytes,
                Err(err) => return Err(Status::internal(err.to_string())),
            },
        };
        if let Err(err) = self.output.send(block) {
            return Err(Status::internal(err.to_string()));
        }
        Ok(Response::new(()))
    }
}

fn encode_txs(txs: &[Transaction]) -> Result<Bytes, encode::Error<Infallible>> {
    let mut e = Encoder::new(BytesWriter::default());
    e.array(txs.len() as u64)?;
    for t in txs {
        e.bytes(&t.encoded_txn)?;
    }
    Ok(BytesMut::from(e.into_writer()).freeze())
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

    let (tx, _) = broadcast::channel(args.capacity);

    for uri in args.connect {
        spawn(deliver(uri, tx.subscribe()));
    }

    Service::new(tx).serve(args.port).await
}

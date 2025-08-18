use std::io;

use proto::internal::internal_api_server::InternalApi;
use timeboost_builder::{CertifierDown, Handle, Subscriber};
use timeboost_types::{Block, BlockNumber};
use tokio::net::{ToSocketAddrs, lookup_host};
use tonic::{Request, Response, Status};

use timeboost_proto::{self as proto, internal::internal_api_server::InternalApiServer};
use tracing::debug;

pub struct GrpcServer {
    service: InternalApiService,
}

impl GrpcServer {
    pub fn new(block_handler: Handle, confirmations: Subscriber<BlockNumber>) -> Self {
        Self {
            service: InternalApiService {
                block_handler,
                confirmations,
            },
        }
    }

    pub async fn serve<A: ToSocketAddrs>(self, addr: A) -> io::Result<()> {
        let addr = lookup_host(addr)
            .await?
            .next()
            .ok_or_else(|| io::Error::other("can not resolve grpc server address"))?;
        tonic::transport::Server::builder()
            .add_service(InternalApiServer::new(self.service))
            .serve(addr)
            .await
            .map_err(io::Error::other)
    }
}

struct InternalApiService {
    block_handler: Handle,
    confirmations: Subscriber<BlockNumber>,
}

#[tonic::async_trait]
impl InternalApi for InternalApiService {
    async fn submit_block(
        &self,
        r: Request<proto::block::Block>,
    ) -> Result<Response<proto::internal::SubmitReceipt>, Status> {
        let p = r.into_inner();
        let b = Block::new(p.round, p.payload);
        let mut c = self.confirmations.subscribe();
        let receipt = match self.block_handler.enqueue(b).await {
            Ok(num) => loop {
                match c.receive().await {
                    Ok(n) => {
                        if num == n {
                            debug!(round = %p.round, %num, "block has been submitted");
                            break proto::internal::SubmitReceipt {
                                round: p.round,
                                block: num.into(),
                            };
                        }
                    }
                    Err(err) => {
                        if err.is_closed() {
                            return Err(Status::internal("submitter has been terminated"));
                        } else {
                            return Err(Status::internal("error processing confirmations"));
                        }
                    }
                }
            },
            Err(err) => {
                let _: CertifierDown = err;
                return Err(Status::internal("timeboost is shutting down"));
            }
        };
        Ok(Response::new(receipt))
    }
}

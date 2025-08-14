use std::{io, net::SocketAddr};

use proto::internal::internal_api_server::InternalApi;
use timeboost_builder::{CertifierDown, Handle};
use timeboost_types::Block;
use tonic::{Request, Response, Status};

use timeboost_proto::{self as proto, internal::internal_api_server::InternalApiServer};

pub struct GrpcServer {
    service: InternalApiService,
}

impl GrpcServer {
    pub fn new(block_handler: Handle) -> Self {
        Self {
            service: InternalApiService { block_handler },
        }
    }

    pub async fn serve(self, addr: SocketAddr) -> io::Result<()> {
        tonic::transport::Server::builder()
            .add_service(InternalApiServer::new(self.service))
            .serve(addr)
            .await
            .map_err(io::Error::other)
    }
}

struct InternalApiService {
    block_handler: Handle,
}

#[tonic::async_trait]
impl InternalApi for InternalApiService {
    async fn submit_block(&self, r: Request<proto::block::Block>) -> Result<Response<()>, Status> {
        let p = r.into_inner();
        let b = Block::new(p.round, p.payload);
        if let Err(err) = self.block_handler.enqueue(b).await {
            let _: CertifierDown = err;
            return Err(Status::internal("timeboost is shutting down"));
        }
        Ok(Response::new(()))
    }
}

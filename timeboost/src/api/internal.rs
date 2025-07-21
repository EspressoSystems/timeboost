use proto::internal::internal_api_server::InternalApi;
use timeboost_builder::{CertifierDown, Handle};
use timeboost_types::Block;
use tonic::{Request, Response, Status};

use timeboost_proto as proto;

pub struct InternalApiService {
    block_handler: Handle,
}

impl InternalApiService {
    pub fn new(block_handler: Handle) -> Self {
        Self { block_handler }
    }
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

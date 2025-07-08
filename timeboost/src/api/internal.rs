use multisig::PublicKey;
use proto::internal::internal_api_server::InternalApi;
use timeboost_builder::{Handle, ProducerDown};
use timeboost_types::Block;
use tonic::{Request, Response, Status};

use timeboost_proto as proto;
use tracing::warn;

pub struct InternalApiService {
    key: PublicKey,
    block_handler: Handle,
}

impl InternalApiService {
    pub fn new(key: PublicKey, block_handler: Handle) -> Self {
        Self { key, block_handler }
    }
}

#[tonic::async_trait]
impl InternalApi for InternalApiService {
    async fn submit_block(&self, r: Request<proto::block::Block>) -> Result<Response<()>, Status> {
        match Block::try_from(r.into_inner()) {
            Ok(b) => {
                if let Err(err) = self.block_handler.enqueue(b).await {
                    let _: ProducerDown = err;
                    return Err(Status::internal("timeboost is shutting down"));
                }
                Ok(Response::new(()))
            }
            Err(err) => {
                warn!(node = %self.key, %err, "invalid timeboost block");
                Err(Status::invalid_argument("invalid timeboost block"))
            }
        }
    }
}

use std::time::Duration;

use alloy_primitives::{Address, U256};
use alloy_provider::{Provider, RootProvider, network::Ethereum};
use alloy_rpc_types::{BlockId, BlockNumberOrTag, Filter};
use alloy_sol_types::{SolEvent, sol};
use tokio::time::sleep;

use crate::queue::BundleQueue;

sol! {
    event InboxMessageDelivered(uint256 indexed messageNum, bytes data);
}

pub struct DelayedMessages {
    address: Address,
    provider: RootProvider<Ethereum>,
    queue: BundleQueue,
}

impl DelayedMessages {
    pub async fn connect(url: &str, address: Address, queue: BundleQueue) -> Result<Self, Error> {
        let provider = RootProvider::<Ethereum>::connect(url)
            .await
            .map_err(|e| Error::RpcError(e.to_string()))?;
        Ok(Self {
            address,
            provider,
            queue,
        })
    }

    pub async fn go(self) {
        let mut from_block = 0;
        let mut last_finalized = 0;
        loop {
            if let Ok(Some(b)) = self
                .provider
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            {
                let finalized = b.header.number;
                if finalized == last_finalized {
                    continue;
                }
                if from_block == 0 {
                    from_block = finalized.saturating_sub(300);
                }

                let filter = Filter::new()
                    .address(self.address)
                    .from_block(from_block)
                    .to_block(finalized)
                    .event_signature(*InboxMessageDelivered::SIGNATURE_HASH);

                if let Ok(mut logs) = self.provider.get_logs(&filter).await {
                    logs.sort_by(|a, b| {
                        b.block_number
                            .cmp(&a.block_number)
                            .then(b.log_index.cmp(&a.log_index))
                    });
                    if let Some(latest) = logs.first() {
                        let msg_num = latest.topics().get(1).unwrap();

                        let delayed_index: u64 = U256::from_be_bytes(msg_num.0).try_into().unwrap();
                        last_finalized = finalized;
                        tracing::error!("last finalized: {}", last_finalized);
                        self.queue.set_delayed_inbox_index(delayed_index.into());
                    }
                }
            }
            sleep(Duration::from_secs(20)).await;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid uri: {0}")]
    RpcError(String),
}

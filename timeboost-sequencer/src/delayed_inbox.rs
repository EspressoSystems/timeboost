use std::time::Duration;

use alloy::consensus::BlockHeader;
use alloy::network::Ethereum;
use alloy::primitives::{Address, U256};
use alloy::providers::fillers::FillProvider;
use alloy::providers::utils::JoinedRecommendedFillers;
use alloy::providers::{Provider, network::BlockResponse};
use alloy::providers::{ProviderBuilder, RootProvider};
use alloy::rpc::types::{BlockId, BlockNumberOrTag, Filter};
use alloy::sol;
use alloy::sol_types::SolEvent;
use multisig::PublicKey;
use timeboost_config::ChainConfig;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::queue::BundleQueue;

// Polling interval to check for next delayed inbox index
const INBOX_DELAY: Duration = Duration::from_secs(10);

// Max lookback for `from_block` to `to_block` in our `Filter` request
const MAX_BLOCK_LOOKBACK: u64 = 10000;

sol! {
    event InboxMessageDelivered(uint256 indexed messageNum, bytes data);
    event InboxMessageDeliveredFromOrigin(uint256 indexed messageNum);
}

type HttpProvider = FillProvider<JoinedRecommendedFillers, RootProvider, Ethereum>;

pub struct DelayedInbox {
    node: PublicKey,
    ibox_addr: Address,
    provider: HttpProvider,
    queue: BundleQueue,
    url: String,
    tag: BlockNumberOrTag,
}

impl DelayedInbox {
    pub async fn connect(
        node: PublicKey,
        cfg: &ChainConfig,
        queue: BundleQueue,
    ) -> Result<Self, Error> {
        let url = &cfg.rpc_url;
        let parent_chain_id = cfg.id;
        let provider = ProviderBuilder::new().connect_http(url.clone());
        let rpc_chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| Error::RpcError(e.to_string()))?;
        if cfg.id != rpc_chain_id {
            error!(%parent_chain_id, %rpc_chain_id, "mismatching chain id");
            return Err(Error::MismatchingChainID(parent_chain_id, rpc_chain_id));
        }
        Ok(Self {
            node,
            ibox_addr: cfg.inbox_contract,
            provider,
            queue,
            url: url.to_string(),
            tag: BlockNumberOrTag::Finalized,
        })
    }

    pub async fn go(self) {
        let mut prev_block = 0;
        // The first delayed message index will be 0, so initialize with `u64::Max` instead
        let mut prev_delayed_idx = u64::MAX;
        let events = vec![
            InboxMessageDelivered::SIGNATURE,
            InboxMessageDeliveredFromOrigin::SIGNATURE,
        ];
        loop {
            // First get latest finalized block on L1
            if let Ok(Some(b)) = self.provider.get_block(BlockId::Number(self.tag)).await {
                let block_num = b.header().number();
                if block_num == prev_block {
                    // Nothing to do
                    sleep(INBOX_DELAY).await;
                    continue;
                }
                // To prevent large rpc queries go from finalized - MAX_BLOCK_LOOKBACK
                // This is fine because we only need the latest finalized delayed message to set the
                // index
                if block_num.saturating_sub(prev_block) > MAX_BLOCK_LOOKBACK {
                    prev_block = block_num.saturating_sub(MAX_BLOCK_LOOKBACK);
                }

                // Filter for the `InboxMessageDelivered` and `InboxMessageDeliveredFromOrigin`
                // between our last finalized and current finalized on the L1 contract
                let filter = Filter::new()
                    .address(self.ibox_addr)
                    .from_block(prev_block)
                    .to_block(block_num)
                    .events(&events);
                prev_block = block_num;

                if let Ok(mut logs) = self.provider.get_logs(&filter).await {
                    // Make sure event logs are in order, we need highest block number first then
                    // latest log
                    logs.sort_by(|a, b| {
                        b.block_number
                            .cmp(&a.block_number)
                            .then(b.log_index.cmp(&a.log_index))
                    });
                    if let Some((Some(tx_hash), Some(index))) = logs
                        .first()
                        .map(|log| (log.transaction_hash, log.topics().get(1)))
                    {
                        // Update delayed index if newer
                        let delayed_idx = U256::from_be_bytes(index.0)
                            .try_into()
                            .expect("valid msg number");
                        if delayed_idx != prev_delayed_idx {
                            info!(node = %self.node, %delayed_idx, %block_num, tag = %self.tag, ibox_addr = %self.ibox_addr, %tx_hash, "delayed index updated");
                            prev_delayed_idx = delayed_idx;
                            self.queue.set_delayed_inbox_index(delayed_idx.into());
                        }
                    }
                }
            } else {
                warn!(node = %self.node, ibox_addr = %self.ibox_addr, url = %self.url, "failed to get latest finalized block");
            }
            sleep(INBOX_DELAY).await;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rpc err: {0}")]
    RpcError(String),
    #[error("mismatching chain id: {0} != {1}")]
    MismatchingChainID(u64, u64),
}

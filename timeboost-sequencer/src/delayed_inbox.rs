use std::time::Duration;

use alloy_consensus::BlockHeader;
use alloy_primitives::{Address, U256};
use alloy_provider::{Network, Provider, RootProvider, network::BlockResponse};
use alloy_rpc_types::{BlockId, BlockNumberOrTag, Filter};
use alloy_sol_types::{SolEvent, sol};
use multisig::PublicKey;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::queue::BundleQueue;

// Polling interval to check for next delayed inbox index
const INBOX_DELAY: Duration = Duration::from_secs(60);

// Max lookback for `from_block` to `to_block` in our `Filter` request
const MAX_BLOCK_LOOKBACK: u64 = 300;

sol! {
    event InboxMessageDelivered(uint256 indexed messageNum, bytes data);
    event InboxMessageDeliveredFromOrigin(uint256 indexed messageNum);
}

pub struct DelayedInbox<N: Network> {
    node: PublicKey,
    ibox_addr: Address,
    provider: RootProvider<N>,
    queue: BundleQueue,
    url: String,
}

impl<N: Network> DelayedInbox<N> {
    pub async fn connect(
        node: PublicKey,
        url: &str,
        ibox_addr: Address,
        parent_chain_id: u64,
        queue: BundleQueue,
    ) -> Result<Self, Error> {
        let provider = RootProvider::<N>::connect(url)
            .await
            .map_err(|e| Error::RpcError(e.to_string()))?;
        let rpc_chain_id = provider
            .get_chain_id()
            .await
            .map_err(|e| Error::RpcError(e.to_string()))?;
        if parent_chain_id != rpc_chain_id {
            error!(%parent_chain_id, %rpc_chain_id, "mismatching chain id");
            return Err(Error::MismatchingChainID(parent_chain_id, rpc_chain_id));
        }
        Ok(Self {
            node,
            ibox_addr,
            provider,
            queue,
            url: url.to_string(),
        })
    }

    pub async fn go(self) {
        let mut prev_finalized = 0;
        let mut prev_delayed_idx = 0;
        let events = vec![
            InboxMessageDelivered::SIGNATURE,
            InboxMessageDeliveredFromOrigin::SIGNATURE,
        ];
        loop {
            // First get latest finalized block on L1
            if let Ok(Some(b)) = self
                .provider
                .get_block(BlockId::Number(BlockNumberOrTag::Finalized))
                .await
            {
                let finalized = b.header().number();
                if finalized == prev_finalized {
                    // Nothing to do
                    sleep(INBOX_DELAY).await;
                    continue;
                }
                // To prevent large rpc queries go from finalized - MAX_BLOCK_LOOKBACK
                // This is fine because we only need the latest finalized delayed message to set the
                // index
                if finalized.saturating_sub(prev_finalized) > MAX_BLOCK_LOOKBACK {
                    prev_finalized = finalized.saturating_sub(MAX_BLOCK_LOOKBACK);
                }

                // Filter for the `InboxMessageDelivered` and `InboxMessageDeliveredFromOrigin`
                // between our last finalized and current finalized on the L1 contract
                let filter = Filter::new()
                    .address(self.ibox_addr)
                    .from_block(prev_finalized)
                    .to_block(finalized)
                    .events(&events);
                prev_finalized = finalized;

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
                            debug_assert!(delayed_idx > prev_delayed_idx);
                            info!(node = %self.node, %delayed_idx, parent_finalized_block = %finalized, ibox_addr = %self.ibox_addr, %tx_hash, "delayed index updated");
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

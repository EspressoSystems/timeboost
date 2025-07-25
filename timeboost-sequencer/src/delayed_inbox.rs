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

const INBOX_DELAY: Duration = Duration::from_secs(60);

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
        url: String,
        ibox_addr: Address,
        parent_chain_id: u64,
        queue: BundleQueue,
    ) -> Result<Self, Error> {
        let provider = RootProvider::<N>::connect(&url)
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
            url,
        })
    }

    pub async fn go(self) {
        let mut last_finalized = 0;
        let mut last_delayed_index = 0;
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
                if finalized == last_finalized {
                    sleep(INBOX_DELAY).await;
                    continue;
                }
                if last_finalized == 0 {
                    last_finalized = finalized.saturating_sub(300);
                }

                // Filter for the `InboxMessageDelivered` and `InboxMessageDeliveredFromOrigin`
                // between our last finalized and current finalized on the L1 contract
                let filter = Filter::new()
                    .address(self.ibox_addr)
                    .from_block(last_finalized)
                    .to_block(finalized)
                    .events(&events);
                last_finalized = finalized;

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
                        let delayed_index = U256::from_be_bytes(index.0)
                            .try_into()
                            .expect("valid msg number");
                        if delayed_index != last_delayed_index {
                            debug_assert!(delayed_index > last_delayed_index);
                            info!(node = %self.node, %delayed_index, parent_finalized_block = %finalized, ibox_addr = %self.ibox_addr, %tx_hash, "delayed index updated");
                            last_delayed_index = delayed_index;
                            self.queue.set_delayed_inbox_index(delayed_index.into());
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

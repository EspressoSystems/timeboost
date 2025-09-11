//! Event monitoring for contract events that trigger committee transitions
use std::time::Duration;

use alloy::{primitives::Address, providers::Provider, rpc::types::BlockNumberOrTag};
use anyhow::Result;
use timeboost_contract::KeyManagerEventMonitor;
use tokio::time::sleep;
use tracing::{error, info};
use std::sync::Arc;

use crate::conf::EventMonitoringConfig;

/// Event monitor that watches for contract events and triggers committee transitions
pub struct EventMonitor<P> {
    provider: P,
    contract_addr: Address,
    config: EventMonitoringConfig,
}

impl<P: Provider + Clone + Send + Sync + 'static> EventMonitor<P> {
    pub fn new(provider: P, contract_addr: Address, config: EventMonitoringConfig) -> Self {
        Self {
            provider,
            contract_addr,
            config,
        }
    }

    /// Start monitoring contract events in the background
    pub async fn start_monitoring(self) -> Result<()> {
        if !self.config.enabled {
            info!("Event monitoring is disabled");
            return Ok(());
        }

        let monitor_task = tokio::spawn(async move {
            if let Err(e) = self.monitor_events().await {
                error!("Event monitoring failed: {}", e);
            }
        });

        if let Err(e) = monitor_task.await {
            error!("Event monitor task panicked: {}", e);
        }

        Ok(())
    }

    /// Monitor contract events and send them to the processing channel
    async fn monitor_events(self) -> Result<()> {
        let event_monitor = KeyManagerEventMonitor::new(Arc::new(self.provider.clone()), self.contract_addr);
        let mut last_processed_block = None;
        let start_block_number = self.config.start_block_number;
        loop {
            match self.get_latest_block_number().await {
                Ok(latest_block) => {
                    let from_block = if let Some(last_block) = last_processed_block {
                        BlockNumberOrTag::Number(last_block + 1)
                    } else {
                        BlockNumberOrTag::Number(start_block_number)
                    };

                    // Get committee created events since last check
                    match event_monitor
                        .get_committee_created_events(from_block, BlockNumberOrTag::Latest)
                        .await
                    {
                        Ok(events) => {
                            for event in events {
                                info!(
                                    committee_id = event.id,
                                    "New committee created event detected"
                                );

                                // TODO: process event
                            }

                            last_processed_block = Some(latest_block);
                        }
                        Err(e) => {
                            error!("Failed to get committee created events: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to get latest block number: {}", e);
                }
            }

            // Wait before next poll
            sleep(Duration::from_secs(self.config.poll_interval_seconds)).await;
        }
    }

    /// Get the latest block number from the provider
    async fn get_latest_block_number(&self) -> Result<u64> {
        self.provider
            .get_block_number()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get latest block number: {}", e))
    }
}

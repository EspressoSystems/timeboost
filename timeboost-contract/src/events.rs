//! Event monitoring and filtering for KeyManager contract
use crate::bindings::keymanager::KeyManager;
use alloy::{
    primitives::Address,
    providers::Provider,
    rpc::types::{BlockNumberOrTag, Filter},
    sol_types::SolEvent,
};
use anyhow::Result;
use std::sync::Arc;

pub struct KeyManagerEventMonitor<P> {
    provider: Arc<P>,
    contract_addr: Address,
}

impl<P: Provider> KeyManagerEventMonitor<P> {
    pub fn new(provider: Arc<P>, contract_addr: Address) -> Self {
        Self {
            provider,
            contract_addr,
        }
    }

    pub async fn get_committee_created_events(
        &self,
        from_block: BlockNumberOrTag,
        to_block: BlockNumberOrTag,
    ) -> Result<Vec<KeyManager::CommitteeCreated>> {
        let filter = Filter::new()
            .address(self.contract_addr)
            .from_block(from_block)
            .to_block(to_block)
            .event(KeyManager::CommitteeCreated::SIGNATURE);

        let logs = self.provider.get_logs(&filter).await?;
        let events = logs
            .into_iter()
            .filter_map(|log| {
                KeyManager::CommitteeCreated::decode_log(&log.into())
                    .ok()
                    .map(|decoded_log| decoded_log.data)
            })
            .collect();

        Ok(events)
    }

    pub async fn get_threshold_encryption_key_updated_events(
        &self,
        from_block: BlockNumberOrTag,
        to_block: BlockNumberOrTag,
    ) -> Result<Vec<KeyManager::ThresholdEncryptionKeyUpdated>> {
        let filter = Filter::new()
            .address(self.contract_addr)
            .from_block(from_block)
            .to_block(to_block)
            .event(KeyManager::ThresholdEncryptionKeyUpdated::SIGNATURE);

        let logs = self.provider.get_logs(&filter).await?;
        let events = logs
            .into_iter()
            .filter_map(|log| {
                KeyManager::ThresholdEncryptionKeyUpdated::decode_log(&log.into())
                    .ok()
                    .map(|decoded_log| decoded_log.data)
            })
            .collect();

        Ok(events)
    }

    pub async fn get_manager_changed_events(
        &self,
        from_block: BlockNumberOrTag,
        to_block: BlockNumberOrTag,
    ) -> Result<Vec<KeyManager::ManagerChanged>> {
        let filter = Filter::new()
            .address(self.contract_addr)
            .from_block(from_block)
            .to_block(to_block)
            .event(KeyManager::ManagerChanged::SIGNATURE);

        let logs = self.provider.get_logs(&filter).await?;
        let events = logs
            .into_iter()
            .filter_map(|log| {
                KeyManager::ManagerChanged::decode_log(&log.into())
                    .ok()
                    .map(|decoded_log| decoded_log.data)
            })
            .collect();

        Ok(events)
    }

    pub async fn get_committees_pruned_events(
        &self,
        from_block: BlockNumberOrTag,
        to_block: BlockNumberOrTag,
    ) -> Result<Vec<KeyManager::CommitteesPruned>> {
        let filter = Filter::new()
            .address(self.contract_addr)
            .from_block(from_block)
            .to_block(to_block)
            .event(KeyManager::CommitteesPruned::SIGNATURE);

        let logs = self.provider.get_logs(&filter).await?;
        let events = logs
            .into_iter()
            .filter_map(|log| {
                KeyManager::CommitteesPruned::decode_log(&log.into())
                    .ok()
                    .map(|decoded_log| decoded_log.data)
            })
            .collect();

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitteeMemberSol, KeyManager};
    use alloy::{primitives::Address, providers::WalletProvider, rpc::types::BlockNumberOrTag};
    use rand::prelude::*;

    #[tokio::test]
    async fn test_committee_created_event_monitoring() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider_arc = Arc::new(provider);
        let _manager = provider_arc.default_signer_address();

        // create event monitor & get initial block number
        let initial_block = provider_arc.get_block_number().await.unwrap();
        let contract = KeyManager::new(contract_addr, &provider_arc);
        let monitor = KeyManagerEventMonitor::new(provider_arc.clone(), contract_addr);

        // create a committee to trigger CommitteeCreated event
        let rng = &mut rand::rng();
        let members = (0..3)
            .map(|_| CommitteeMemberSol::random())
            .collect::<Vec<_>>();
        let timestamp = rng.random::<u64>();

        // set next committee to trigger CommitteeCreated event
        let _tx_receipt = contract
            .setNextCommittee(timestamp, members.clone())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // query for CommitteeCreated events
        let final_block = provider_arc.get_block_number().await.unwrap();
        let events = monitor
            .get_committee_created_events(
                BlockNumberOrTag::Number(initial_block),
                BlockNumberOrTag::Number(final_block),
            )
            .await
            .unwrap();

        // verify we got the event
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.id, 0); // first committee should have id 0
    }

    #[tokio::test]
    async fn test_threshold_encryption_key_updated_event_monitoring() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider_arc = Arc::new(provider);
        let initial_block = provider_arc.get_block_number().await.unwrap();

        let contract = KeyManager::new(contract_addr, &provider_arc);

        // create event monitor and get initial block number
        let monitor = KeyManagerEventMonitor::new(provider_arc.clone(), contract_addr);

        // set threshold encryption key to trigger ThresholdEncryptionKeyUpdated event
        let test_key = b"test_threshold_encryption_key_32_bytes!".to_vec();
        let _tx_receipt = contract
            .setThresholdEncryptionKey(test_key.clone().into())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // query for ThresholdEncryptionKeyUpdated events
        let final_block = provider_arc.get_block_number().await.unwrap();
        let events = monitor
            .get_threshold_encryption_key_updated_events(
                BlockNumberOrTag::Number(initial_block),
                BlockNumberOrTag::Number(final_block),
            )
            .await
            .unwrap();

        // verify we got the event
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.thresholdEncryptionKey, test_key);
    }

    #[tokio::test]
    async fn test_manager_changed_event_monitoring() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider_arc = Arc::new(provider);
        let contract = KeyManager::new(contract_addr, &provider_arc);

        let manager = provider_arc.default_signer_address();

        // create event monitor
        let monitor = KeyManagerEventMonitor::new(provider_arc.clone(), contract_addr);

        // get initial block number
        let initial_block = provider_arc.get_block_number().await.unwrap();

        // create a new manager address
        let new_manager = Address::random();

        // change manager to trigger ManagerChanged event
        let _tx_receipt = contract
            .setManager(new_manager)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // get the block number after the transaction
        let final_block = provider_arc.get_block_number().await.unwrap();

        // query for ManagerChanged events
        let events = monitor
            .get_manager_changed_events(
                BlockNumberOrTag::Number(initial_block),
                BlockNumberOrTag::Number(final_block),
            )
            .await
            .unwrap();

        // verify we got the event
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.oldManager, manager);
        assert_eq!(event.newManager, new_manager);
    }

    #[tokio::test]
    async fn test_no_events_in_empty_range() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();

        // create event monitor
        let monitor = KeyManagerEventMonitor::new(Arc::new(provider), contract_addr);

        // query for events in a range where no events occurred
        let events = monitor
            .get_committee_created_events(BlockNumberOrTag::Number(0), BlockNumberOrTag::Number(0))
            .await
            .unwrap();

        // verify we got no events
        assert_eq!(events.len(), 0);
    }

    #[tokio::test]
    async fn test_multiple_events_monitoring() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider_arc = Arc::new(provider);
        let contract = KeyManager::new(contract_addr, &provider_arc);

        // create event monitor
        let monitor = KeyManagerEventMonitor::new(provider_arc.clone(), contract_addr);

        // get initial block number
        let initial_block = provider_arc.get_block_number().await.unwrap();

        // create multiple committees to trigger multiple CommitteeCreated events
        let rng = &mut rand::rng();
        let base_timestamp = rng.random::<u64>();
        for i in 0..3 {
            let members = (0..2)
                .map(|_| CommitteeMemberSol::random())
                .collect::<Vec<_>>();
            // ensure timestamps are far enough apart to avoid validation errors
            let timestamp = base_timestamp + (i as u64 * 1000);

            contract
                .setNextCommittee(timestamp, members)
                .send()
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap();
        }

        // get the final block number
        let final_block = provider_arc.get_block_number().await.unwrap();

        // query for all CommitteeCreated events
        let events = monitor
            .get_committee_created_events(
                BlockNumberOrTag::Number(initial_block),
                BlockNumberOrTag::Number(final_block),
            )
            .await
            .unwrap();

        // verify we got all 3 events
        assert_eq!(events.len(), 3);

        // verify the committee IDs are sequential
        let mut committee_ids: Vec<u64> = events.iter().map(|e| e.id).collect();
        committee_ids.sort();
        assert_eq!(committee_ids, vec![0, 1, 2]);
    }
}

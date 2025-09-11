//! Committee management and querying utilities
use crate::bindings::keymanager::KeyManager;
use alloy::{primitives::Address, providers::Provider};
use anyhow::Result;
use std::sync::Arc;

pub struct CommitteeManager<P> {
    provider: Arc<P>,
    contract_addr: Address,
}

impl<P: Provider> CommitteeManager<P> {
    pub fn new(provider: Arc<P>, contract_addr: Address) -> Self {
        Self {
            provider,
            contract_addr,
        }
    }

    pub async fn get_committees_for_startup(
        &self,
        current_id: u64,
        previous_id: Option<u64>,
    ) -> Result<(KeyManager::Committee, Option<KeyManager::Committee>)> {
        let contract = KeyManager::new(self.contract_addr, &self.provider);

        let current = contract.getCommitteeById(current_id).call().await?;
        let previous = if let Some(prev_id) = previous_id {
            Some(contract.getCommitteeById(prev_id).call().await?)
        } else {
            None
        };

        Ok((current, previous))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitteeMemberSol, KeyManager};
    use rand::prelude::*;

    #[tokio::test]
    async fn test_get_committees_for_startup_current_only() {
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider = Arc::new(provider);
        let contract = KeyManager::new(contract_addr, &provider);

        let manager = CommitteeManager::new(provider.clone(), contract_addr);

        let rng = &mut rand::rng();
        let members = (0..3)
            .map(|_| CommitteeMemberSol::random())
            .collect::<Vec<_>>();
        let timestamp = rng.random::<u64>();

        // create the committee
        contract
            .setNextCommittee(timestamp, members.clone())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        let (current, previous) = manager.get_committees_for_startup(0, None).await.unwrap();

        // verify current committee
        assert_eq!(current.id, 0);
        assert_eq!(current.effectiveTimestamp, timestamp);
        assert_eq!(current.members.len(), 3);

        // verify no previous committee
        assert!(previous.is_none());
    }

    #[tokio::test]
    async fn test_get_committees_for_startup_with_previous() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider = Arc::new(provider);
        let contract = KeyManager::new(contract_addr, &provider);

        let manager = CommitteeManager::new(provider.clone(), contract_addr);

        let rng = &mut rand::rng();
        let first_members = (0..2)
            .map(|_| CommitteeMemberSol::random())
            .collect::<Vec<_>>();
        let first_timestamp = rng.random::<u64>();

        contract
            .setNextCommittee(first_timestamp, first_members.clone())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // create second committee (will be current)
        let second_members = (0..3)
            .map(|_| CommitteeMemberSol::random())
            .collect::<Vec<_>>();
        let second_timestamp = first_timestamp + 1000; // Ensure different timestamp

        contract
            .setNextCommittee(second_timestamp, second_members.clone())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // test getting both current and previous committees
        let (current, previous) = manager
            .get_committees_for_startup(1, Some(0))
            .await
            .unwrap();

        // verify current committee (id=1)
        assert_eq!(current.id, 1);
        assert_eq!(current.effectiveTimestamp, second_timestamp);
        assert_eq!(current.members.len(), 3);

        // verify previous committee (id=0)
        assert!(previous.is_some());
        let prev = previous.unwrap();
        assert_eq!(prev.id, 0);
        assert_eq!(prev.effectiveTimestamp, first_timestamp);
        assert_eq!(prev.members.len(), 2);
    }

    #[tokio::test]
    async fn test_get_committees_for_startup_nonexistent_committee() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();

        let manager = CommitteeManager::new(Arc::new(provider), contract_addr);

        let result = manager.get_committees_for_startup(999, None).await;

        // should return an error
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_committees_for_startup_nonexistent_previous() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider = Arc::new(provider);
        let contract = KeyManager::new(contract_addr, &provider);

        let manager = CommitteeManager::new(provider.clone(), contract_addr);

        let rng = &mut rand::rng();
        let members = (0..2)
            .map(|_| CommitteeMemberSol::random())
            .collect::<Vec<_>>();
        let timestamp = rng.random::<u64>();

        contract
            .setNextCommittee(timestamp, members)
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // try to get current committee with non-existent previous
        let result = manager.get_committees_for_startup(0, Some(999)).await;

        // should return an error because previous committee doesn't exist
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_committees_for_startup_multiple_committees() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let provider = Arc::new(provider);
        let contract = KeyManager::new(contract_addr, &provider);

        let manager = CommitteeManager::new(provider.clone(), contract_addr);

        // create multiple committees
        let rng = &mut rand::rng();
        let base_timestamp = rng.random::<u64>();

        for i in 0..5 {
            let members = (0..2)
                .map(|_| CommitteeMemberSol::random())
                .collect::<Vec<_>>();
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

        // test getting committee 3 with previous committee 2
        let (current, previous) = manager
            .get_committees_for_startup(3, Some(2))
            .await
            .unwrap();

        // verify current committee (id=3)
        assert_eq!(current.id, 3);
        assert_eq!(current.effectiveTimestamp, base_timestamp + 3000);
        assert_eq!(current.members.len(), 2);

        // verify previous committee (id=2)
        assert!(previous.is_some());
        let prev = previous.unwrap();
        assert_eq!(prev.id, 2);
        assert_eq!(prev.effectiveTimestamp, base_timestamp + 2000);
        assert_eq!(prev.members.len(), 2);
    }

    #[tokio::test]
    async fn test_committee_manager_creation() {
        // setup test chain and deploy contract
        let (provider, contract_addr) = crate::init_test_chain().await.unwrap();
        let manager = CommitteeManager::new(Arc::new(provider), contract_addr);

        // manager should be created successfully
        assert_eq!(manager.contract_addr, contract_addr);
    }
}

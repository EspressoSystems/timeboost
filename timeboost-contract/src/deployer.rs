//! Helper logic for contract deployment

use alloy::{contract::RawCallBuilder, primitives::Address, providers::Provider};

use crate::{ERC1967Proxy, KeyManager};

type ContractResult<T> = Result<T, alloy::contract::Error>;

/// Deploy a contract (with logging)
pub(crate) async fn deploy<P: Provider>(
    name: &str,
    tx: RawCallBuilder<P>,
) -> ContractResult<Address> {
    tracing::info!("deploying {name}");
    let pending_tx = tx.send().await?;
    let tx_hash = *pending_tx.tx_hash();
    tracing::info!(%tx_hash, "waiting for tx to be mined");

    let receipt = pending_tx.get_receipt().await?;
    tracing::info!(%receipt.gas_used, %tx_hash, "tx mined");
    let addr = receipt
        .contract_address
        .ok_or(alloy::contract::Error::ContractNotDeployed)?;

    tracing::info!("deployed {name} at {addr:#x}");
    Ok(addr)
}

/// Given a chain provider/connector, deploy a new KeyManager contract
pub async fn deploy_key_manager_contract(
    provider: impl Provider,
    manager: Address,
) -> ContractResult<Address> {
    // first deploy the implementation contract
    let tx = KeyManager::deploy_builder(&provider);
    let impl_addr = deploy("KeyManager", tx).await?;
    let km = KeyManager::new(impl_addr, &provider);

    // then deploy the proxy, point to the implementation contract and initialize it
    let init_data = km.initialize(manager).calldata().to_owned();
    let tx = ERC1967Proxy::deploy_builder(&provider, impl_addr, init_data);
    let proxy_addr = deploy("KeyManagerProxy", tx).await?;
    Ok(proxy_addr)
}

#[cfg(test)]
mod tests {
    use alloy::{providers::WalletProvider, sol_types::SolValue};
    use rand::prelude::*;

    use crate::{CommitteeMemberSol, CommitteeSol, KeyManager};

    #[tokio::test]
    async fn test_key_manager_deployment() {
        let (provider, addr) = crate::init_test_chain().await.unwrap();
        let manager = provider.default_signer_address();
        let contract = KeyManager::new(addr, provider);

        // try read from the contract storage
        assert_eq!(contract.manager().call().await.unwrap(), manager);

        // try write to the contract storage
        let rng = &mut rand::rng();
        let members = (0..5)
            .map(|_| CommitteeMemberSol::random())
            .collect::<Vec<_>>();
        let timestamp = rng.random::<u64>();

        let _tx_receipt = contract
            .setNextCommittee(timestamp, members.clone())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
            .unwrap();

        // make sure next committee is correctly registered
        assert_eq!(
            contract
                .getCommitteeById(0)
                .call()
                .await
                .unwrap()
                .abi_encode_sequence(),
            CommitteeSol {
                id: 0,
                effectiveTimestamp: timestamp,
                members,
            }
            .abi_encode_sequence()
        );
    }
}

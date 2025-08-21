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
    use crate::{KeyManager, deployer::deploy_key_manager_contract};
    use alloy::{primitives::Address, providers::ProviderBuilder};

    #[tokio::test]
    async fn test_key_manager_deployment() {
        let provider = ProviderBuilder::new().connect_anvil_with_wallet();
        let manager = Address::random();
        let addr = deploy_key_manager_contract(&provider, manager)
            .await
            .unwrap();
        let contract = KeyManager::new(addr, provider);

        // try read from the contract storage
        assert_eq!(contract.manager().call().await.unwrap(), manager);
    }
}

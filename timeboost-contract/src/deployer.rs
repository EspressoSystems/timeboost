//! Helper logic for contract deployment
use alloy::{
    contract::RawCallBuilder,
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    signers::local::MnemonicBuilder,
};
use coins_bip39::English;

use url::Url;

use crate::{ERC1967Proxy, KeyManager};

type ContractResult<T> = Result<T, alloy::contract::Error>;

#[derive(Clone)]
pub struct DeploymentEnvironment {
    pub url: Url,
    pub network_name: &'static str,
    pub mnemonic: String,
    pub account_index: usize,
}

impl DeploymentEnvironment {
    pub fn provider(&self) -> impl Provider + Clone {
        let wallet = MnemonicBuilder::<English>::default()
            .phrase(&self.mnemonic)
            .derivation_path(&format!("m/44'/60'/0'/0/{}", self.account_index))
            .expect("Invalid derivation path")
            .build()
            .expect("invalid mnemonic");

        ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(self.url.clone())
    }
}

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
pub async fn deploy_key_manager_contract<P>(
    provider: &P,
    manager: Address,
) -> ContractResult<Address>
where
    P: Provider,
{
    // first deploy the implementation contract
    let tx = KeyManager::deploy_builder(&provider);
    let impl_addr = deploy("KeyManager", tx).await?;
    let km = KeyManager::new(impl_addr, provider);

    // then deploy the proxy, point to the implementation contract and initialize it
    let init_data = km.initialize(manager).calldata().to_owned();
    let tx = ERC1967Proxy::deploy_builder(&provider, impl_addr, init_data);
    let proxy_addr = deploy("KeyManagerProxy", tx).await?;
    tracing::info!("deployed KeyManagerProxy at {proxy_addr:#x}");
    Ok(proxy_addr)
}

pub async fn deploy_key_manager_contract_with_env(
    env: DeploymentEnvironment,
    manager: Address,
) -> ContractResult<Address> {
    let provider = env.provider();
    tracing::info!("Deploying KeyManagerProxy to {}", env.network_name);
    let proxy_addr = deploy_key_manager_contract(&provider, manager).await?;
    Ok(proxy_addr)
}

#[cfg(test)]
mod tests {
    use crate::{
        KeyManager,
        deployer::{
            DeploymentEnvironment, deploy_key_manager_contract,
            deploy_key_manager_contract_with_env,
        },
    };
    use alloy::{node_bindings::Anvil, primitives::Address, providers::ProviderBuilder};

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

    #[tokio::test]
    async fn test_deployment_with_env() {
        // Spawn Anvil and get its URL
        let anvil = Anvil::new().spawn();
        let mnemonic = "test test test test test test test test test test test junk";

        let env = DeploymentEnvironment {
            url: anvil.endpoint_url(),
            network_name: "Local Anvil",
            mnemonic: mnemonic.to_string(),
            account_index: 0,
        };

        let manager = Address::random();
        let addr = deploy_key_manager_contract_with_env(env.clone(), manager)
            .await
            .unwrap();

        // Verify deployment
        let contract = KeyManager::new(addr, env.provider());
        assert_eq!(contract.manager().call().await.unwrap(), manager);
    }

    // TODO: add tests for remote deployment where the user specifies the network url and mnemonic
    // from an env file
}

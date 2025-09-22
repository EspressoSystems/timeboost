//! Contract deployment helpers for testing
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

#[cfg(test)]
mod tests {
    use super::deploy_key_manager_contract;
    use crate::{CommitteeMemberSol, CommitteeSol, KeyManager, KeyManager::CommitteeCreated};
    use alloy::{
        eips::BlockNumberOrTag,
        node_bindings::Anvil,
        primitives::U256,
        providers::{Provider, ProviderBuilder, WalletProvider},
        rpc::types::Filter,
        sol_types::{SolEvent, SolValue},
        transports::ws::WsConnect,
    };
    use futures::StreamExt;
    use rand::prelude::*;

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
            // deploy takes first 2 blocks: deploying implementation contract and proxy contract
            // setNextCommittee is the 3rd tx, thus in 3rd block
            CommitteeSol {
                id: 0,
                registeredBlockNumber: U256::from(3),
                effectiveTimestamp: timestamp,
                members,
            }
            .abi_encode_sequence()
        );
    }

    #[tokio::test]
    async fn test_event_stream() {
        let anvil = Anvil::new().spawn();
        let wallet = anvil.wallet().unwrap();
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(anvil.endpoint_url());
        let pubsub_provider = ProviderBuilder::new()
            .connect_pubsub_with(WsConnect::new(anvil.ws_endpoint_url()))
            .await
            .unwrap();
        assert_eq!(
            pubsub_provider.get_chain_id().await.unwrap(),
            provider.get_chain_id().await.unwrap()
        );

        let manager = provider.default_signer_address();
        let km_addr = deploy_key_manager_contract(&provider, manager)
            .await
            .unwrap();
        let contract = KeyManager::new(km_addr, &provider);

        // setup event stream
        let filter = Filter::new()
            .address(km_addr)
            .event(KeyManager::CommitteeCreated::SIGNATURE)
            .from_block(BlockNumberOrTag::Latest);
        let mut events = pubsub_provider
            .subscribe_logs(&filter)
            .await
            .unwrap()
            .into_stream();

        // register some committees on the contract, which emit events
        let rng = &mut rand::rng();
        let c0_timestamp = rng.random::<u64>();
        for i in 0..5 {
            let members = (0..5)
                .map(|_| CommitteeMemberSol::random())
                .collect::<Vec<_>>();
            let timestamp = c0_timestamp + 1000 * i;

            let _tx_receipt = contract
                .setNextCommittee(timestamp, members.clone())
                .send()
                .await
                .unwrap()
                .get_receipt()
                .await
                .unwrap();

            // Read the corresponding event
            let log = events.next().await.unwrap();
            let typed_log = log.log_decode_validate::<CommitteeCreated>().unwrap();
            assert_eq!(typed_log.data().id, i);
        }
    }
}

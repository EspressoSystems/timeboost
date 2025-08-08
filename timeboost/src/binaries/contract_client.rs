// WIP contract client
use timeboost_contracts::bindings::key_manager;
use alloy::{
    node_bindings::Anvil,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let anvil = Anvil::new().try_spawn().unwrap();
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let provider = ProviderBuilder::new().wallet(signer).connect_http(anvil.endpoint_url());

    // Example: Get the chain ID
    let chain_id = provider.get_chain_id().await?;
    println!("Chain ID: {}", chain_id);

    // Deploy the `KeyManager` contract.
    let contract = key_manager::KeyManager::deploy(&provider).await?;
    println!("KeyManager contract deployed at: {}", contract.address());

    Ok(())
}
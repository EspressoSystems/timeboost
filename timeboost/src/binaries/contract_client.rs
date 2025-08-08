// WIP contract client
use timeboost_contracts::bindings::key_manager;
use alloy_provider::Provider;
use alloy_provider::ProviderBuilder;
use alloy_node_bindings::Anvil;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let anvil = Anvil::new().try_spawn().unwrap();
    let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

    // Example: Get the chain ID
    let chain_id = provider.get_chain_id().await?;
    println!("Chain ID: {}", chain_id);

    Ok(())
}
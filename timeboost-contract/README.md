# Timeboost-Contract

A Rust crate that provides interfaces for interacting with Timeboost smart contracts from Rust code.

## Overview

This crate bridges the Timeboost system with deployed smart contracts, providing:
- **Contract Clients**: Type-safe interfaces for contract interactions
- **Deployment Utilities**: Helper functions for contract deployment (testing only)
- **Integration Patterns**: Common patterns for Timeboost<>contract communication

## Quick Start

### Testing with Deployed Contracts

```rust
use timeboost_contract::{init_test_chain, KeyManager};
use alloy::primitives::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get a deployed contract for testing
    let (provider, contract_address) = init_test_chain().await?;
    
    // Interact with the contract
    let contract = KeyManager::new(contract_address, provider);
    let manager = contract.manager().call().await?;
    println!("Current manager: {:#x}", manager);
    
    Ok(())
}
```

### Manual Contract Deployment (for testing)

```rust
use timeboost_contract::deployer::deploy_key_manager_contract;
use alloy::primitives::Address;
use alloy::providers::ProviderBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create your own provider
    let provider = ProviderBuilder::new().connect_anvil_with_wallet();
    
    // Deploy a contract
    let manager_address = Address::random();
    let contract_address = deploy_key_manager_contract(&provider, manager_address).await?;
    
    println!("KeyManager deployed at: {:#x}", contract_address);
    Ok(())
}
```

## API Reference

### init_test_chain()

Convenience function for testing - spawns Anvil and deploys a KeyManager contract:

```rust
pub async fn init_test_chain() -> Result<(TestProviderWithWallet, Address)>
```

**Returns:**
- `TestProviderWithWallet` - Provider connected to local Anvil instance
- `Address` - Address of the deployed KeyManager contract

### deploy_key_manager_contract()

Core deployment function for KeyManager contracts:

```rust
pub async fn deploy_key_manager_contract<P: Provider>(
    provider: &P,
    manager: Address,
) -> ContractResult<Address>
```

**Parameters:**
- `provider` - Alloy provider for network communication
- `manager` - Address to set as the contract manager

**Returns:**
- `Address` - Address of the deployed proxy contract

## Testing

### Running Tests

```bash
# Run all tests
cargo test -p timeboost-contract

# Run specific test
cargo test -p timeboost-contract test_key_manager_deployment
```

### Test Coverage

- **`test_key_manager_deployment`**: Basic contract deployment and verification
- **`test_local_deployment`**: End-to-end deployment with environment configuration

Tests automatically spawn local Anvil instances for isolated testing.

## Integration with Timeboost

This crate is designed to be used by other Timeboost components that need to:
- Deploy contracts for testing
- Interact with deployed KeyManager contracts
- Handle contract-related errors and responses

## Dependencies

- **alloy**: Ethereum client library
- **alloy-signer-local**: Local wallet signing
- **tokio**: Async runtime
- **anyhow**: Error handling

## Related Documentation

- **[Contracts README](../contracts/README.md)** - Smart contract details and deployment scripts
- **[Timeboost README](../timeboost/README.md)** - Main system documentation

## License

This project is licensed under the same terms as the parent Timeboost project.
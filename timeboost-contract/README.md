# Timeboost-Contract

A Rust crate that provides interfaces for interacting with Timeboost smart contracts from Rust code.

## Overview

This crate bridges the Timeboost system with deployed smart contracts, providing:
- **Contract Clients**: Type-safe interfaces for contract interactions
- **Deployment Utilities**: Helper functions for contract deployment (testing only)
- **Integration Patterns**: Common patterns for Timeboost<>contract communication

## Quick Start

### Contract Deployment used for tests

```rust
use timeboost_contract::deployer::{DeploymentEnvironment, deploy_key_manager_contract_with_env};
use alloy::primitives::Address;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a deployment environment
    let env = DeploymentEnvironment {
        url: "http://localhost:8545".parse()?,
        network_name: "Local Development",
        mnemonic: "test test test test test test test test test test test junk".to_string(),
        account_index: 0,
    };

    // Deploy a contract (for testing)
    let manager_address = Address::random();
    let contract_address = deploy_key_manager_contract_with_env(env, manager_address).await?;
    
    println!("KeyManager deployed at: {:#x}", proxy_address);
    Ok(())
}
```

## API Reference

### DeploymentEnvironment

Configuration for contract deployment and interaction:

```rust
pub struct DeploymentEnvironment {
    pub url: Url,                    // Network RPC endpoint
    pub network_name: &'static str,  // Human-readable network name
    pub mnemonic: String,            // Wallet mnemonic for transaction signing
    pub account_index: usize,        // HD wallet derivation index
}
```

**Methods:**
- `provider()` - Creates an Alloy provider for network communication
- `run()` - Deploys KeyManager contract and returns addresses

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
- **coins-bip39**: BIP39 mnemonic support
- **tokio**: Async runtime
- **anyhow**: Error handling

## Related Documentation

- **[Contracts README](../contracts/README.md)** - Smart contract details and deployment scripts
- **[Timeboost README](../timeboost/README.md)** - Main system documentation

## License

This project is licensed under the same terms as the parent Timeboost project.
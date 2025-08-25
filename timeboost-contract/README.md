# Timeboost-Contract
This is a rust crate to handle interactions between the smart contract, found in [../contracts](../contracts) and the timeboost crate [../timeboost](../timeboost).

**📋 For detailed information about the smart contracts themselves, see the [Contracts README](../contracts/README.md)**

It handles:
1. Contract deployments
2. Contract<>Timeboost interactions

## Testing Deployments
### Key Manager Contract
#### Local Blockchain Environment
To test the deployment of the key management contract, we can conduct a rust test which runs the deployment code and deploys the smart contract to a local, temporary environment (powered by Foundry's Anvil).
```sh
cargo test -p timeboost-contract test_key_manager_deployment
```
Tests:
- test_key_manager_deployment 
    - key manager deployment
    - correct manager address assignment in the contract
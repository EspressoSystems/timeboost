# Timeboost-Contract

A Rust crate that provides interfaces for interacting with Timeboost smart contracts from Rust code.

## Overview

This crate bridges the Timeboost system with deployed smart contracts, providing:
- **Deployment Utilities**: Helper functions for contract deployment (testing only)
- **Integration Patterns**: Common patterns for Timeboost<>contract communication

## Testing

### Running Tests

```bash
# Run all tests
cargo test -p timeboost-contract

# Run specific test
cargo test -p timeboost-contract test_key_manager_deployment
```

## Related Documentation

- **[Contracts README](../contracts/README.md)** - Smart contract details and deployment scripts
- **[Timeboost README](../timeboost/README.md)** - Main system documentation

## License

This project is licensed under the same terms as the parent Timeboost project.
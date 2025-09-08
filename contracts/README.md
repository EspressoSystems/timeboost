# Timeboost Smart Contracts

This directory contains the smart contracts that power the decentralized Timeboost protocol. These contracts run on Ethereum-compatible blockchains and provide the foundation for secure, decentralized time synchronization.

## Background
Smart contracts are executable code, deployed on blockchains that 
can be read from / written to anyone with an internet connection. 
Transaction data and smart contract storage is public and can be 
accessed in blockchain explorers. In decentralized Timeboost, 
smart contracts are used to allow anyone to interact with various 
of the protocol. This readme is directed at developers who are 
contributing to or making use of this decentralized timeboost 
implementation. 

## What Are These Contracts For?

Timeboost needs a way to coordinate cryptographic keys and committee members across a decentralized network. These smart contracts provide:

- **Key Management**: Store and manage public keys for the protocol
- **Committee Coordination**: Track which nodes are part of the consensus committee
- **Access Control**: Ensure only authorized parties can update critical protocol parameters
- **Transparency**: All changes are recorded on-chain for public verification

These contracts act as the "coordination layer" that allows the Timeboost network to operate without a central authority.

## Handling Upgradeability

### The Upgrade Problem
Once deployed, smart contracts can't be changed. To solve this, we use a proxy solution that performs functionally as upgradeable contracts. 

### The Proxy Solution
We use a "proxy pattern" that works like this:

1. **Users always interact with the proxy** - This address never changes
2. **The proxy points to an implementation** - This can be updated
3. **When you upgrade** - Just point the proxy to a new implementation
4. **All data stays safe** - Storage is preserved across upgrades

Think of it like changing the engine in a car - the car (proxy) stays the same, but you can swap out the engine (implementation) for a better one.

### Our Architecture
```
User → Proxy Contract → Implementation Contract
                    ↓
                Storage (persistent)
```

## The Contracts

### KeyManager - The Main Contract

**What it stores:**
- **Encryption keys** - The cryptographic keys used by the protocol
- **Committee members** - Who's currently in the consensus committee
- **Manager address** - Who can update the contract

**What it does:**
- **Sets committees** - Updates which nodes are part of the network
- **Manages keys** - Stores the threshold encryption key
- **Controls access** - Only the manager can make changes
- **Logs everything** - All changes are recorded as events

**Key functions:**
- `setNextCommittee()` - Add a new committee with future members
- `currentCommitteeId()` - Find which committee is active right now
- `getCommitteeById()` - Get details about a specific committee
- `setThresholdEncryptionKey()` - Set the encryption key for the protocol

### ERC1967Proxy - The Upgrade Mechanism
This is the "shell" that makes upgrades possible:

- **Never changes** - Users always interact with this address
- **Delegates calls** - Forwards requests to the current implementation
- **Preserves data** - All storage survives upgrades
- **SecOps Precautions** - it's important to call the initialize methods during deploys and upgrades so that those transactions aren't front-run

## Getting Started

### Prerequisites
- **Foundry** - For building and testing contracts

### Building the Contracts
```bash
# Build all contracts
just build-contracts

# Or use forge directly
forge build
```

### Testing
```bash
# Run all tests
just test-contracts

# Run with detailed output
forge test -vvv

# Run specific test
forge test --match-test test_setThresholdEncryptionKey
```

### Integration Testing
For testing contract interactions from Rust code, see the [timeboost-contract README](../timeboost-contract/README.md).

## Deployment
You can deploy a local anvil network (as done in the test), a fork of a real network, a testnet network (e.g. Ethereum Sepolia) or a mainnet (e.g. Ethereum Mainnet).

### Quick Start (Local Testing)
```bash
# 1. Start a local blockchain
anvil

# 2. Deploy the contracts
cp env.example .env
# Edit .env with your values
./script/deploy.sh
```

**📋 For detailed deployment instructions, see the [deployment script README](script/README.md)**

## Security

### Current Status
- **ERC1967Proxy** - Audited by OpenZeppelin, widely used
- **KeyManager** - Not yet audited (audit planned)

### Security Considerations
- **Manager privileges** - The manager can update committees and keys
- **Upgrade authority** - Only the contract owner can upgrade
- **Committee validation** - Contracts validate committee transitions
- **Event logging** - All changes are logged onchain for transparency

### Best Practices
- **Use multisig wallets** - Don't use single-key wallets for manager/owner
- **Test thoroughly** - Always test on testnets first
- **Monitor events** - Watch for unexpected contract changes
- **Keep keys secure** - Store private keys and mnemonics safely

## Getting Help
- Check the [deployment script README](script/README.md) for deployment issues
- Review the [timeboost-contract README](../timeboost-contract/README.md) for integration questions
# Background
Smart contracts are executable code, deployed on blockchains that can be read from / written to anyone with an internet connection. Transaction data and smart contract storage is public and can be accessed in blockchain explorers. In decentralized Timeboost, smart contracts are used to allow anyone to interact with various of the protocol. This readme is directed at developers who are contributing to or making use of this decentralized timeboost implementation. 

At the time of writing, the implementation for the **Key Management** contract can be found in this repo. This contract provides decentralized access and access control for cryptographic keys.

## Architecture Overview
Smart contracts are addressed by their blockchain address which can be used for reading and writing to the contract. Smart Contracts are not modifiable once deployed on a blockchain which means the case of upgrades have to be specially considered.

### Upgradeability
The `KeyManager` contract is upgradeable using a pattern called UUPS. Since contracts on a blockchain cannot be modified, upgradeability is achieved through a proxy contract which is the interface between users and the current contract implementation. When the owners of the contract want to upgrade, they update the address that the proxy contract points to. So the user always sends their read/write requests to the proxy contract and the proxy contract calls the current implementation contract (set by the owner) to determine the intended business logic for that read/write operation. The storage for that implementation contract is read from the proxy and the functionality  is determined by the implementation contract. 
 
- **Proxy Pattern**: Enables contract upgrades without losing state
- **Implementation**: Contains the business logic and can be upgraded
- **Storage**: Persistent data storage that survives upgrades

## Smart Contracts 
### KeyManager Contract
The core contract for managing cryptographic keys and access control.

**Purpose:**
- Secure key storage and retrieval
- Committee storage and retrieval
- Role-based access control 
- Upgradeable implementation
- Event logging for transparency and observability

### ERC1967Proxy
Standard proxy contract for upgradeable deployments.

**Purpose:**
- Delegates calls to implementation contract
- Maintains storage layout compatibility
- Enables seamless upgrades

## Development
### Building Contracts
```bash
just build-contracts
```

### Testing Contracts
```bash
just test-contracts
```
#### Run with verbose output
```bash
forge test --vvv
```
#### Integration Testing
Please see this [README](../timeboost-contract/README.md)

## Deployment
You can deploy a local anvil network (as done in the test), a fork of a real network, a testnet network (e.g. Ethereum Sepolia) or a mainnet (e.g. Ethereum Mainnet).

### Deployment steps
```bash
```

## Security
### Audit Status
- `ERC1967Proxy.sol` - an OpenZeppelin Contract which has been audited and widely used
- `KeyManager.sol` - not yet audited at the time of writing. 
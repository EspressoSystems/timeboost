# Test/Demo network configuration

The overall workflow works as follows:
- each individual node run `mkconfig` to generate a local config files, containing private keys, public keys, network addresses, chain configs, and nitro config. See [`node_0.toml`](./c0/node_0.toml) for an example. This `mkconfig` will additionally append (without duplication) to a [`committee.toml`](./c0/committee.toml) config file which is meant for the key manager role.
  - `committee.toml` simulates the (unspecified) offchain process of OCL DAO process eventually produced.
- one run `just test-chain-deploy --keep-anvil` which internally invoked two binaries: [`deploy`](../timeboost-contract/src/binaries/deploy.rs) to deploy contracts to parent chain, and [`register`](../timeboost-contract/src/binaries/register.rs) to take a `committee.toml` file and invoke `setNextCommittee()` on the [`KeyManager` contract](../contracts/src/KeyManager.sol).
  - this process is part of `./scripts/run_demo_[sailfish|timeboost]`.
  - for test blockchain, the deployed `KeyManager` contract is deterministic thus we included it ahead of time as part of `chain_config` in `node_i.toml` node config in the first step.
- a timeboost/sailfish node starts with a `--config node_i.toml` flag. On startup, it will fetch other peers' network address (the primary `sailfish_address`, all other are derived) and public keys from the contract since `.chain_config` did specify the deployed `KeyManager.sol` contract address. After getting all these info, timeboost node can construct struct like `Committee`, `Network` etc locally, and spawn off as usual.


To generate configs for all nodes in a new committee:

``` sh
# see mkconfig.rs Args or `mkconfig --help` for more options
just mkconfig 5 --seed 42
just mkconfig 13 --nitro-addr "localhost:55000"

# recipe for docker env is fixed at 5 nodes
just mkconfig_docker --seed 42

# recipe for nitro CI test, fixed at 2 nodes with nitro chain config
just mkconfig_nitro --seed 42
```

### On test wallet mnemonic 

The official test wallet is using `test ... test junk` as its mnemonic and most testnet will pre-fund accounts under this wallet. But the nonce of these wallet, especially the public testnets, is unpredictable making the deployed contract address unpredictable. 
Even though in test environments, we spawn off test blockchain from a fresh state, thus deployed KeyManager contract will always live in `0xe7f1725e7734ce288f8367e1bb143e90bb3f0512`, when we integrate with live Arbitrum testnet, this won't be the case.
To avoid future confusion, we choose a newly generated mnemonic phrase `"attend year erase basket blind adapt stove broccoli isolate unveil acquire category"`, not preoccupied w.h.p. and our deployed contract address should be the same across testnet (local or live). The only additional work is to fund this wallet using the default faucet which is step in [`test-contract-deploy` script](../../scripts/test-contract-deploy).
Now you can see in `--key-manager-addr "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35"` in `justfile`, which can verified by running `just test-contract-deploy`.

```
$ cast wallet new-mnemonic

Phrase:
attend year erase basket blind adapt stove broccoli isolate unveil acquire category

Accounts:
- Account 0:
Address:     0x36561082951eed7ffD59cFD82D70570C57072d02
Private key: 0x4a7347a749f03f485414757fce2ee0c77a76ee0a019c8af32b034b3b240a3136
```

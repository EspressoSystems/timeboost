# Test/Demo network configuration

The overall workflow works as follows:
- each individual node run `mkconfig` to generate a local config files, containing private keys, public keys, network addresses, chain configs, and nitro config. See [`node_0.toml`](./c0/node_0.toml) for an example. This `mkconfig` will additionally append (without duplication) to a [`committee.toml`](./c0/committee.toml) config file which is meant for the key manager role.
  - `committee.toml` simulates the (unspecified) offchain process of OCL DAO process eventually produced.
- one run `just test-chain-deploy --keep-anvil` which internally invoked two binaries: [`deploy`](../timeboost-contract/src/binaries/deploy.rs) to deploy contracts to parent chain, and [`register`](../timeboost-contract/src/binaries/register.rs) to take a `committee.toml` file and invoke `setNextCommittee()` on the [`KeyManager` contract](../contracts/src/KeyManager.sol).
  - this process is part of `./scripts/run_demo_[sailfish|timeboost]`.
  - for test blockchain, the deployed `KeyManager` contract is deterministic thus we included it ahead of time as part of `chain_config` in `node_i.toml` node config in the first step.
- a timeboost/sailfish node starts with a `--config-file node_i.toml` flag. On startup, it will fetch other peers' network address (the primary `sailfish_address`, all other are derived) and public keys from the contract since `.chain_config` did specify the deployed `KeyManager.sol` contract address. After getting all these info, timeboost node can construct struct like `Committee`, `Network` etc locally, and spawn off as usual.


To generate configs for all nodes in a new committee:

``` sh
# see mkconfig.rs Args or `mkconfig --help` for more options
just mkconfig 5
just mkconfig 13 --nitro-addr "0xabc"

# current just recipe for docker env is fixed at 5 nodes
just mkconfig_docker
```

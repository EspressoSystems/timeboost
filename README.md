# License
## Copyright
(c) 2025 Espresso Systems. Sailfish and Decentralized Timeboost were developed by Espresso Systems. While we plan to adopt an open source license, we have not yet selected one. As such, all rights are reserved for the time being. Please reach out to us if you have thoughts on licensing.

# Timeboost

Timeboost is a protocol which implements the Felten-Shoup
[decentralized timeboost protocol][timeboost]. This protocol is backed up by the
[Sailfish][sailfish] distributed consensus protocol. This repository contains the implementation
of the protocol in Rust, as well as exhaustive testing. The layout of the repository is as follows:

- `cliquenet`: Communication crate providing secure communication with the
   [Noise protocol framework][noise] over TCP/IP.
- `metrics`: Metrics API type definitions.
- `multisig`: Ed25519-based signature set creation and verification.
- `sailfish`: The implementation of the Sailfish consensus protocol, re-exporting the types from
   - `sailfish-consensus`,
   - `sailfish-rbc`, and
   - `sailfish-types`.
- `sailfish-consensus`: The core consensus protocol implementation.
- `sailfish-rbc`: Reliable byzantine broadcast implementation as used by sailfish.
- `sailfish-types`: Data type definitions exported by sailfish.
- `tests`: Battery of integration tests.
- `timeboost`: Contains the core implementation of the decentralized Timeboost builder protocol.
- `timeboost-builder`: Contains the builder implementation for the Timeboost protocol.
- `timeboost-sequencer`: Contains the sequencer implementation for the Timeboost protocol.
- `timeboost-types`: Contains essential type definitions of Timeboost.
- `timeboost-crypto`: Contains the threshold encryption scheme used by timeboost.
- `timeboost-utils`: Contains some utility functions.
- `timeboost-proto`: Contains protobuf schema and protobuf generated code for inlusion list
- `yapper`: Transaction submission test tool.

## Pre-requisites
- **Rust toolchain** (Minimum supported rust version (MSRV): 1.88): [Install via rustup](https://rustup.rs/)
- **just** (for command aliases):
  ```sh
  cargo install just
  ```
- **cargo-nextest** (for running tests):
  ```sh
  cargo install cargo-nextest
  ```

- **Foundry** (for Solidity development and testing): [Install Foundry](https://book.getfoundry.sh/getting-started/installation)
  ```sh
  curl -L https://foundry.paradigm.xyz | bash
  foundryup
  ```

- **Docker** (for integration tests, if needed): [Install Docker](https://docs.docker.com/get-docker/)

- **Initialize Submodules:**
   ```sh
   git submodule update --init --recursive
   ```

## Build

Debug build
```shell
just build
```

Release build
```shell
just build-release
```

## Run

Run in docker
```shell
just run-integration
```

### Accessing Metrics

Metrics are exposed on port 8000 + `i` for each node. Once the nodes are up and running, you
can execute the following command to access the metrics for the first node. The system is working
if you see output and the round number is gradually increasing.

```shell
curl --request GET \
  --url http://localhost:8000/status/metrics \
  --header 'User-Agent: insomnia/10.1.1'
```

## Lint

```shell
just lint
```

We recommend enforcing git pre-commit to ensure linting is done before each commit:

``` shell
ln -s ../../scripts/pre-commit .git/hooks/pre-commit
```

## Test

```shell
just test
```

[noise]: https://noiseprotocol.org/
[sailfish]: https://eprint.iacr.org/2024/472.pdf
[timeboost]: https://github.com/OffchainLabs/decentralized-timeboost-spec

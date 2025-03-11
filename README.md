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
- `timeboost-core`: Contains essential type definitions of timeboost.
- `timeboost-crypto`: Contains the threshold encryption scheme used by timeboost.
- `timeboost-utils`: Contains some utility functions.

## MSRV (minimum supported Rust version)
The MSRV of this repository is 1.85.

## Build

Debug build
```shell
just build
```

Release build
```shell
just build_release
```

## Run

Run in docker
```shell
just run_integration
```

Run locally
```shell
just run_integration_local
```

### Accessing Metrics

Metrics are exposed on port 9000 + `i` for each node. Once the nodes are up and running, you
can execute the following command to access the metrics for the first node. The system is working
if you see output and the round number is gradually increasing.

```shell
curl --request GET \
  --url http://localhost:9000/status/metrics \
  --header 'User-Agent: insomnia/10.1.1'
```

## Lint

```shell
just lint
```

## Test

```shell
just test
```

[noise]: https://noiseprotocol.org/
[sailfish]: https://eprint.iacr.org/2024/472.pdf
[timeboost]: https://github.com/OffchainLabs/decentralized-timeboost-spec

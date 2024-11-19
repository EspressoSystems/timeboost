# Timeboost
Timeboost is a protocol which implements the Felden-Shoup [decentralized timeboost protocol](https://github.com/OffchainLabs/decentralized-timeboost-spec). This protocol is backed up by the [Sailfish](https://eprint.iacr.org/2024/472.pdf) distributed consensus protocol. This repository contains the implementation of the protocol in Rust, as well as exhaustive testing. The layout of the repository is as follows:

- `timeboost` contains the core implementation of the decentralized Timeboost builder protocol.
- `sailfish` contains the implementation of the Sailfish consensus protocol.
- `timeboost-core` contains shared code between the two protocols.
- `timeboost-networking` contains the network layer for the protocol.

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
Metrics are exposed on port 9000 + <node_id> for each node. Once the nodes are up and running, you can execute the following command to access the metrics for the first node. The system is working if you see output and the round number is gradually increasing.

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

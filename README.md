# Timeboost

A decentralized sequencer integrated with the [Espresso Network](https://www.espressosys.com/) for fast transaction confirmations. This implementation follows the [Felten-Shoup Decentralized Timeboost specification](https://github.com/OffchainLabs/decentralized-timeboost-spec), using [Sailfish](https://eprint.iacr.org/2024/472.pdf) consensus with an optional encrypted mempool based on the [SG01](https://www.shoup.net/papers/thresh1.pdf) threshold decryption scheme.

## Overview

This repository provides a complete decentralized sequencer implementation with configurable transaction ordering policies:

- **Timeboost Mode**: Priority-based ordering with express lanes via Timeboost contracts
- **FCFS Mode**: First-come-first-served ordering

Both modes support an optional encrypted mempool using threshold encryption for transaction privacy before ordering.

Written in Rust with comprehensive testing infrastructure.

## Architecture

```
timeboost/
├── Core Components
│   ├── timeboost/               # Main orchestration and API layer
│   ├── timeboost-builder/       # Block certification and Espresso submission
│   ├── timeboost-sequencer/     # Transaction ordering and threshold decryption
│   ├── timeboost-types/         # Shared type definitions
│   ├── timeboost-crypto/        # Threshold encryption (TPKE) and DKG
│   ├── timeboost-config/        # Node and committee configuration
│   └── timeboost-utils/         # Common utilities
│
├── Consensus Layer
│   ├── sailfish/                # Consensus coordinator and handover management
│   ├── sailfish-consensus/      # DAG-based BFT consensus
│   ├── sailfish-rbc/            # Reliable broadcast channel
│   └── sailfish-types/          # Consensus type definitions
│
├── Networking
│   ├── cliquenet/               # P2P networking (Noise protocol, X25519)
│   └── multisig/                # Signatures and quorum certificates
│
└── Infrastructure
    ├── adapters/                # CBOR encoding adapters
    ├── robusta/                 # Espresso network client
    ├── state-io/                # Persistent state backends
    ├── test-utils/              # Test infrastructure
    ├── tests/                   # Integration tests
    └── times/                   # Performance metrics
```

## Prerequisites

- **Rust toolchain** (Minimum supported rust version: 1.88) - [Install via rustup](https://rustup.rs/)
- **just** - Command runner for project tasks - [Install just](https://github.com/casey/just#installation)
- **cargo-nextest** - Next-generation test runner for Cargo - [Install nextest](https://nexte.st/book/installation.html)
- **Foundry** - Solidity development and testing toolkit - [Install Foundry](https://book.getfoundry.sh/getting-started/installation)
- **Docker** - For running integration tests - [Install Docker](https://docs.docker.com/get-docker/)

## Usage

### Build

Debug build

```shell
just build
```

Release build

```shell
just build-release
```

### Run

Run in Docker

```shell
just docker run-integration
```

### Lint

```shell
just lint
```

### Test

```shell
just test
```

## License

Copyright (c) 2025 Espresso Systems. Sailfish and Decentralized Timeboost were developed by Espresso Systems. While we plan to adopt an open source license, we have not yet selected one. As such, all rights are reserved for the time being. Please reach out to us if you have thoughts on licensing.

[noise]: https://noiseprotocol.org/
[sailfish]: https://eprint.iacr.org/2024/472.pdf
[SG01]: (https://www.shoup.net/papers/thresh1.pdf)
[timeboost]: https://github.com/OffchainLabs/decentralized-timeboost-spec

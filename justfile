export RUSTDOCFLAGS := '-D warnings'

log_levels  := "RUST_LOG=timeboost=debug,sailfish=debug,cliquenet=debug,tests=debug"
run_as_root := if env("CI", "") == "true" { "sudo" } else { "run0" }

####################
###BUILD COMMANDS###
####################

build *ARGS:
  cargo build {{ARGS}}

update-submodules:
  git submodule update --remote --recursive
  cd timeboost-proto && cargo build
  cd ../contracts && forge build

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

build_docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest
  docker build . -f ./docker/yapper.Dockerfile -t yapper:latest

build-contracts:
  forge build

[private]
build-port-alloc:
  cargo build --release -p test-utils --bin run --bin port-alloc --no-default-features --features ports

[private]
build-test-utils:
  cargo build --release -p test-utils --all-features

####################
###CHECK COMMANDS###
####################
clippy:
  cargo clippy --workspace --lib --tests --benches -- -D warnings

check:
  cargo check --all

check-individually:
  @for pkg in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name'); do \
    echo "Checking $pkg"; \
    cargo check -p $pkg || exit 1; \
  done

fmt *ARGS='--all':
  cargo +nightly fmt {{ARGS}}

fmt_check:
  cargo +nightly fmt --check

lint: clippy fmt_check

fix:
  cargo fix --allow-dirty --allow-staged

ci_local:
  just build && just lint && just test_ci --release && \
  just run_demo --ignore-stamp --yapper -c test-configs/c0 && \
  just run_sailfish_demo && just build_docker

bacon: clippy check fmt

####################
####RUN COMMANDS####
####################
run_integration: build_docker
  -docker network create --subnet=172.20.0.0/16 timeboost
  docker compose -f docker-compose.yml -f docker-compose.metrics.yml up -d

stop_integration:
  docker compose -f docker-compose.yml -f docker-compose.metrics.yml down

run_monitoring:
  -docker network create --subnet=172.20.0.0/16 timeboost
  docker compose -f docker-compose.metrics.yml up -d

stop_monitoring:
  docker compose -f docker-compose.metrics.yml down

run_demo *ARGS:
  scripts/run-timeboost-demo {{ARGS}}

run_sailfish_demo *ARGS:
  scripts/run-sailfish-demo {{ARGS}}

run *ARGS:
  cargo run {{ARGS}}

bench *ARGS:
  cargo bench --benches {{ARGS}} -- --nocapture

mkconfig NUM_NODES DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n {{NUM_NODES}} \
    --public-addr "127.0.0.1:8000" \
    --internal-addr "127.0.0.1:8003" \
    --http-api "127.0.0.1:8004" \
    --chain-namespace 10101 \
    --parent-rpc-url "http://127.0.0.1:8545" \
    --parent-chain-id 31337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/c0" {{ARGS}}

mkconfig_docker DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n 5 \
    --public-addr "172.20.0.2:8000" \
    --internal-addr "172.20.0.2:8003" \
    --http-api "172.20.0.2:8004" \
    --mode "increment-address" \
    --chain-namespace 10101 \
    --parent-rpc-url "http://127.0.0.1:8545" \
    --parent-chain-id 31337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/docker" {{ARGS}}

mkconfig_nitro DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n 2 \
    --public-addr "127.0.0.1:8000" \
    --internal-addr "0.0.0.0:8003" \
    --http-api "127.0.0.1:8004" \
    --nitro-addr "localhost:55000" \
    --chain-namespace 412346 \
    --parent-rpc-url "http://127.0.0.1:8545" \
    --parent-chain-id 1337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/nitro-ci-committee" {{ARGS}}

verify_blocks *ARGS:
  cargo run --release --bin block-verifier {{ARGS}}

####################
####TEST COMMANDS###
####################
test *ARGS: build-port-alloc
  target/release/run --spawn target/release/port-alloc cargo nextest run -- {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test-contracts: build-contracts
  forge test

test_ci *ARGS: build-port-alloc
  env {{log_levels}} NO_COLOR=1 target/release/run \
    --spawn target/release/port-alloc \
    cargo nextest run -- --workspace {{ARGS}}
  env {{log_levels}} NO_COLOR=1 cargo test --doc {{ARGS}}

test-individually: build-port-alloc
  @for pkg in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name'); do \
    echo "Testing $pkg"; \
    $(target/release/run \
        --spawn target/release/port-alloc \
        cargo nextest run -- --no-tests=pass -p $pkg) || exit 1; \
  done

test-contract-deploy *ARGS:
  scripts/test-contract-deploy {{ARGS}}

test-all: build_release build-test-utils
  env RUST_LOG=timeboost_builder::submit=debug,block_checker=info,warn \
  target/release/run \
    --verbose \
    --timeout 120 \
    --spawn "1:anvil --port 8545" \
    --run   "2:sleep 3" \
    --run   "3:scripts/deploy-test-contract test-configs/local/committee.toml http://localhost:8545" \
    --spawn "4:target/release/block-maker --bind 127.0.0.1:55000 -c test-configs/local/committee.toml" \
    --spawn "4:target/release/yapper -c test-configs/local/committee.toml" \
    --spawn "5:target/release/run-committee -c test-configs/local/ -t target/release/timeboost" \
    target/release/block-checker -- -c test-configs/local -b 1000

[linux]
forward-ipv4 val: build-test-utils
    {{run_as_root}} target/release/net-setup system --forward-ipv4 {{val}}

[linux]
create-net: build-test-utils
    {{run_as_root}} target/release/net-setup create -c test-configs/linux/net.toml

[linux]
delete-net: build-test-utils
    {{run_as_root}} target/release/net-setup delete -c test-configs/linux/net.toml

[linux]
netsim: build_release build-test-utils
    #!/usr/bin/env bash
    set -eo pipefail
    function run_as_root {
        if [ "$CI" == "true" ]; then
            sudo "$@"
        else
            run0 --setenv=PATH --setenv=HOME --setenv=RUST_LOG "$@"
        fi
    }
    export RUST_LOG=timeboost_builder::submit=debug,block_checker=info,warn
    run_as_root target/release/run \
        --verbose \
        --timeout 120 \
        --clear-env \
        --env PATH \
        --env HOME \
        --env RUST_LOG \
        --uid $(id -u) \
        --gid $(id -g) \
        --spawn "1:anvil --host 10.0.1.0 --port 8545" \
        --run   "2:sleep 3" \
        --run   "3:scripts/deploy-test-contract test-configs/linux/committee.toml http://10.0.1.0:8545" \
        --spawn "4:target/release/block-maker --bind 10.0.1.0:55000 -c test-configs/linux/committee.toml" \
        --spawn "4:target/release/yapper -c test-configs/linux/committee.toml" \
        --spawn-as-root "5:target/release/run-committee -u $(id -u) -g $(id -g) -c test-configs/linux/ -t target/release/timeboost" \
        target/release/block-checker -- -c test-configs/linux -b 200

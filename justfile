export RUSTDOCFLAGS := '-D warnings'

log_levels  := "RUST_LOG=timeboost=debug,sailfish=debug,cliquenet=debug,tests=debug"
run_as_root := if env("CI", "") == "true" { "sudo" } else { "run0" }

build *ARGS:
  cargo build {{ARGS}}

update-submodules:
  git submodule update --remote --recursive
  cd timeboost-proto && cargo build
  cd contracts && forge build

build-release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

build-release-until:
  cargo build --release --workspace --all-targets --features "until"

build-docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest

build-docker-amd:
  docker build . -f ./docker/timeboost-amd.Dockerfile -t timeboost:latest

clean-docker:
  docker ps -q | xargs -r docker stop
  docker compose down --rmi all --volumes --remove-orphans
  docker system prune -a --volumes --force

build-contracts:
  forge build

[private]
build-port-alloc:
  cargo build --release -p test-utils --bin run --bin port-alloc --no-default-features --features ports

[private]
build-test-utils:
  cargo build --release -p test-utils --all-features

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

fmt-check:
  cargo +nightly fmt --check

lint: clippy fmt-check

fix:
  cargo fix --allow-dirty --allow-staged

ci-local:
  just build && just lint && just test-ci --release && \
  just run-demo --ignore-stamp --yapper -c test-configs/c0 && \
  just run-sailfish-demo && just build-docker

run-integration: build-docker-amd
    -docker network create timeboost
    docker compose -f docker-compose.block-maker.yml -f docker-compose.metrics.yml up -d

run-integration-nitro: build-docker-amd
  -docker network create timeboost
  docker compose -f docker-compose.nitro.yml -f docker-compose.metrics.yml up -d

run-integration-nitro-ci:
  -docker network create timeboost
  docker compose -f docker-compose.nitro-ci.yml up -d

run-demo *ARGS:
  scripts/run-timeboost-demo {{ARGS}}

run-sailfish-demo: build-test-utils build-release
  env RUST_LOG=sailfish=info,warn \
  target/release/run --verbose \
      --spawn "1:anvil --port 8545" \
      --run   "2:sleep 3" \
      --run   "3:scripts/deploy-contract -c test-configs/c0/committee.toml -u http://localhost:8545" \
      --spawn "4:target/release/sailfish -c test-configs/c0/node_0.toml --stamp /tmp/stamp-0.sf --ignore-stamp" \
      --spawn "4:target/release/sailfish -c test-configs/c0/node_1.toml --stamp /tmp/stamp-1.sf --ignore-stamp" \
      --spawn "4:target/release/sailfish -c test-configs/c0/node_2.toml --stamp /tmp/stamp-2.sf --ignore-stamp" \
      --spawn "4:target/release/sailfish -c test-configs/c0/node_3.toml --stamp /tmp/stamp-3.sf --ignore-stamp" \
      target/release/sailfish -- -c test-configs/c0/node_4.toml --stamp /tmp/stamp-4.sf --ignore-stamp --until 300

run *ARGS:
  cargo run {{ARGS}}

bench *ARGS:
  cargo bench --benches {{ARGS}} -- --nocapture

mkconfig NUM_NODES DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n {{NUM_NODES}} \
    --committee-id 0 \
    --public-addr "127.0.0.1:8000" \
    --internal-addr "127.0.0.1:8003" \
    --http-api "127.0.0.1:8004" \
    --chain-namespace 10101 \
    --parent-rpc-url "http://127.0.0.1:8545" \
    --parent-ws-url "ws://127.0.0.1:8545" \
    --parent-chain-id 31337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/c0" {{ARGS}}

mkconfig-docker DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n 5 \
    --committee-id 0 \
    --public-addr "node:8000" \
    --public-mode "docker-dns" \
    --internal-addr "node:8003" \
    --http-api "node:8004" \
    --nitro-addr "nitro:55000" \
    --nitro-mode "docker-dns" \
    --parent-rpc-url "http://demo-l1-network:8545" \
    --parent-ws-url "ws://demo-l1-network:8546" \
    --chain-namespace 412346 \
    --parent-chain-id 1337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --espresso-base-url "http://espresso-dev-node:41000/v1/" \
    --espresso-websocket-url "ws://espresso-dev-node:41000/v1/" \
    --output "test-configs/docker" {{ARGS}}

mkconfig-nitro-ci DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n 2 \
    --committee-id 0 \
    --public-addr "127.0.0.1:8000" \
    --internal-addr "0.0.0.0:8003" \
    --http-api "127.0.0.1:8004" \
    --nitro-addr "localhost:55000" \
    --chain-namespace 412346 \
    --parent-rpc-url "http://127.0.0.1:8545" \
    --parent-ws-url "ws://127.0.0.1:8546" \
    --parent-chain-id 1337 \
    --espresso-base-url "http://127.0.0.1:41000/v1/" \
    --espresso-websocket-url "ws://127.0.0.1:41000/v1/" \
    --parent-ibox-contract "0xCbfD7eeB1Cbd827a8B4dE3752D3994E9A8641FA2" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/nitro-ci" {{ARGS}}

mkconfig-local DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n 5 \
    --committee-id 0 \
    --public-addr "127.0.0.1:8000" \
    --internal-addr "127.0.0.1:8003" \
    --http-api "127.0.0.1:8004" \
    --nitro-addr "127.0.0.1:55000" \
    --nitro-mode "unchanged" \
    --chain-namespace 10101 \
    --parent-rpc-url "http://127.0.0.1:8545" \
    --parent-ws-url "ws://127.0.0.1:8545" \
    --parent-chain-id 31337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/local" {{ARGS}}

mkconfig-linux NUM_NODES DATETIME *ARGS:
  cargo run --release --bin mkconfig -- -n {{NUM_NODES}} \
    --committee-id 0 \
    --public-addr "11.0.0.1:8000" \
    --public-mode "increment-address" \
    --internal-addr "11.0.0.1:8003" \
    --http-api "11.0.0.1:8004" \
    --nitro-addr "11.0.1.0:55000" \
    --nitro-mode "unchanged" \
    --chain-namespace 10101 \
    --parent-rpc-url "http://11.0.1.0:8545" \
    --parent-ws-url "ws://11.0.1.0:8545" \
    --parent-chain-id 31337 \
    --parent-ibox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
    --key-manager-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
    --timestamp {{DATETIME}} \
    --stamp-dir "/tmp" \
    --output "test-configs/linux" {{ARGS}}

verify-blocks *ARGS:
  cargo run --release --bin block-verifier {{ARGS}}

test *ARGS: build-port-alloc
  target/release/run --spawn target/release/port-alloc cargo nextest run -- {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test-contracts: build-contracts
  forge test

test-ci *ARGS: build-port-alloc
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

test-all nodes="5": build-release build-test-utils
  env RUST_LOG=timeboost_builder::submit=debug,block_checker=info,warn,yapper=error \
  target/release/run \
    --verbose \
    --timeout 120 \
    --spawn "1:anvil --port 8545" \
    --run   "2:sleep 3" \
    --run   "3:scripts/deploy-contract -c test-configs/local/committee.toml -u http://localhost:8545" \
    --spawn "4:target/release/block-maker --bind 127.0.0.1:55000 -c test-configs/local/committee.toml --max-nodes {{nodes}}" \
    --spawn "4:target/release/yapper -c test-configs/local/ --max-nodes {{nodes}}" \
    --spawn "5:target/release/run-committee \
        -c test-configs/local/ \
        -s test-configs/scenarios/rolling-restart.toml \
        --verbose \
        --max-nodes {{nodes}}" \
    target/release/block-checker -- -c test-configs/local --max-nodes {{nodes}} -b 300

test-dyn-comm: build-release-until build-test-utils
  env RUST_LOG=sailfish=warn,timeboost=info,info target/release/run \
    --verbose \
    --timeout 120 \
    --spawn "1:anvil --port 8545" \
    --run   "2:sleep 2" \
    --run   "3:scripts/deploy-contract -c test-configs/c0/committee.toml -u http://localhost:8545" \
    --spawn "4:target/release/run-committee -c test-configs/c0/ --max-nodes 5 --until 2000" \
    --run   "5:target/release/mkconfig -n 4 \
                 --committee-id 1 \
                 --public-addr 127.0.0.1:9000 \
                 --internal-addr 127.0.0.1:9003 \
                 --http-api 127.0.0.1:9004 \
                 --chain-namespace 10101 \
                 --parent-rpc-url http://127.0.0.1:8545 \
                 --parent-ws-url ws://127.0.0.1:8545 \
                 --parent-chain-id 31337 \
                 --parent-ibox-contract 0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1 \
                 --key-manager-contract 0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35 \
                 --timestamp +16s \
                 --stamp-dir /tmp \
                 --output test-configs/c1" \
    --run   "6:sleep 6" \
    --run   "7:target/release/register \
                 -a threshold-enc-key \
                 -m 'attend year erase basket blind adapt stove broccoli isolate unveil acquire category' \
                 -u http://localhost:8545 \
                 -k 0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35 \
                 -c test-configs/c0/committee.toml \
                 --max-members 5" \
    --run   "8:target/release/register \
                 -a new-committee \
                 -m 'attend year erase basket blind adapt stove broccoli isolate unveil acquire category' \
                 -u http://localhost:8545 \
                 -k 0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35 \
                 -c test-configs/c1/committee.toml \
                 --max-members 4" \
    --spawn "9:target/release/yapper --config test-configs/c1/ --max-nodes 4" \
    target/release/run-committee -- \
      -c test-configs/c1/ \
      --until 800 \
      --required-decrypt-rounds 3 \
      --verbose \
      --max-nodes 4 && rm -rf test-configs/c1

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
netsim nodes: build-release build-test-utils
    #!/usr/bin/env bash
    set -eo pipefail
    function run_as_root {
        if [ "$CI" == "true" ]; then
            sudo --preserve-env=PATH,HOME,RUST_LOG "$@"
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
        --spawn "1:anvil --host 11.0.1.0 --port 8545" \
        --run   "2:sleep 3" \
        --run   "3:scripts/deploy-contract -c test-configs/linux/committee.toml --max-nodes {{nodes}} -u http://11.0.1.0:8545" \
        --spawn "4:target/release/block-maker --bind 11.0.1.0:55000 -c test-configs/linux/committee.toml --max-nodes {{nodes}}" \
        --spawn "4:target/release/yapper -c test-configs/linux/ --max-nodes {{nodes}}" \
        --spawn-as-root "5:target/release/run-committee \
            -u $(id -u) \
            -g $(id -g) \
            -c test-configs/linux/ \
            -s test-configs/scenarios/default.toml \
            --verbose \
            --max-nodes {{nodes}}" \
        target/release/block-checker -- -c test-configs/linux -b 200 --max-nodes {{nodes}}

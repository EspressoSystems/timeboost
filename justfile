set export

export RUSTDOCFLAGS := '-D warnings'

LOG_LEVELS := "RUST_LOG=timeboost=debug,sailfish=debug,cliquenet=debug,tests=debug"

####################
###BUILD COMMANDS###
####################

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

build_docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest
  docker build . -f ./docker/yapper.Dockerfile -t yapper:latest

build-contracts:
  forge build

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
  just build && just lint && just test_ci --release && just run_demo && just run_sailfish_demo && just build_docker

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

run_integration_local *ARGS:
  ./scripts/run-local-integration {{ARGS}}

run_demo *ARGS:
  ./scripts/run-timeboost-demo {{ARGS}}

run_sailfish_demo *ARGS:
  ./scripts/run-sailfish-demo {{ARGS}}

run *ARGS:
  cargo run {{ARGS}}

bench *ARGS:
  cargo bench --benches {{ARGS}} -- --nocapture

mkconfig_local NUM_NODES *ARGS:
  just mkconfig_local_full {{NUM_NODES}} "https://theserversroom.com/ethereum/54cmzzhcj1o/" 1 "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f" {{ARGS}}

mkconfig_local_full NUM_NODES RPC_URL PARENT_CHAIN_ID PARENT_INBOX_ADDRESS *ARGS:
  cargo run --bin mkconfig -- -n {{NUM_NODES}} \
    --sailfish-base-addr "127.0.0.1:8000" \
    --decrypt-base-addr "127.0.0.1:10000" \
    --certifier-base-addr "127.0.0.1:11000" \
    --internal-base-addr "127.0.0.1:5000" \
    --parent-rpc-url {{RPC_URL}} \
    --parent-chain-id {{PARENT_CHAIN_ID}} \
    --parent-ibox-contr-addr {{PARENT_INBOX_ADDRESS}} \
    --mode "increment-port" {{ARGS}} | jq

mkconfig_docker NUM_NODES *ARGS:
  just mkconfig_docker_full {{NUM_NODES}} "https://theserversroom.com/ethereum/54cmzzhcj1o/" 1 "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f" {{ARGS}}

mkconfig_docker_full NUM_NODES RPC_URL PARENT_CHAIN_ID PARENT_INBOX_ADDRESS *ARGS:
  cargo run --bin mkconfig -- -n {{NUM_NODES}} \
    --sailfish-base-addr "172.20.0.2:8000" \
    --decrypt-base-addr "172.20.0.2:8001" \
    --certifier-base-addr "172.20.0.2:8002" \
    --internal-base-addr "172.20.0.2:5000" \
    --parent-rpc-url {{RPC_URL}} \
    --parent-chain-id {{PARENT_CHAIN_ID}} \
    --parent-ibox-contr-addr {{PARENT_INBOX_ADDRESS}} \
    --mode "increment-address" {{ARGS}} | jq

verify_blocks *ARGS:
  cargo run --release --bin block_verifier {{ARGS}}

####################
####TEST COMMANDS###
####################
test *ARGS:
  cargo nextest run {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test-contracts: build-contracts
  forge test

test_ci *ARGS:
  env {{LOG_LEVELS}} NO_COLOR=1 cargo nextest run --workspace {{ARGS}}
  env {{LOG_LEVELS}} NO_COLOR=1 cargo test --doc {{ARGS}}

test-individually:
  @for pkg in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name'); do \
    echo "Testing $pkg"; \
    cargo nextest run --no-tests=pass -p $pkg || exit 1; \
  done

test-contract-deploy:
  #!/bin/bash
  set -exo pipefail

  # Kill any existing anvil processes to avoid port conflicts
  pkill anvil || true
  sleep 1

  # Start anvil in background
  anvil --port 8545 > anvil.log 2>&1 &
  ANVIL_PID=$!
  echo $ANVIL_PID > .anvil.pid

  # Set up cleanup function
  cleanup() {
    if [ -n "$ANVIL_PID" ]; then
      kill $ANVIL_PID 2>/dev/null || true
    fi
    rm -f .anvil.pid anvil.log
  }

  # Ensure cleanup happens on exit
  trap cleanup EXIT

  # Wait for anvil to start
  sleep 1

  # Run the deploy command
  RUST_LOG=info cargo run --bin deploy --config ./test-configs/keymanager.toml

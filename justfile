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

mkconfig NUM_NODES *ARGS:
  #!/bin/bash
  for i in $(seq 0 $(({{NUM_NODES}} - 1))); do \
    echo "mkconfig for node $i"; \
    just mkconfig_full "http://127.0.0.1:8545" 31337 "0x4dbd4fc535ac27206064b68ffcf827b0a60bab3f" \
      --sailfish "127.0.0.1:$((8000 + i))" \
      -o "test-configs/c0/node_$i.toml" \
      --seed $((42+i)) {{ARGS}}; \
  done

mkconfig_full RPC_URL PARENT_CHAIN_ID PARENT_INBOX_ADDRESS *ARGS:
  cargo run --bin mkconfig -- \
    --key-manager-addr "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512" \
    --parent-rpc-url {{RPC_URL}} \
    --parent-chain-id {{PARENT_CHAIN_ID}} \
    --parent-ibox-contr-addr {{PARENT_INBOX_ADDRESS}} \
    {{ARGS}}

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

test-contract-deploy *ARGS:
  ./scripts/test-contract-deploy {{ARGS}}

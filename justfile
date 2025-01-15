set export

####################
###BUILD COMMANDS###
####################

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

build_docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest
  docker build . -f ./docker/tx-generator.Dockerfile -t tx-generator:latest
  docker build . -f ./docker/fake-contract.Dockerfile -t fake-contract:latest

####################
###CHECK COMMANDS###
####################
clippy:
  cargo clippy --workspace --lib --tests --benches -- -D warnings

check:
  cargo check --all

fmt:
  cargo fmt --all

fmt_check:
  cargo fmt --check

lint: clippy fmt_check

fix:
  cargo fix --allow-dirty --allow-staged

ci_local:
  just build && just lint && just test_ci --release && just run_demo && just build_docker

bacon: clippy check fmt

####################
####RUN COMMANDS####
####################
run_integration: build_docker
  docker compose -f docker-compose.yml -f docker-compose.metrics.yml up -d

stop_integration:
  docker compose -f docker-compose.yml -f docker-compose.metrics.yml down

run_integration_local *ARGS:
  ./scripts/run-local-integration {{ARGS}}

run_demo *ARGS:
  ./scripts/run-demo {{ARGS}}

run_tx_generator *ARGS:
  cargo run --release --bin tx-generator {{ARGS}}

run_fake_contract *ARGS:
  cd fake-contract && uv run main.py {{ARGS}}

run *ARGS:
  cargo run {{ARGS}}

bench:
  cargo bench --benches -- --nocapture

####################
####TEST COMMANDS###
####################
test *ARGS:
  cargo nextest run --test-threads $(nproc) {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test_ci *ARGS:
  RUST_LOG=sailfish=debug,tests=debug cargo nextest run --workspace --retries 3 --test-threads $(nproc) {{ARGS}}
  RUST_LOG=sailfish=debug,tests=debug cargo test --doc {{ARGS}}


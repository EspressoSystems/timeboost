set export

original_rustflags := env_var_or_default('RUSTFLAGS', '')

export RUSTDOCFLAGS := '-D warnings --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'
export RUSTFLAGS := original_rustflags + ' --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

test *ARGS:
  cargo nextest run {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test_ci *ARGS:
  RUST_LOG=sailfish=debug,tests=debug cargo nextest run --workspace --retries 3 {{ARGS}}
  RUST_LOG=sailfish=debug,tests=debug cargo test --doc {{ARGS}}

run *ARGS:
  cargo run {{ARGS}}

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

build_docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest
  docker build . -f ./docker/tx-generator.Dockerfile -t tx-generator:latest

run_integration: build_docker
  docker compose up --abort-on-container-exit

run_integration_local *ARGS:
  ./scripts/run-local-integration {{ARGS}}

run_demo *ARGS:
  ./scripts/run-demo {{ARGS}}

run_tx_generator *ARGS:
  cargo run --release --bin tx-generator {{ARGS}}

ci_local:
  just build && just lint && just test_ci --release && just run_demo && just build_docker

bacon: clippy check fmt

set export

original_rustflags := env_var_or_default('RUSTFLAGS', '')

export RUSTDOCFLAGS := '-D warnings --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'
export RUSTFLAGS := original_rustflags + ' --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

test *ARGS:
  cargo nextest run --no-capture {{ARGS}}

test_ci *ARGS:
  RUST_LOG=sailfish=debug,tests=debug cargo nextest run --workspace --retries 3 --no-capture {{ARGS}}

run *ARGS:
  cargo run {{ARGS}}

clippy:
  cargo clippy --workspace --lib --tests -- -D warnings

fmt:
  cargo fmt

fmt_check:
  cargo fmt --check

lint: clippy fmt_check

fix:
  cargo fix --allow-dirty --allow-staged

build_docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest

run_integration: build_docker
  docker compose up --abort-on-container-exit

run_integration_local *ARGS:
  ./scripts/run-local-integration {{ARGS}}

run_demo:
  ./scripts/run-demo

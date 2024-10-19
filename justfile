set export

original_target_dir := env_var_or_default('CARGO_TARGET_DIR', 'target')
original_rustflags := env_var_or_default('RUSTFLAGS', '')

export RUSTDOCFLAGS := '-D warnings --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'
export RUSTFLAGS := original_rustflags + ' --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'
export CARGO_TARGET_DIR := original_target_dir + '/tokio'

build:
  cargo build

build_release:
  cargo build --release --workspace

test *ARGS:
  cargo nextest run --release --no-capture {{ARGS}}

test_ci *ARGS:
  RUST_LOG=sailfish=debug,tests=debug cargo nextest run --workspace --test-threads 1 --release --retries 3 --no-capture  {{ARGS}}

run *ARGS:
  cargo run {{ARGS}}

clippy:
  cargo clippy -- -D warnings

fmt:
  cargo fmt

fmt_check:
  cargo fmt --check

lint: clippy fmt_check

fix:
  cargo fix --allow-dirty --allow-staged
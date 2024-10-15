set export

original_target_dir := env_var_or_default('CARGO_TARGET_DIR', 'target')

export RUSTDOCFLAGS := '-D warnings --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'
export RUSTFLAGS := '--cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"'
export CARGO_TARGET_DIR := original_target_dir + '/tokio'

build:
  cargo build

build_release:
  cargo build --release

test *ARGS:
  cargo nextest -- --test-threads 1 --nocapture {{ARGS}}

test_ci *ARGS:
  RUST_LOG=sailfish=debug,tests=debug cargo nextest run --workspace --test-threads 1 {{ARGS}}

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
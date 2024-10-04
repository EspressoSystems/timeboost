set export

async := "async-std"

original_target_dir := env_var_or_default('CARGO_TARGET_DIR', 'target')

@cargo *ARGS:
  echo setting async executor to {{async}}
  export RUSTDOCFLAGS='-D warnings --cfg async_executor_impl="{{async}}" --cfg async_channel_impl="{{async}}"' RUSTFLAGS='--cfg async_executor_impl="{{async}}" --cfg async_channel_impl="{{async}}"' CARGO_TARGET_DIR='{{original_target_dir}}/{{async}}' && cargo {{ARGS}}

@tokio target *ARGS:
  echo setting executor to tokio
  export RUSTDOCFLAGS='-D warnings --cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"' RUSTFLAGS='--cfg async_executor_impl="tokio" --cfg async_channel_impl="tokio"' CARGO_TARGET_DIR='{{original_target_dir}}/tokio' && just {{target}} {{ARGS}}

@async_std target *ARGS:
  echo setting executor to async-std
  export RUST_MIN_STACK=4194304 RUSTDOCFLAGS='-D warnings --cfg async_executor_impl="async-std" --cfg async_channel_impl="async-std"' RUSTFLAGS='--cfg async_executor_impl="async-std" --cfg async_channel_impl="async-std"' CARGO_TARGET_DIR='{{original_target_dir}}/async-std' && just {{target}} {{ARGS}}

@async-std target *ARGS:
  echo setting executor to async-std
  export RUST_MIN_STACK=4194304 RUSTDOCFLAGS='-D warnings --cfg async_executor_impl="async-std" --cfg async_channel_impl="async-std"' RUSTFLAGS='--cfg async_executor_impl="async-std" --cfg async_channel_impl="async-std"' CARGO_TARGET_DIR='{{original_target_dir}}/async-std' && just {{target}} {{ARGS}}

build:
  cargo build

build_release:
  cargo build --release

test *ARGS:
  cargo test {{ARGS}}

run:
  cargo run

clippy:
  cargo clippy -- -D warnings

fmt:
  cargo fmt

fmt_check:
  cargo fmt --check

lint: clippy fmt_check

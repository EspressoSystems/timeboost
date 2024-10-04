build:
  cargo build

build_release:
  cargo build --release

test *ARGS:
  cargo test {{ARGS}}

run:
  cargo run

set export

export RUSTDOCFLAGS := '-D warnings'

####################
###BUILD COMMANDS###
####################

build *ARGS:
  cargo build {{ARGS}}

build_release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

build_docker:
  docker build . -f ./docker/timeboost.Dockerfile -t timeboost:latest

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

####################
####TEST COMMANDS###
####################
test *ARGS:
  cargo nextest run {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test_ci *ARGS:
  RUST_LOG=sailfish=debug,tests=debug cargo nextest run --workspace --retries 3 {{ARGS}}
  RUST_LOG=sailfish=debug,tests=debug cargo test --doc {{ARGS}}


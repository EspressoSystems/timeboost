export RUSTDOCFLAGS := '-D warnings'

log_levels  := "RUST_LOG=timeboost=debug,sailfish=debug,cliquenet=debug,tests=debug"
run_as_root := if env("CI", "") == "true" { "sudo" } else { "run0" }
apikey      := "sEVxPYlY3Rwte9ZApZDZPd-K7TCiZnBlhZp7se8jVWM="
an_host     := "http://127.0.0.1:8545"
an_mnemonic := "test test test test test test test test test test test junk"
km_mnemonic := "attend year erase basket blind adapt stove broccoli isolate unveil acquire category"
km_addr     := "0x36561082951eed7ffd59cfd82d70570c57072d02"
km_contract := "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35"
km_comm_abi := "getCommitteeById(uint64)((uint64,uint64,uint256,(bytes,bytes,bytes,address,string,string)[]))"

build *ARGS:
  cargo build {{ARGS}}

build-release *ARGS:
  cargo build --release --workspace --all-targets {{ARGS}}

[private]
build-port-alloc:
  cargo build --release -p test-utils --bin run --bin port-alloc --no-default-features --features ports

[private]
build-test-utils:
  cargo build --release -p test-utils --all-features

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

fmt-check:
  cargo +nightly fmt --check

lint: clippy fmt-check

fix:
  cargo fix --allow-dirty --allow-staged

docker *args:
  just -f docker/justfile {{args}}

ci-local:
  just build
  just lint
  just test-ci --release
  just run-sailfish-demo
  just test-all
  just test-dyn-comm
  just run-integration
  just docker ci-local

run-sailfish-demo: build-test-utils build-release
  env RUST_LOG=sailfish=info,warn \
  target/release/run --verbose \
      --spawn "1|anvil --port 8545" \
      --run   "2|sleep 3" \
      --run   "3|just deploy-contract {{an_host}}" \
      --run   "4|just register-committee {{an_host}} test-configs/nodes/committees/committee-0.toml" \
      --spawn "5|target/release/sailfish -c test-configs/nodes/21R4uDwS7fdxsNPWy92DArC575sYiQdEasFBVEpH8m53e.toml" \
      --spawn "5|target/release/sailfish -c test-configs/nodes/23as9Uo6W2AeGronB6nMpcbs8Nxo6CoJ769uePw9sf6Ud.toml" \
      --spawn "5|target/release/sailfish -c test-configs/nodes/23oAdU4acQbwSuC6aTEXqwkvQRVCjySzX18JfBNEbHgij.toml" \
      --spawn "5|target/release/sailfish -c test-configs/nodes/29iGhwSi5p4zJn2XgGLCwWVU5rCw7aMM2Xk8aJnYnDweU.toml" \
      target/release/sailfish -- -c test-configs/nodes/eiwaGN1NNaQdbnR9FsjKzUeLghQZsTLPjiL4RcQgfLoX.toml --until 300

run *ARGS:
  cargo run {{ARGS}}

bench *ARGS:
    cargo bench --benches {{ARGS}} -- --nocapture

mkconfig nodes apikey seed="42": build-release
    for i in $(seq 0 $(({{nodes}} - 1))); do \
        target/release/configure \
            --seed "$(({{seed}} + $i))" \
            --bind "127.0.0.1:$((8000 + 10 * $i))" \
            --nitro "127.0.0.1:55000" \
            --batchposter "127.0.0.1:$((8005 + 10 * $i))" \
            --espresso-namespace 10101 \
            --espresso-base-url "https://query.decaf.testnet.espresso.network/v1/" \
            --espresso-websocket-url "wss://query.decaf.testnet.espresso.network/v1/" \
            --espresso-builder-base-url "https://builder.decaf.testnet.espresso.network/v0/" \
            --chain-rpc-url "http://127.0.0.1:8545" \
            --chain-websocket-url "ws://127.0.0.1:8545" \
            --chain-id 31337 \
            --inbox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
            --committee-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
            --auction-contract "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1" \
            --apikey "{{apikey}}" \
            --output "test-configs/nodes"; \
    done

mkconfig-linux nodes apikey seed="42": build-release
    for i in $(seq 0 $(({{nodes}} - 1))); do \
        target/release/configure \
            --seed "$(({{seed}} + $i))" \
            --bind "11.0.0.$((1 + $i)):8000" \
            --nitro "11.0.1.0:55000" \
            --batchposter "11.0.1.0:8005" \
            --espresso-namespace 10101 \
            --espresso-base-url "https://query.decaf.testnet.espresso.network/v1/" \
            --espresso-websocket-url "wss://query.decaf.testnet.espresso.network/v1/" \
            --espresso-builder-base-url "https://builder.decaf.testnet.espresso.network/v0/" \
            --chain-rpc-url "http://11.0.1.0:8545" \
            --chain-websocket-url "ws://11.0.1.0:8545" \
            --chain-id 31337 \
            --inbox-contract "0xa0f3a1a4e2b2bcb7b48c8527c28098f207572ec1" \
            --committee-contract "0x2bbf15bc655c4cc157b769cfcb1ea9924b9e1a35" \
            --auction-contract "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1" \
            --apikey "{{apikey}}" \
            --output "test-configs/linux"; \
    done

verify-blocks *ARGS: build-test-utils
    target/release/block-verifier {{ARGS}}

deploy-contract host:
    just fund {{host}} {{km_addr}} 1ether "{{an_mnemonic}}"
    target/release/contract deploy \
        --index 0 \
        --rpc-url {{host}} \
        --mnemonic "{{km_mnemonic}}"

register-committee host path:
    target/release/contract register-committee \
        --committee {{path}} \
        --index 0 \
        --rpc-url {{host}} \
        --contract {{km_contract}} \
        --mnemonic "{{km_mnemonic}}"

register-key host:
    target/release/contract register-key \
        --index 0 \
        --rpc-url {{host}} \
        --contract {{km_contract}} \
        --apikey "{{apikey}}" \
        --mnemonic "{{km_mnemonic}}"

fund host address amount mnemonic:
    cast send --value {{amount}} \
        --rpc-url {{host}} \
        --mnemonic "{{mnemonic}}" \
        --mnemonic-index 0 \
        {{address}}

bridge host inbox amount mnemonic:
    cast send {{inbox}} "depositEth()" \
        --value {{amount}} \
        --rpc-url {{host}} \
        --mnemonic "{{mnemonic}}" \
        --mnemonic-index 0

fetch-key host contract:
    cast call {{contract}} "thresholdEncryptionKey()" --rpc-url {{host}}

fetch-committee host contract committee_id:
    #!/usr/bin/env bash
    set -euo pipefail
    raw=$(cast call {{contract}} "getCommitteeById(uint64)" {{committee_id}} --rpc-url {{host}})
    cast abi-decode --json "{{km_comm_abi}}" "$raw" | jq

fetch-active host contract:
    #!/usr/bin/env bash
    set -euo pipefail
    committee_id=$(cast call {{contract}} "currentCommitteeId()(uint64)" --rpc-url {{host}})
    just fetch-committee {{host}} {{contract}} $committee_id

test *ARGS: build-port-alloc
  target/release/run --spawn target/release/port-alloc cargo nextest run -- {{ARGS}}
  @if [ "{{ARGS}}" == "" ]; then cargo test --doc; fi

test-ci *ARGS: build-port-alloc
  env {{log_levels}} NO_COLOR=1 target/release/run \
    --spawn target/release/port-alloc \
    cargo nextest run -- --workspace {{ARGS}}
  env {{log_levels}} NO_COLOR=1 cargo test --doc {{ARGS}}

test-individually: build-port-alloc
  @for pkg in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[].name'); do \
    echo "Testing $pkg"; \
    $(target/release/run \
        --spawn target/release/port-alloc \
        cargo nextest run -- --no-tests=pass -p $pkg) || exit 1; \
  done

test-all: build-release build-test-utils
  env RUST_LOG=block_checker=info,error \
  target/release/run \
    --verbose \
    --timeout 120 \
    --spawn "1|anvil --port 8545 --silent" \
    --run   "2|sleep 3" \
    --run   "3|just deploy-contract {{an_host}}" \
    --run   "4|just register-committee {{an_host}} test-configs/nodes/committees/committee-0.toml" \
    --spawn "5|target/release/block-maker --chain test-configs/chain.toml --bind 127.0.0.1:55000" \
    --spawn "6|target/release/run-committee \
        --chain test-configs/chain.toml \
        --committee 0 \
        --nodes test-configs/nodes/ \
        --scenario test-configs/scenarios/rolling-restart.toml \
        --verbose" \
    --run   "7|sleep 3" \
    --run   "8|just register-key {{an_host}}" \
    --spawn "9|target/release/tx-generator \
        --chain test-configs/chain.toml \
        --namespace 10101 \
        --apikey "{{apikey}}"" \
    target/release/block-checker -- \
        --chain test-configs/chain.toml \
        --namespace 10101 \
        --espresso-base-url https://query.decaf.testnet.espresso.network/v1/ \
        --espresso-websocket-base-url wss://query.decaf.testnet.espresso.network/v1/ \
        --blocks 300

test-no-express: build-release build-test-utils
  env RUST_LOG=block_checker=info,error \
  target/release/run \
    --verbose \
    --timeout 180 \
    --spawn "1|anvil --port 8545 --silent" \
    --run   "2|sleep 3" \
    --run   "3|just deploy-contract {{an_host}}" \
    --run   "4|just register-committee {{an_host}} test-configs/no-express/committees/committee-0.toml" \
    --spawn "5|target/release/block-maker --chain test-configs/chain.no-express.toml --bind 127.0.0.1:55000" \
    --spawn "6|target/release/run-committee \
        --chain test-configs/chain.no-express.toml \
        --committee 0 \
        --nodes test-configs/no-express/ \
        --scenario test-configs/scenarios/rolling-restart.toml \
        --verbose" \
    --run   "7|sleep 3" \
    --run   "8|just register-key {{an_host}}" \
    --spawn "9|target/release/tx-generator \
        --chain test-configs/chain.no-express.toml \
        --apikey "{{apikey}}"" \
    target/release/block-checker -- \
        --chain test-configs/chain.toml \
        --namespace 10101 \
        --espresso-base-url https://query.decaf.testnet.espresso.network/v1/ \
        --espresso-websocket-base-url wss://query.decaf.testnet.espresso.network/v1/ \
        --blocks 300

test-dyn-comm: build-release build-test-utils
    env RUST_LOG=block_checker=info,error \
    target/release/run \
        --verbose \
        --timeout 120 \
        --spawn "1|anvil --port 8545 --silent --block-time 1" \
        --run   "2|sleep 3" \
        --run   "3|just deploy-contract {{an_host}}" \
        --run   "4|just register-committee {{an_host}} test-configs/nodes/committees/committee-0.toml" \
        --spawn "5|target/release/run-committee \
            --chain test-configs/chain.toml \
            --committee 0 \
            --nodes test-configs/nodes/ \
            --verbose" \
        --run   "6|sleep 3" \
        --run   "7|just register-key {{an_host}}" \
        --run   "8|just register-committee {{an_host}} test-configs/nodes/committees/committee-1.toml" \
        --run   "9|sleep 3" \
        --spawn "10|target/release/run-committee \
            --chain test-configs/chain.toml \
            --committee 1 \
            --nodes test-configs/nodes/ \
            --verbose" \
        --run   "11|sleep 3" \
        --spawn "12|target/release/block-maker --chain test-configs/chain.toml --bind 127.0.0.1:55000" \
        --spawn "13|target/release/tx-generator \
            --chain test-configs/chain.toml \
            --enc-ratio 1.0 \
            --apikey "{{apikey}}"" \
        target/release/block-checker -- \
            --chain test-configs/chain.toml \
            --namespace 10101 \
            --espresso-base-url https://query.decaf.testnet.espresso.network/v1/ \
            --espresso-websocket-base-url wss://query.decaf.testnet.espresso.network/v1/ \
            --blocks 300

[linux]
forward-ipv4 val: build-test-utils
    {{run_as_root}} target/release/net-setup system --forward-ipv4 {{val}}

[linux]
create-net: build-test-utils
    {{run_as_root}} target/release/net-setup create -c test-configs/net.toml

[linux]
delete-net: build-test-utils
    {{run_as_root}} target/release/net-setup delete -c test-configs/net.toml

[linux]
netsim nodes: build-release build-test-utils
    #!/usr/bin/env bash
    set -eo pipefail
    function run_as_root {
        if [ "$CI" == "true" ]; then
            sudo --preserve-env=PATH,HOME,RUST_LOG "$@"
        else
            run0 --setenv=PATH --setenv=HOME --setenv=RUST_LOG "$@"
        fi
    }
    export RUST_LOG=timeboost_builder::submit=debug,block_checker=info,warn
    run_as_root target/release/run \
        --verbose \
        --timeout 120 \
        --clear-env \
        --env PATH \
        --env HOME \
        --env RUST_LOG \
        --uid $(id -u) \
        --gid $(id -g) \
        --spawn "1|anvil --host 11.0.1.0 --port 8545 --silent" \
        --run   "2|sleep 3" \
        --run   "3|just deploy-contract 11.0.1.0:8545" \
        --run   "4|just register-committee 11.0.1.0:8545 test-configs/linux/committees/linux-{{nodes}}.toml" \
        --spawn "5|target/release/block-maker \
            --chain test-configs/chain.linux.toml \
            --bind 11.0.1.0:55000" \
        --spawn-as-root "6|target/release/run-committee \
            -u $(id -u) \
            -g $(id -g) \
            --chain test-configs/chain.linux.toml \
            --committee 0 \
            --nodes test-configs/linux/ \
            --net test-configs/net.toml \
            --scenario test-configs/scenarios/default.toml \
            --verbose" \
        --run   "7|sleep 3" \
        --run   "8|just register-key 11.0.1.0:8545" \
        --spawn "9|target/release/tx-generator \
            --chain test-configs/chain.linux.toml \
            --apikey "{{apikey}}"" \
        target/release/block-checker -- \
            --chain test-configs/chain.linux.toml \
            --namespace 10101 \
            --espresso-base-url https://query.decaf.testnet.espresso.network/v1/ \
            --espresso-websocket-base-url wss://query.decaf.testnet.espresso.network/v1/ \
            --blocks 300

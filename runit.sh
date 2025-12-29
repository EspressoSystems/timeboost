#!/bin/bash
set -euo pipefail

# for i in $(seq 0 3); do
#     batch_poster_port=$((8547 + i * 10))
#     echo "Running configure for node $i with seed $((42 + i)) and batch poster port ${batch_poster_port}"
#     cargo run --release --bin configure -- \
#         --seed $((42 + i)) \
#         --bind "0.0.0.0:8000" \
#         --external "node$i:8000" \
#         --nitro "nitro$i:55000" \
#         --batchposter "http://host.docker.internal:${batch_poster_port}" \
#         --espresso-namespace 412346 \
#         --espresso-base-url "http://espresso-dev-node:41000/v1/" \
#         --espresso-websocket-url "ws://espresso-dev-node:41000/v1/" \
#         --stamp-dir "/tmp" \
#         --output "/home/luke/timeboost-config"
# done

# cargo run --release --bin assemble -- \
#     --committee 0 \
#     --start 2025-10-01T00:00:00Z \
#     --output /home/luke/timeboost-config/chain.toml \
#     /home/luke/timeboost-config/*.public.toml

cargo run --release --bin contract -- register-key \
          --index 0 \
          --rpc-url "https://eth-sepolia.g.alchemy.com/v2/fPbE6uMeRsz0XwiNLEmQ8XeT30VCV_Ks" \
          --contract "0xc92C6b91Fe721AE1110183067B76E5348f3Bb59e" \
          --apikey "qJk2e1Eb-6rDB9ifuDMKrjn9beYJQcc9QXb_1GZCHR0=" \
          --mnemonic "chalk uniform spike dog health opera delay rabbit used mosquito keep denial"
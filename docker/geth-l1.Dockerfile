FROM ghcr.io/espressosystems/geth-l1:main
COPY docker/geth-config/genesis-default.json /genesis.json
COPY docker/geth-config/test-jwt-secret.txt /config/test-jwt-secret.txt

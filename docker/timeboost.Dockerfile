FROM rust:bookworm AS builder
SHELL ["/bin/bash", "-c"]

WORKDIR /app

COPY . .
RUN apt update && apt-get install -y protobuf-compiler libssl-dev jq
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"
RUN forge --version
RUN rustup component add rustfmt --toolchain nightly

RUN cargo build --release --bins

FROM debian:bookworm-slim

WORKDIR /app

RUN apt update && apt-get install -y libcurl4 openssl jq

RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

COPY --from=builder /app/target/release/timeboost .
COPY --from=builder /app/target/release/yapper .
COPY --from=builder /app/target/release/register .
COPY --from=builder /app/target/release/deploy .
COPY --from=builder /app/target/release/block-maker .
COPY --from=builder /app/target/release/block-checker .
COPY --from=builder /app/target/release/block-verifier .
COPY --from=builder /app/target/release/mkconfig .
COPY --from=builder /app/scripts/deploy-contract /app/scripts/deploy-contract

COPY --from=builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=builder /root/.foundry/bin/cast /usr/local/bin/cast
RUN chmod +x /usr/local/bin/forge /usr/local/bin/cast

RUN chown -R timeboostuser:appgroup /app && chmod +x \
    /app/timeboost \
    /app/yapper \
    /app/register \
    /app/deploy \
    /app/block-maker \
    /app/block-checker \
    /app/block-verifier \
    /app/mkconfig \
    /app/scripts/deploy-contract

USER timeboostuser

ENV RUST_LOG=sailfish=debug,timeboost=debug,cliquenet=error

CMD ["/app/timeboost"]

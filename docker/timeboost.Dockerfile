FROM rust:bookworm AS builder
SHELL ["/bin/bash", "-c"]

WORKDIR /app

COPY .. .
RUN apt update && apt-get install -y libssl-dev jq
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"
RUN cargo build --release --bins

FROM debian:bookworm-slim

WORKDIR /app

RUN apt update && apt-get install -y libcurl4 openssl jq

RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

COPY --from=builder /app/target/release/timeboost .
COPY --from=builder /app/target/release/tx-generator .
COPY --from=builder /app/target/release/contract .
COPY --from=builder /app/target/release/block-maker .
COPY --from=builder /app/target/release/block-checker .
COPY --from=builder /app/target/release/block-verifier .
COPY --from=builder /app/target/release/configure .
COPY --from=builder /app/target/release/funder .
COPY --from=builder /app/target/release/assemble .

COPY --from=builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=builder /root/.foundry/bin/cast /usr/local/bin/cast
RUN chmod +x /usr/local/bin/forge /usr/local/bin/cast

RUN chown -R timeboostuser:appgroup /app && chmod +x \
    /app/timeboost \
    /app/tx-generator \
    /app/contract \
    /app/block-maker \
    /app/block-checker \
    /app/block-verifier \
    /app/configure \
    /app/funder \
    /app/assemble

USER timeboostuser

ENV RUST_LOG=sailfish=debug,timeboost=debug,cliquenet=error

CMD ["/app/timeboost"]

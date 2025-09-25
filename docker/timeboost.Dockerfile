# Builder stage
FROM rust:bookworm AS builder
SHELL ["/bin/bash", "-c"]

WORKDIR /app

COPY . .
RUN apt update && apt-get install -y protobuf-compiler libssl-dev
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"
RUN forge --version
RUN rustup component add rustfmt --toolchain nightly

RUN cargo build --release --bins

# Non-root app container stage
FROM debian:bookworm-slim

WORKDIR /app

RUN apt update && apt-get install -y libcurl4 openssl

# Create non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

# Copy binary
COPY --from=builder /app/target/release/timeboost .
COPY --from=builder /app/target/release/yapper .
COPY --from=builder /app/target/release/register .
COPY --from=builder /app/target/release/deploy .
COPY --from=builder /app/target/release/block-maker .
COPY --from=builder /app/target/release/block-checker .
COPY --from=builder /app/scripts/deploy-contract .

COPY --from=builder /app/test-configs/docker .

# Copy Foundry binaries from builder
COPY --from=builder /root/.foundry/bin/forge /usr/local/bin/forge
COPY --from=builder /root/.foundry/bin/cast /usr/local/bin/cast
RUN chmod +x /usr/local/bin/forge /usr/local/bin/cast

# Set ownership of application files and make binary executable
RUN chown -R timeboostuser:appgroup /app && chmod +x \
    /app/timeboost \
    /app/yapper \
    /app/register \
    /app/deploy \
    /app/deploy-contract \
    /app/block-maker \
    /app/block-checker

# Switch to non-root user
USER timeboostuser

# Set the log level to debug by default
ENV RUST_LOG=${RUST_LOG:-sailfish=debug,timeboost=debug,cliquenet=error}

# Run the timeboost binary
CMD ["/app/timeboost"]

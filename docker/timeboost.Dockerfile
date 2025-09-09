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

RUN cargo build --release --bin timeboost

# Non-root app container stage
FROM debian:bookworm-slim

WORKDIR /app

RUN apt update && apt-get install -y libcurl4 openssl

# Create non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

# Copy binary
COPY --from=builder /app/target/release/timeboost .
COPY --from=builder /app/test-configs/docker .

# Set ownership of application files and make binary executable
RUN chown -R timeboostuser:appgroup /app && chmod +x /app/timeboost

# Switch to non-root user
USER timeboostuser

# Set the log level to debug by default
ENV RUST_LOG=${RUST_LOG:-sailfish=debug,timeboost=debug,cliquenet=error}

EXPOSE ${TIMEBOOST_SAILFISH_PORT}
EXPOSE ${TIMEBOOST_DECRYPT_PORT}
EXPOSE ${TIMEBOOST_CERTIFIER_PORT}
EXPOSE ${TIMEBOOST_RPC_PORT}
EXPOSE ${TIMEBOOST_METRICS_PORT}

# Run the timeboost binary
CMD ["/app/timeboost"]

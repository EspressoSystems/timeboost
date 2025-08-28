# Builder stage
FROM rust:bookworm AS builder

WORKDIR /app

COPY . .
RUN apt update && apt-get install -y protobuf-compiler
RUN curl -L https://foundry.paradigm.xyz | bash && /root/.foundry/bin/foundryup
ENV PATH="/root/.foundry/bin:${PATH}"
RUN forge --version
RUN rustup component add rustfmt --toolchain nightly
RUN cargo build --release --bin yapper

# Non-root app container stage
FROM debian:bullseye-slim

WORKDIR /app

RUN apt update && apt-get install -y libcurl4

# Create non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup yapperuser

# Copy binary and just
COPY --from=builder /app/target/release/yapper .
COPY --from=builder /app/test-configs/docker .

# Set ownership of application files and make binary executable
RUN chown -R yapperuser:appgroup /app && chmod +x /app/yapper

# We need curl for the healthcheck
RUN apt update && apt-get install -y openssl

# Switch to non-root user
USER yapperuser

# Set the log level to debug by default
ENV RUST_LOG=info

# Run the timeboost binary
CMD ["/app/yapper"]

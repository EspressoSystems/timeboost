# Builder stage
FROM rust:bullseye AS builder

WORKDIR /app

COPY . .

RUN cargo build --release --bin timeboost

# Non-root app container stage
FROM debian:bullseye-slim

WORKDIR /app

# Create non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

# Copy binary
COPY --from=builder /app/target/release/timeboost .
COPY --from=builder /app/test-configs .

# Set ownership of application files and make binary executable
RUN chown -R timeboostuser:appgroup /app && chmod +x /app/timeboost

# Switch to non-root user
USER timeboostuser

# Set the log level to debug by default
ENV RUST_LOG=${RUST_LOG:-sailfish=debug,timeboost=debug,cliquenet=error}

EXPOSE ${TIMEBOOST_SAILFISH_PORT}
EXPOSE ${TIMEBOOST_DECRYPT_PORT}
EXPOSE ${TIMEBOOST_PRODUCER_PORT}
EXPOSE ${TIMEBOOST_RPC_PORT}
EXPOSE ${TIMEBOOST_METRICS_PORT}

# Run the timeboost binary
CMD ["/app/timeboost"]

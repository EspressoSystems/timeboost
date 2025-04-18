# Builder stage
FROM rust:bullseye AS builder

WORKDIR /app

COPY . .

RUN cargo install just

RUN just build_release

# Non-root app container stage
FROM debian:bullseye-slim

WORKDIR /app

# Create non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup timeboostuser

# Copy binary and just
COPY --from=builder /app/target/release/timeboost .
COPY --from=builder /app/test-configs .

# Set ownership of application files and make binary executable
RUN chown -R timeboostuser:appgroup /app && chmod +x /app/timeboost

# We need curl for the healthcheck
RUN apt update && apt install -yqq curl

# Switch to non-root user
USER timeboostuser

# Set the log level to debug by default
ENV RUST_LOG=${RUST_LOG:-sailfish=debug,timeboost=debug,cliquenet=error}

EXPOSE ${TIMEBOOST_PORT}
EXPOSE ${TIMEBOOST_RPC_PORT}
EXPOSE ${TIMEBOOST_METRICS_PORT}

# Run the timeboost binary
CMD ["/app/timeboost"]
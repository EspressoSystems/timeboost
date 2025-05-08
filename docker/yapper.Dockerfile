# Builder stage
FROM rust:bullseye AS builder

WORKDIR /app

COPY . .

RUN cargo build --release --bin yapper

# Non-root app container stage
FROM debian:bullseye-slim

WORKDIR /app

# Create non-root user and group
RUN groupadd -r appgroup && useradd -r -g appgroup yapperuser

# Copy binary and just
COPY --from=builder /app/target/release/yapper .
COPY --from=builder /app/test-configs .

# Set ownership of application files and make binary executable
RUN chown -R yapperuser:appgroup /app && chmod +x /app/yapper

# We need curl for the healthcheck
RUN apt update && apt install -yqq curl

# Switch to non-root user
USER yapperuser

# Set the log level to debug by default
ENV RUST_LOG=info

# Run the timeboost binary
CMD ["/app/yapper"]
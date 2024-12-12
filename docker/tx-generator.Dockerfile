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
RUN groupadd -r appgroup && useradd -r -g appgroup txgeneratoruser

# Copy binary and just
COPY --from=builder /app/target/release/tx-generator .

# Set ownership of application files and make binary executable
RUN chown -R txgeneratoruser:appgroup /app && chmod +x /app/tx-generator

# Switch to non-root user
USER txgeneratoruser

# Set the log level to debug by default
ENV RUST_LOG=${RUST_LOG:-debug}


# Run the timeboost binary
CMD ["tx-generator"]
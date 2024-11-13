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
COPY --from=builder /app/target/tokio/release/timeboost .

# Grab our example_config.toml
COPY --from=builder /app/example_config.toml .

# Set ownership of application files and make binary executable
RUN chown -R timeboostuser:appgroup /app && chmod +x /app/timeboost

# Switch to non-root user
USER timeboostuser

# Set the log level to debug
ENV RUST_LOG=${RUST_LOG:-sailfish=debug,timeboost=debug}

# Run the timeboost binary
CMD ["timeboost"]
# Multi-stage build for minimal image size
FROM golang:1.25.12-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=${VERSION:-dev}" \
    -o sentinelflow \
    ./cmd/sentinelflow

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    openssh-client \
    && update-ca-certificates

# Create non-root user
RUN addgroup -S sentinelflow && adduser -S sentinelflow -G sentinelflow

WORKDIR /workspace

# Copy binary from builder
COPY --from=builder /build/sentinelflow /usr/local/bin/sentinelflow

# Copy default policies
COPY policies /policies

# Set ownership
RUN chown -R sentinelflow:sentinelflow /workspace

# Switch to non-root user
USER sentinelflow

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s \
    CMD sentinelflow version || exit 1

# Default command
ENTRYPOINT ["sentinelflow"]
CMD ["--help"]

# Metadata
LABEL org.opencontainers.image.title="SentinelFlow"
LABEL org.opencontainers.image.description="CI/CD Security Gatekeeper"
LABEL org.opencontainers.image.source="https://github.com/cozygarage/sentinelflow"
LABEL org.opencontainers.image.vendor="SentinelFlow"

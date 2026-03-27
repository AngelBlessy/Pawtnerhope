# ---------- Builder Stage ----------
ARG GO_VERSION=1.21
FROM golang:${GO_VERSION}-bookworm AS builder

WORKDIR /app

# Cache dependencies first
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o run-app .


# ---------- Runtime Stage ----------
FROM debian:bookworm-slim

# Install CA certificates for MongoDB Atlas TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m appuser

WORKDIR /app

# Copy binary
COPY --from=builder /app/run-app /usr/local/bin/run-app

# Copy static HTML files
COPY --from=builder /app/*.html /app/

# Change ownership
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["run-app"]

# Multi-stage build for podmaker-vault-bridge.
# Result: ~12 MB Alpine image, statically linked (CGO disabled),
# non-root user, /data writable for the on-disk mTLS cert bundle.

ARG GO_VERSION=1.25
ARG VERSION=dev

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vault-bridge-agent \
    ./cmd/vault-bridge-agent

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget \
 && addgroup -S bridge \
 && adduser -S -G bridge -h /data bridge \
 && mkdir -p /data \
 && chown -R bridge:bridge /data
USER bridge
WORKDIR /data
COPY --from=build /out/vault-bridge-agent /usr/local/bin/podmaker-vault-bridge

# mTLS cert bundle persists across container restarts. Mount a
# volume here unless the bridge is ephemeral.
VOLUME ["/data"]
ENV PODMAKER_BRIDGE_CERT_DIR=/data \
    PODMAKER_BRIDGE_METRICS_ADDR=0.0.0.0:7768

# Prometheus scrape port.
EXPOSE 7768

# The metrics surface doubles as a liveness probe — it ships a
# trivial /healthz that returns 200 once the agent is up. Probes
# every 30s, fails after 3 misses (so ~1.5 minutes of bad readings
# before Docker marks the container unhealthy).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:7768/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/podmaker-vault-bridge"]

# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Build the React Studio SPA bundle
# ==============================================================================
FROM node:22-bookworm-slim AS web-builder
WORKDIR /src/web

COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY web/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Build the Go / CGO (DuckDB) gateway binary with embedded SPA
# ==============================================================================
FROM golang:1.25-bookworm AS go-builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
COPY --from=web-builder /src/web/dist ./web/dist

RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/faradaiwire ./cmd/faradaiwire

# ==============================================================================
# Stage 3: Minimal Containerized Security Gateway runtime (zero Node/Python/Git)
# ==============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 faradai \
    && useradd --uid 10001 --gid faradai --home-dir /data --shell /usr/sbin/nologin faradai \
    && mkdir -p /data /etc/faradaiwire \
    && chown -R 10001:10001 /data

COPY --from=go-builder /out/faradaiwire /usr/local/bin/faradaiwire
COPY config.example.yaml /etc/faradaiwire/config.example.yaml

ENV FARADAI_WIRE_HOME=/data \
    FARADAI_WIRE_HOST=0.0.0.0 \
    FARADAI_WIRE_ADMIN_HOST=0.0.0.0 \
    FARADAI_WIRE_ALLOW_STDIO=false \
    FARADAI_WIRE_ALLOW_LOCAL_TARGETS=true

WORKDIR /data
VOLUME ["/data"]
EXPOSE 19410 19415

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${FARADAI_WIRE_PORT:-19410} && printf 'GET /health HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && grep -q '200 OK' <&3"]

USER 10001:10001
ENTRYPOINT ["faradaiwire"]
CMD ["run", "--standalone"]

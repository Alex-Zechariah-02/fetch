# syntax=docker/dockerfile:1

# The Fetch image: the shop's build and the demo, services and Accounts
# programs, run as a non-root user. demo up -role fetch -programs /opt/fetch
# serves them over TLS that admits only the gateway's client certificate (the
# fetch folder of demo certs, mounted read-only); every run starts from seed
# in a temporary folder, so the root filesystem stays read-only.
# Base images are pinned by digest; the tags show which release each is.

FROM node:24.21.0-trixie-slim@sha256:173f125896c3b47ddf056734c7ea789d04595a6a08769a8f78e0df642781fb66 AS shop
WORKDIR /src/client
COPY client/package.json client/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY e2e/package.json e2e/ports.ts /src/e2e/
COPY client/index.html client/tsconfig.json client/vite.config.ts ./
COPY client/src ./src
RUN npm run build

FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS programs
# The toolchain is go.mod's toolchain line, so the build never downloads one.
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/demo ./cmd/services ./cmd/accounts
COPY --from=shop /src/client/dist /out/shop

# The nonroot user of this image is UID and GID 65532 (its /etc/passwd).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG REVISION=""
LABEL org.opencontainers.image.title="Fetch" \
      org.opencontainers.image.description="Example shop and REST APIs for APIWard" \
      org.opencontainers.image.source="https://github.com/Alex-Zechariah-02/fetch" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=programs /out /opt/fetch
USER 65532:65532
EXPOSE 9501-9506
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --start-interval=2s --retries=3 \
    CMD ["/opt/fetch/demo", "health"]
ENTRYPOINT ["/opt/fetch/demo"]

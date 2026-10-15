# syntax=docker/dockerfile:1.7
#
# Build:   docker build -t tsidp:local .
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/you/tsidp:dev --push .
#
# The binary is linked statically against musl so the final image can be
# distroless/static: no libc, no OpenSSL, no libstdc++, nothing for a
# scanner to find except the binary itself. It runs as uid 65532 like the
# tailscale/tailscale image does in userspace mode, so both containers in a
# pod can share the LocalAPI socket with write access.

ARG RUST_VERSION=1
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-bookworm AS builder
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src

# musl targets; arm64 is cross-compiled from the build host with the GNU
# cross toolchain acting as linker and C compiler (ring's C code).
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends musl-tools; \
    case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl > /rust-target ;; \
      arm64) echo aarch64-unknown-linux-musl > /rust-target; \
             apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    rustup target add "$(cat /rust-target)"; \
    rm -rf /var/lib/apt/lists/*
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=yes -C target-feature=+crt-static" \
    CC_aarch64_unknown_linux_musl=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_musl=aarch64-linux-gnu-ar \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static"

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=tsidp-target-$TARGETARCH \
    set -eux; T="$(cat /rust-target)"; \
    TSIDP_VERSION="$VERSION" cargo build --release --locked --target "$T"; \
    cp "target/$T/release/tsidp-server" /tsidp-server; mkdir -p /data; \
    # Fail the build if anything is dynamically linked after all.
    readelf -d /tsidp-server > /tmp/dynsec 2>&1 || true; \
    if grep -q NEEDED /tmp/dynsec; then echo "binary is not static:" >&2; cat /tmp/dynsec >&2; exit 1; fi

# Release artifacts: `docker buildx build --target binary --output type=local,dest=out .`
# leaves just the static binary in ./out, for the GitHub Release tarballs.
FROM scratch AS binary
COPY --from=builder /tsidp-server /tsidp-server

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/abrar-uddin/tsidp-rust" \
      org.opencontainers.image.description="Tailscale OIDC identity provider (Rust, sidecar/Kubernetes friendly)" \
      org.opencontainers.image.licenses="BSD-3-Clause"
COPY --from=builder /tsidp-server /tsidp-server
# /data is the conventional state dir; make it owned by nonroot so a plain
# `docker run -v tsidp-data:/data` works without a chown dance (issues #113/#114).
COPY --from=builder --chown=65532:65532 /data /data
USER 65532:65532
ENV TSIDP_STATE_DIR=/data \
    TSIDP_LISTEN=127.0.0.1:8443 \
    TSIDP_ADMIN_LISTEN=0.0.0.0:9464
EXPOSE 8443 8080 9464
# readiness, not liveness: fails while tailscaled is not Running
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s CMD ["/tsidp-server", "--check-ready"]
ENTRYPOINT ["/tsidp-server"]

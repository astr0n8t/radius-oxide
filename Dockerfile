# syntax=docker/dockerfile:1

# Builds fully static musl binaries for every target platform natively on the
# build host (no QEMU, no C cross toolchains: rustup's bundled rust-lld does the
# linking), caches compiled dependencies in their own layer via cargo-chef, and
# ships the result on distroless/static.

FROM --platform=$BUILDPLATFORM lukemathwalker/cargo-chef:0.1.78-rust-slim AS chef
WORKDIR /app

# Produce a dependency-only recipe; it only changes when Cargo.toml/Cargo.lock do.
FROM chef AS planner
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG TARGETPLATFORM

# Map the docker platform to a static musl rust target.
RUN case "$TARGETPLATFORM" in \
      linux/amd64)  target=x86_64-unknown-linux-musl ;; \
      linux/arm64)  target=aarch64-unknown-linux-musl ;; \
      linux/arm/v7) target=armv7-unknown-linux-musleabihf ;; \
      linux/arm/v6) target=arm-unknown-linux-musleabihf ;; \
      *) echo "unsupported platform: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac && \
    echo "$target" > /rust-target && \
    rustup target add "$target"

ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld \
    CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER=rust-lld

# Build dependencies only. This layer is reused until the recipe changes.
COPY --from=planner /app/recipe.json recipe.json
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo chef cook --release --target "$(cat /rust-target)" --recipe-path recipe.json

# Build the application itself.
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release --target "$(cat /rust-target)" && \
    cp "target/$(cat /rust-target)/release/radius-oxide" /radius-oxide

FROM gcr.io/distroless/static-debian12:nonroot

LABEL app="radius-oxide"
LABEL org.opencontainers.image.source="https://github.com/astr0n8t/radius-oxide"

ENV RUST_LOG=info

COPY --from=builder /radius-oxide /radius-oxide

USER nonroot:nonroot

ENTRYPOINT ["/radius-oxide"]

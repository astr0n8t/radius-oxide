# Build Stage
ARG BUILDPLATFORM
FROM --platform=${BUILDPLATFORM} rust:latest as rust-source
FROM --platform=${BUILDPLATFORM} ghcr.io/cross-rs/x86_64-unknown-linux-gnu:edge as build_amd64
FROM --platform=${BUILDPLATFORM} ghcr.io/cross-rs/aarch64-unknown-linux-gnu:edge as build_arm64
FROM --platform=${BUILDPLATFORM} ghcr.io/cross-rs/armv7-unknown-linux-gnueabi:edge as build_armv7
FROM --platform=${BUILDPLATFORM} ghcr.io/cross-rs/arm-unknown-linux-gnueabi:edge as build_arm

ARG TARGETARCH
ARG TARGETVARIANT
FROM --platform=${BUILDPLATFORM} build_${TARGETARCH}${TARGETVARIANT} as builder

COPY --from=rust-source /usr/local/rustup /usr/local
COPY --from=rust-source /usr/local/cargo /usr/local

RUN rustup default stable

LABEL app="radius-oxide"
LABEL REPO="https://github.com/astr0n8t/radius-oxide"

WORKDIR /app

ARG TARGETPLATFORM
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then rustup target add x86_64-unknown-linux-gnu; fi

RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then rustup target add aarch64-unknown-linux-gnu; fi

RUN if [ "$TARGETPLATFORM" = "linux/arm" ]; then rustup target add arm-unknown-linux-gnueabi; fi

RUN if [ "$TARGETPLATFORM" = "linux/armv7" ]; then rustup target add armv7-unknown-linux-gnueabi; fi

# create a new empty project
RUN cargo init

COPY ./src src
COPY Cargo.toml ./

# Translate docker platforms to rust platforms
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
        cargo build --release --target x86_64-unknown-linux-gnu; \
        cp /app/target/x86_64-unknown-linux-gnu/release/radius-oxide /app/radius-oxide; \
 fi

RUN if [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        cargo build --release --target aarch64-unknown-linux-gnu; \
        cp /app/target/aarch64-unknown-linux-gnu/release/radius-oxide /app/radius-oxide; \
 fi

RUN if [ "$TARGETPLATFORM" = "linux/armv7" ]; then \
        cargo build --release --target armv7-unknown-linux-gnueabi; \
        cp /app/target/armv7-unknown-linux-gnueabi/release/radius-oxide /app/radius-oxide; \
 fi

RUN if [ "$TARGETPLATFORM" = "linux/arm" ]; then \
        cargo build --release --target arm-unknown-linux-gnueabi; \
        cp /app/target/arm-unknown-linux-gnueabi/release/radius-oxide /app/radius-oxide; \
 fi

# second stage.
FROM gcr.io/distroless/cc-debian12 as build-release-stage

ENV RUST_LOG=info

COPY --from=builder /app/radius-oxide /radius-oxide

USER nonroot:nonroot

ENTRYPOINT ["/radius-oxide"]

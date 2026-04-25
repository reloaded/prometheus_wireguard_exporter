# Forked from upstream `MindFlavor/prometheus_wireguard_exporter`'s
# Dockerfile. Differences vs. upstream:
#   - Drops the musl.cc cross-toolchain dance. The upstream Dockerfile
#     fetched musl-cross tarballs from `https://musl.cc` per target
#     triple at build time; that service has flaky availability and
#     occasionally returns HTML error pages that make `tar -xz` fail.
#     Using `rust:1-alpine` per-target means rustc + musl-gcc come
#     from Alpine packages and Docker buildx + QEMU does the
#     cross-arch emulation transparently. Slower in CI than native
#     cross-compile, but reliable.
#   - Bumps `actions/checkout`-style tooling stays in the workflow,
#     not here.

ARG ALPINE_VERSION=3.20
ARG RUST_VERSION=1

FROM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS base
WORKDIR /usr/src/prometheus_wireguard_exporter

# musl-dev for the alpine static-link toolchain; `file` for the
# build-stage sanity check.
RUN apk add --no-cache --q musl-dev file

# Pre-fetch cargo deps with a placeholder src/main.rs so layer cache
# survives source edits.
RUN mkdir src && echo 'fn main() {}' > src/main.rs
COPY Cargo.toml Cargo.lock ./
RUN cargo fetch && rm src/main.rs

# Build the dep cache once with the placeholder still in place — same
# trick as upstream, just without the musl-cross indirection.
RUN echo 'fn main() {}' > src/main.rs && \
    cargo build --release && \
    rm -rf target/release/deps/prometheus_wireguard_exporter* \
           target/release/prometheus_wireguard_exporter* \
           src/main.rs

COPY . .

# Lint stage — `docker build --target lint` runs clippy over the
# real source.
FROM base AS lint
RUN rustup component add clippy && cargo clippy --release

# Test stage — `docker build --target test` produces an image whose
# entrypoint runs the test suite. Workflow `verify` job runs it via
# `docker run --rm test-container`.
FROM base AS test
ENTRYPOINT ["cargo", "test", "--release"]

# Build stage — produces a static-ish musl binary (alpine target).
FROM base AS build
RUN cargo build --release && \
    cp target/release/prometheus_wireguard_exporter /tmp/binary && \
    file /tmp/binary

# Final image
FROM alpine:${ALPINE_VERSION}
EXPOSE 9586/tcp
WORKDIR /usr/local/bin
RUN apk add --no-cache --q tini wireguard-tools-wg sudo && \
    rm -rf /var/cache/apk/* && \
    adduser prometheus-wireguard-exporter -s /bin/sh -D -u 1000 1000 && \
    mkdir -p /etc/sudoers.d && \
    echo 'prometheus-wireguard-exporter ALL=(root) NOPASSWD:/usr/bin/wg show * dump' > /etc/sudoers.d/prometheus-wireguard-exporter && \
    chmod 0440 /etc/sudoers.d/prometheus-wireguard-exporter
USER prometheus-wireguard-exporter
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/prometheus_wireguard_exporter"]
CMD [ "-a" ]
COPY --from=build --chown=prometheus-wireguard-exporter /tmp/binary ./prometheus_wireguard_exporter

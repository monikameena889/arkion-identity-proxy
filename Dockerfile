# syntax=docker/dockerfile:1.7

# ---------- build ----------
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bins \
 && mkdir -p /out \
 && cp target/release/arkion-identity-proxy target/release/pki-gen target/release/echo-upstream target/release/loadgen /out/

# ---------- test (docker build --target test .) ----------
FROM build AS test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo test --release --locked

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent arkion \
 && install -d -o 10001 -g 10001 /pki /config
COPY --from=build /out/ /usr/local/bin/
COPY --chmod=0644 config/policy.yaml /config/policy.yaml

ENV LISTEN_ADDR=0.0.0.0:8443 \
    ADMIN_ADDR=0.0.0.0:9901 \
    UPSTREAM_URL=http://backend:8080 \
    TLS_CERT=/pki/server.crt \
    TLS_KEY=/pki/server.key \
    CLIENT_CA_BUNDLE=/pki/trust-bundle.pem \
    POLICY_FILE=/config/policy.yaml \
    LOG_FORMAT=json

USER 10001:10001
EXPOSE 8443 9901
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s CMD curl -fsS http://127.0.0.1:9901/readyz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["arkion-identity-proxy"]

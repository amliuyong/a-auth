# syntax=docker/dockerfile:1
FROM rust:1.96.1-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3 AS build
ARG SOURCE_COMMIT
ENV CARGO_BUILD_JOBS=2
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN test "${#SOURCE_COMMIT}" = 40 && \
    case "$SOURCE_COMMIT" in *[!0-9a-f]*) exit 1;; esac && \
    cargo build -p agent-auth-http --release --locked --no-default-features \
      --features postgres --bin agent-auth-postgres

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG SOURCE_COMMIT
LABEL org.opencontainers.image.source="https://github.com/amliuyong/a-auth" \
      org.opencontainers.image.revision="$SOURCE_COMMIT" \
      org.opencontainers.image.title="a-auth PostgreSQL"
ENV RUST_MIN_STACK=8388608
USER 65532:65532
WORKDIR /
COPY --from=build --chown=65532:65532 /source/target/release/agent-auth-postgres /agent-auth-postgres
EXPOSE 8080 8082
ENTRYPOINT ["/agent-auth-postgres"]
CMD ["serve-web", "/etc/a-auth/runtime/runtime.json"]

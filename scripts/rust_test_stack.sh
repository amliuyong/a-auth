#!/usr/bin/env bash

# AWS-enabled debug tests exercise the full Axum middleware and signing poll
# chain. Keep every Rust integration-test entry point on the same stack policy.
export RUST_MIN_STACK="${RUST_MIN_STACK:-8388608}"

#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
source ./scripts/rust_test_stack.sh

: "${A_AUTH_TEST_DATABASE_URL:?Set a dedicated PostgreSQL 16+ contract-test database URL}"
cargo test -p agent-auth-http --features postgres --test postgres_contracts \
  --locked "$@"

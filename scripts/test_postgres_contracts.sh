#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
source ./scripts/rust_test_stack.sh

: "${A_AUTH_TEST_DATABASE_URL:?Set a dedicated PostgreSQL 16+ contract-test database URL}"
task_contract_features=postgres
if [[ "${A_AUTH_TEST_AWS_ADAPTERS:-0}" == 1 ]]; then
  : "${A_AUTH_TEST_DYNAMODB_ENDPOINT:?Set a loopback DynamoDB endpoint for AWS adapter contracts}"
  task_contract_features=postgres,aws
fi
# Each contract creates its own pool and launches concurrent actors. Bound
# independent contracts so a standard 100-connection test server also has room
# for the twelve-pool cold-migration drill; per-contract contention is unchanged.
RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}" \
cargo test -p agent-auth-http --features "$task_contract_features" --test postgres_contracts \
  --locked "$@"

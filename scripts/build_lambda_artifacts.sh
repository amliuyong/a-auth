#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARIES=(
  agent-auth-lambda
  agent-auth-reclaim
  agent-auth-recompute
  agent-auth-migrate-credentials
  agent-auth-security-event-archive
  agent-auth-ssf-delivery
  agent-auth-tenant-key-provisioner
  agent-auth-governance-worker
)

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

for command in cargo git sha256sum; do
  command -v "$command" >/dev/null || fail "missing command: $command"
done

deployment_commit="$(git -C "$ROOT" rev-parse HEAD)"
[[ "$deployment_commit" =~ ^[0-9a-f]{40}$ ]] ||
  fail "Git HEAD is not a full lowercase commit SHA"
[[ -z "$(git -C "$ROOT" status --porcelain \
  --untracked-files=normal --ignore-submodules=dirty)" ]] ||
  fail "Lambda deployment artifacts require a clean worktree"

for binary in "${BINARIES[@]}"; do
  rm -f "$ROOT/target/lambda/$binary/deployment-provenance.json"
done
cd "$ROOT"
cargo lambda build \
  --release \
  --arm64 \
  --features lambda,aws \
  --locked \
  --bin agent-auth-lambda \
  --bin agent-auth-reclaim \
  --bin agent-auth-recompute \
  --bin agent-auth-migrate-credentials \
  --bin agent-auth-security-event-archive \
  --bin agent-auth-ssf-delivery \
  --bin agent-auth-tenant-key-provisioner \
  --bin agent-auth-governance-worker

[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$deployment_commit" ]] ||
  fail "Git HEAD changed while Lambda artifacts were building"
[[ -z "$(git -C "$ROOT" status --porcelain \
  --untracked-files=normal --ignore-submodules=dirty)" ]] ||
  fail "worktree changed while Lambda artifacts were building"

for binary in "${BINARIES[@]}"; do
  asset="$ROOT/target/lambda/$binary"
  bootstrap="$asset/bootstrap"
  provenance="$asset/deployment-provenance.json"
  [[ -f "$bootstrap" ]] ||
    fail "cargo lambda did not produce the $binary bootstrap"
  bootstrap_sha256="$(sha256sum "$bootstrap" | cut -d' ' -f1)"
  [[ "$bootstrap_sha256" =~ ^[0-9a-f]{64}$ ]] ||
    fail "could not derive the $binary bootstrap SHA-256"
  printf \
    '{"schema":"agent-auth-lambda-provenance-v1","commit":"%s","bootstrap_sha256":"%s"}\n' \
    "$deployment_commit" "$bootstrap_sha256" >"$provenance"
done
printf 'Built Lambda artifacts for %s\n' "$deployment_commit"

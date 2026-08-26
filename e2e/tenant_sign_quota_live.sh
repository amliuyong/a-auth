#!/usr/bin/env bash
# C10.14 live gate: low-contention tenant signing quota isolation.
#
# The gate creates one temporary SPIFFE workload client in each of two active
# SaaS tenants. After both tenants mint a real access token, it conditionally
# exhausts only tenant A's shared KMS-sign bucket. Tenant A must receive 503
# with Retry-After while tenant B still mints a token. Shared bucket rows are
# restored only when their versions prove no unrelated writer intervened.
set -euo pipefail
set +x
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${SAAS_STACK:-AgentAuthSaas}"
TENANT_A="${TENANT_A:-t1}"
TENANT_B="${TENANT_B:-t3}"
EXPECTED_COMMIT="${EXPECTED_COMMIT:?set EXPECTED_COMMIT to the full deployed SHA}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c10-14-evidence-$(date -u +%Y%m%dT%H%M%SZ).json}"
SCOPE="kb:read"

for command in aws cmp curl git jq python3 sed seq sha256sum sleep; do
  command -v "$command" >/dev/null ||
    { echo "missing required command: $command" >&2; exit 1; }
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
  { echo "EXPECTED_COMMIT must be a full lowercase Git SHA" >&2; exit 1; }
for tenant in "$TENANT_A" "$TENANT_B"; do
  [[ "$tenant" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] ||
    { echo "invalid tenant ID" >&2; exit 1; }
done
[[ "$TENANT_A" != "$TENANT_B" ]] ||
  { echo "tenant IDs must differ" >&2; exit 1; }

check_ok() { printf 'OK: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

WORK="$(mktemp -d)"
SECRETS="$WORK/secrets"
mkdir -m 700 "$SECRETS"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
RESOURCE="https://c10-14-$RUN_ID.invalid"
BUNDLE_KEY="assets/c10-14-$RUN_ID.json"
KEY_FILE="$SECRETS/signing-key.pem"
JWKS_FILE="$WORK/jwks.json"
FRONTEND_BUCKET=""
CLIENT_A=""
CLIENT_B=""
CLIENT_A_INTENT=0
CLIENT_B_INTENT=0
REDIRECT_A="https://c10-14-a-$RUN_ID.invalid/cb"
REDIRECT_B="https://c10-14-b-$RUN_ID.invalid/cb"
BINDING_A="c10-14-a-$RUN_ID"
BINDING_B="c10-14-b-$RUN_ID"
TD_A="c10-14-a-$RUN_ID.spiffe.test"
TD_B="c10-14-b-$RUN_ID.spiffe.test"
TENANT_A_BUCKET="kms-sign-tenant:$TENANT_A"
TENANT_B_BUCKET="kms-sign-tenant:$TENANT_B"
BUCKETS_MUTATED=0
CLEANED=0

tpk() {
  local tenant="$1" value="$2"
  printf '%s\x1f%s' "$tenant" "$value"
}

dynamo_item_absent() {
  local response_file="$1"
  [[ ! -s "$response_file" ]] ||
    jq -e 'has("Item") | not' "$response_file" >/dev/null
}

recover_client_id() {
  local tenant="$1" redirect="$2" output="$3"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --consistent-read --page-size 100 \
    --projection-expression 'client_id,redirect_uris' --output json >"$output" ||
    return 1
  jq -er --arg tenant "$tenant" --arg redirect "$redirect" '
    [.Items[]?
     | select(any(.redirect_uris.L[]?; .S == $redirect))
     | .client_id.S
     | select(startswith($tenant + "\u001f"))
     | split("\u001f")[1]]
    | if length == 0 then "__absent__"
      elif length == 1 then .[0]
      else error("multiple clients matched the unique redirect")
      end
  ' "$output"
}

snapshot_bucket() {
  local key="$1" output="$2"
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
    --key "$(jq -cn --arg key "$key" '{key:{S:$key}}')" \
    --consistent-read --output json >"$output"
}

bucket_version() {
  local snapshot="$1"
  jq -er 'if has("Item") then .Item.version.N | tonumber else 0 end' "$snapshot"
}

restore_bucket() {
  local key="$1" before="$2" expected_version="$3"
  if jq -e 'has("Item")' "$before" >/dev/null; then
    aws dynamodb put-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
      --item "$(jq -c '.Item' "$before")" \
      --condition-expression 'version = :expected' \
      --expression-attribute-values "$(jq -cn --arg version "$expected_version" \
        '{":expected":{N:$version}}')" >/dev/null
  else
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
      --key "$(jq -cn --arg key "$key" '{key:{S:$key}}')" \
      --condition-expression 'version = :expected' \
      --expression-attribute-values "$(jq -cn --arg version "$expected_version" \
        '{":expected":{N:$version}}')" >/dev/null
  fi
}

restore_bucket_if_owned() {
  local key="$1" before="$2" min_version="$3" max_version="$4" label="$5"
  local current="$WORK/$label-current.json" current_version
  snapshot_bucket "$key" "$current" || return 1
  jq -S '.Item // null' "$before" >"$WORK/$label-before.item"
  jq -S '.Item // null' "$current" >"$WORK/$label-current.item"
  if cmp "$WORK/$label-before.item" "$WORK/$label-current.item" >/dev/null; then
    return 0
  fi
  jq -e 'has("Item")' "$current" >/dev/null || return 1
  current_version="$(bucket_version "$current")"
  [[ "$current_version" -ge "$min_version" &&
    "$current_version" -le "$max_version" ]] || return 1
  restore_bucket "$key" "$before" "$current_version"
}

best_effort_fixture_cleanup() {
  local label tenant binding client_var redirect intent client recovered had_errexit=0
  [[ $- == *e* ]] && had_errexit=1
  set +e
  for tuple in \
    "a|$TENANT_A|$BINDING_A|CLIENT_A|$REDIRECT_A|$CLIENT_A_INTENT" \
    "b|$TENANT_B|$BINDING_B|CLIENT_B|$REDIRECT_B|$CLIENT_B_INTENT"; do
    IFS='|' read -r label tenant binding client_var redirect intent <<<"$tuple"
    client="${!client_var}"
    if [[ "$intent" == "1" && -z "$client" && -n "${CLIENTS_TABLE:-}" ]]; then
      recovered="$(recover_client_id "$tenant" "$redirect" \
        "$WORK/client-$label-recovery.json")"
      if [[ "$recovered" != "__absent__" ]]; then
        client="$recovered"
        printf -v "$client_var" '%s' "$client"
      fi
    fi
    if [[ -n "${TRUST_TABLE:-}" ]]; then
      aws dynamodb delete-item \
        --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" \
        --key "$(jq -cn --arg key "$(tpk "$tenant" "$binding")" \
          '{binding_id:{S:$key}}')" >/dev/null
    fi
    if [[ -n "$client" && -n "${RATE_TABLE:-}" ]]; then
      aws dynamodb delete-item \
        --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
        --key "$(jq -cn --arg key "$(tpk "$tenant" "$client")" \
          '{key:{S:$key}}')" >/dev/null
    fi
    if [[ -n "$client" && -s "$SECRETS/$tenant-admin.headers" ]]; then
      curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
        -o /dev/null -X DELETE -H "@$SECRETS/$tenant-admin.headers" \
        "https://$tenant.$ZONE/admin/clients/$client"
    fi
  done
  if [[ -n "$FRONTEND_BUCKET" ]]; then
    aws s3 rm "s3://$FRONTEND_BUCKET/$BUNDLE_KEY" \
      --profile "$PROFILE" --region "$REGION" >/dev/null
  fi
  ((had_errexit == 1)) && set -e
  return 0
}

fixtures_absent_round() {
  local label tenant binding client_var redirect intent client recovered output
  for tuple in \
    "a|$TENANT_A|$BINDING_A|CLIENT_A|$REDIRECT_A|$CLIENT_A_INTENT" \
    "b|$TENANT_B|$BINDING_B|CLIENT_B|$REDIRECT_B|$CLIENT_B_INTENT"; do
    IFS='|' read -r label tenant binding client_var redirect intent <<<"$tuple"
    client="${!client_var}"
    if [[ "$intent" == "1" && -z "$client" ]]; then
      recovered="$(recover_client_id "$tenant" "$redirect" \
        "$WORK/client-$label-recovery-check.json")" || return 1
      if [[ "$recovered" == "__absent__" ]]; then
        client=""
      else
        client="$recovered"
        printf -v "$client_var" '%s' "$client"
      fi
    fi
    if [[ -n "$client" ]]; then
      output="$WORK/client-$label-clean.json"
      aws dynamodb get-item \
        --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
        --key "$(jq -cn --arg key "$(tpk "$tenant" "$client")" \
          '{client_id:{S:$key}}')" --consistent-read --output json >"$output" ||
        return 1
      dynamo_item_absent "$output" || return 1
      output="$WORK/client-rate-$label-clean.json"
      aws dynamodb get-item \
        --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE" \
        --key "$(jq -cn --arg key "$(tpk "$tenant" "$client")" \
          '{key:{S:$key}}')" --consistent-read --output json >"$output" ||
        return 1
      dynamo_item_absent "$output" || return 1
    fi
    output="$WORK/trust-$label-clean.json"
    aws dynamodb get-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" \
      --key "$(jq -cn --arg key "$(tpk "$tenant" "$binding")" \
        '{binding_id:{S:$key}}')" --consistent-read --output json >"$output" ||
      return 1
    dynamo_item_absent "$output" || return 1
  done
  local object_count
  object_count="$(
    # JMESPath backticks are literals.
    # shellcheck disable=SC2016
    aws s3api list-objects-v2 --profile "$PROFILE" --region "$REGION" \
      --bucket "$FRONTEND_BUCKET" --prefix "$BUNDLE_KEY" --max-keys 1 \
      --query 'length(Contents || `[]`)' --output text
  )" || return 1
  [[ "$object_count" == "0" ]]
}

cleanup_resources() {
  local stable_started=-1
  for _ in $(seq 1 90); do
    best_effort_fixture_cleanup
    if fixtures_absent_round; then
      if [[ "$stable_started" -lt 0 ]]; then
        stable_started="$SECONDS"
      elif ((SECONDS - stable_started >= 15)); then
        CLEANED=1
        return 0
      fi
    else
      stable_started=-1
    fi
    sleep 1
  done
  return 1
}

scrub_secrets() {
  local status=0
  [[ -d "$SECRETS" ]] || return 0
  find "$SECRETS" -type f -exec sh -c '
    for file do
      : >"$file" && rm -f -- "$file" || exit 1
    done
  ' sh {} + || status=1
  find "$SECRETS" -mindepth 1 -depth -type d -empty -delete || status=1
  rmdir "$SECRETS" 2>/dev/null || status=1
  [[ ! -e "$SECRETS" ]] || status=1
  return "$status"
}

purge_work_files() {
  local status=0
  find "$WORK" -mindepth 1 -type f -delete || status=1
  find "$WORK" -mindepth 1 -depth -type d -empty -delete || status=1
  return "$status"
}

cleanup() {
  local status=$? scrubbed=1
  trap '' INT TERM
  trap - EXIT
  set +e
  if [[ "$BUCKETS_MUTATED" == "1" ]]; then
    restore_bucket_if_owned \
      "$TENANT_A_BUCKET" "$WORK/a-before.json" \
      "${A_SEED_VERSION:-1}" "$(( ${A_SEED_VERSION:-1} + 1 ))" a ||
      { echo "FAIL: tenant A shared bucket did not restore" >&2; status=1; }
    restore_bucket_if_owned \
      "$TENANT_B_BUCKET" "$WORK/b-before.json" \
      "${B_BEFORE_VERSION:-0}" "$(( ${B_BEFORE_VERSION:-0} + 1 ))" b ||
      { echo "FAIL: tenant B shared bucket did not restore" >&2; status=1; }
  fi
  if [[ "$CLEANED" != "1" ]]; then
    if [[ "$CLIENT_A_INTENT" == "0" && "$CLIENT_B_INTENT" == "0" &&
      -z "$FRONTEND_BUCKET" ]]; then
      CLEANED=1
    elif [[ -n "${CLIENTS_TABLE:-}" && -n "${TRUST_TABLE:-}" &&
      -n "${RATE_TABLE:-}" && -n "$FRONTEND_BUCKET" && -n "${ZONE:-}" ]]; then
      cleanup_resources ||
        { echo "FAIL: tenant quota fixture cleanup did not converge" >&2; status=1; }
    else
      echo "FAIL: fixture identity was not initialized enough for safe cleanup" >&2
      status=1
    fi
  fi
  scrub_secrets || {
    echo "FAIL: sensitive-file scrub did not complete" >&2
    scrubbed=0
    status=1
  }
  if [[ "$status" -eq 0 ]]; then
    purge_work_files && rmdir "$WORK" || status=1
  else
    rm -f "$EVIDENCE_FILE"
    if [[ "$scrubbed" == "1" ]] && purge_work_files; then
      jq -n \
        --arg status "$status" \
        --arg cleaned "$CLEANED" \
        --arg run_id "$RUN_ID" \
        --arg tenant_a "$TENANT_A" \
        --arg tenant_b "$TENANT_B" \
        '{
          result:"fail",
          exit_status:($status|tonumber),
          cleanup_verified:($cleaned=="1"),
          run_id:$run_id,
          tenant_ids:[$tenant_a,$tenant_b],
          sensitive_values_retained:false
        }' >"$WORK/failure.json"
      echo "Redacted recovery material retained at $WORK" >&2
    else
      echo "Sensitive-file deletion could not be proven; no redacted-only diagnostic claim was written" >&2
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

stack_output() {
  local key="$1"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$WORK/stack.json"
}

aws cloudformation describe-stacks \
  --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/stack.json"
[[ "$(jq -er '.Stacks[0].StackStatus' "$WORK/stack.json")" == "UPDATE_COMPLETE" ]] ||
  fail "$STACK is not UPDATE_COMPLETE"
DEPLOYED_COMMIT="$(stack_output DeploymentCommit)"
[[ "$DEPLOYED_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "deployed commit does not match EXPECTED_COMMIT"
HARNESS_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD)"
[[ "$HARNESS_COMMIT" == "$EXPECTED_COMMIT" ]] ||
  fail "harness and deployment must use the same exact commit"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] ||
  fail "live evidence requires a clean worktree"
SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/tenant_sign_quota_live.sh" | cut -d' ' -f1)"
COMMITTED_SCRIPT_SHA256="$(
  git -C "$REPO_ROOT" show "$EXPECTED_COMMIT:e2e/tenant_sign_quota_live.sh" |
    sha256sum | cut -d' ' -f1
)"
[[ "$SCRIPT_SHA256" == "$COMMITTED_SCRIPT_SHA256" ]] ||
  fail "tenant quota harness does not match the exact deployed commit"

CLIENTS_TABLE="$(stack_output ClientsTableName)"
TRUST_TABLE="$(stack_output WorkloadTrustTableName)"
RATE_TABLE="$(stack_output RateLimitTableName)"
AUTH_FN="$(stack_output AuthFnName)"

aws lambda get-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$SECRETS/auth.json"
jq -e --arg commit "$EXPECTED_COMMIT" '
  .State == "Active"
  and .LastUpdateStatus == "Successful"
  and .Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and .Environment.Variables.AGENT_AUTH_FORM == "saas"
  and (.Environment.Variables.AGENT_AUTH_KMS_TENANT_GATE_CAPACITY | tonumber > 0)
  and (.Environment.Variables.AGENT_AUTH_KMS_TENANT_GATE_REFILL_PER_SEC | tonumber > 0)
' "$SECRETS/auth.json" >/dev/null ||
  fail "runtime is not ready with the tenant KMS-sign gate enabled"
ZONE="$(jq -er '.Environment.Variables.AGENT_AUTH_ZONE' "$SECRETS/auth.json")"
BOOTSTRAP_ARN="$(
  jq -er '.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN' \
    "$SECRETS/auth.json"
)"
aws secretsmanager get-secret-value \
  --secret-id "$BOOTSTRAP_ARN" --profile "$PROFILE" --region "$REGION" \
  --query SecretString --output text >"$SECRETS/bootstrap.json"

for tenant in "$TENANT_A" "$TENANT_B"; do
  admin_arn="$(jq -er --arg tenant "$tenant" \
    '.tenant_admin_secret_arns[$tenant]' "$SECRETS/bootstrap.json")"
  aws secretsmanager get-secret-value \
    --secret-id "$admin_arn" --profile "$PROFILE" --region "$REGION" \
    --output json |
    jq -jer '.SecretString | fromjson | .current.secret
      | select(type == "string" and length >= 16)' >"$SECRETS/$tenant-admin.token"
  printf 'authorization: Bearer %s\n' "$(<"$SECRETS/$tenant-admin.token")" \
    >"$SECRETS/$tenant-admin.headers"
  rm -f "$SECRETS/$tenant-admin.token"
  issuer="https://$tenant.$ZONE"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    "$issuer/.well-known/openid-configuration" >"$WORK/$tenant-discovery.json"
  [[ "$(jq -er '.issuer' "$WORK/$tenant-discovery.json")" == "$issuer" ]] ||
    fail "$tenant issuer is not ready"
done
rm -f "$SECRETS/bootstrap.json"

aws cloudformation list-stack-resources \
  --stack-name "$STACK" --profile "$PROFILE" --region "$REGION" \
  --output json >"$WORK/resources.json"
FRONTEND_BUCKET="$(jq -er '
  [
    .StackResourceSummaries[]
    | select(
        .ResourceType == "AWS::S3::Bucket"
        and (.LogicalResourceId | startswith("FrontendSpaBucket"))
        and .ResourceStatus == "CREATE_COMPLETE"
      )
    | .PhysicalResourceId
  ]
  | unique
  | if length == 1 then .[0] else error("expected one frontend bucket") end
' "$WORK/resources.json")"

python3 - "$KEY_FILE" "$JWKS_FILE" <<'PY'
import base64
import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

key_path, jwks_path = sys.argv[1:3]
key = ec.generate_private_key(ec.SECP256R1())
numbers = key.public_key().public_numbers()

def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

with open(key_path, "wb") as output:
    output.write(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
with open(jwks_path, "w", encoding="utf-8") as output:
    json.dump(
        {
            "keys": [{
                "kty": "EC", "crv": "P-256", "kid": "c10-14-live",
                "x": b64u(numbers.x.to_bytes(32, "big")),
                "y": b64u(numbers.y.to_bytes(32, "big")),
                "use": "sig", "alg": "ES256",
            }]
        },
        output,
        separators=(",", ":"),
    )
PY
aws s3 cp "$JWKS_FILE" "s3://$FRONTEND_BUCKET/$BUNDLE_KEY" \
  --profile "$PROFILE" --region "$REGION" \
  --content-type application/json --cache-control 'max-age=60' >/dev/null

create_client() {
  local tenant="$1" label="$2" redirect="$3" intent_var="$4" status
  local response="$WORK/client-$label.json"
  printf -v "$intent_var" '%s' 1
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o "$response" -w '%{http_code}' -X POST \
    -H "@$SECRETS/$tenant-admin.headers" -H 'content-type: application/json' \
    --data-binary "$(jq -cn --arg redirect "$redirect" \
      '{redirect_uris:[$redirect],token_endpoint_auth_method:"none"}')" \
    "https://$tenant.$ZONE/admin/clients")"
  [[ "$status" == "201" ]] || fail "$tenant client creation returned HTTP $status"
}
create_client "$TENANT_A" a "$REDIRECT_A" CLIENT_A_INTENT
CLIENT_A="$(jq -er '.client_id' "$WORK/client-a.json")"
create_client "$TENANT_B" b "$REDIRECT_B" CLIENT_B_INTENT
CLIENT_B="$(jq -er '.client_id' "$WORK/client-b.json")"

for tuple in "$TENANT_A|$CLIENT_A" "$TENANT_B|$CLIENT_B"; do
  IFS='|' read -r tenant client <<<"$tuple"
  aws dynamodb update-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --key "$(jq -cn --arg client "$(tpk "$tenant" "$client")" \
      '{client_id:{S:$client}}')" \
    --update-expression \
      'SET client_type = :workload, allowed_resources = :resources, allowed_scopes = :scopes' \
    --expression-attribute-values "$(jq -cn --arg resource "$RESOURCE" --arg scope "$SCOPE" '
      {
        ":workload": {S:"workload"},
        ":resources": {L:[{S:$resource}]},
        ":scopes": {L:[{S:$scope}]}
      }
    ')" >/dev/null
done

BUNDLE_URL="https://$TENANT_A.$ZONE/$BUNDLE_KEY"
stable=0
for _ in $(seq 1 30); do
  if curl -fsS --proto '=https' --connect-timeout 5 --max-time 15 \
    "$BUNDLE_URL" | jq -e '.keys[0].kid == "c10-14-live"' >/dev/null; then
    stable=$((stable + 1))
  else
    stable=0
  fi
  [[ "$stable" -ge 3 ]] && break
  sleep 2
done
[[ "$stable" -ge 3 ]] || fail "temporary JWKS did not become stable"

create_binding() {
  local tenant="$1" binding="$2" td="$3" client="$4"
  jq -cn --arg binding "$binding" --arg tenant "$tenant" --arg td "$td" \
    --arg uri "$BUNDLE_URL" --arg client "$client" '{
      binding_id:$binding,
      tenant_id:$tenant,
      mechanism:"spiffe_jwt",
      trust_domain:$td,
      jwks_uri:$uri,
      subject_pattern:("spiffe://" + $td + "/agent/*"),
      mapped_client_id:$client
    }' >"$WORK/binding-$binding.json"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o "$WORK/binding-$binding.response" -w '%{http_code}' -X POST \
    -H "@$SECRETS/$tenant-admin.headers" -H 'content-type: application/json' \
    --data-binary "@$WORK/binding-$binding.json" \
    "https://$tenant.$ZONE/admin/workload-trust")"
  [[ "$status" == "201" ]] ||
    fail "$tenant workload binding returned HTTP $status"
}
create_binding "$TENANT_A" "$BINDING_A" "$TD_A" "$CLIENT_A"
create_binding "$TENANT_B" "$BINDING_B" "$TD_B" "$CLIENT_B"

make_assertion() {
  local tenant="$1" td="$2" output="$3"
  python3 - "$KEY_FILE" "https://$tenant.$ZONE" "$td" >"$output" <<'PY'
import base64
import json
import secrets
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

key_path, audience, trust_domain = sys.argv[1:4]
key = serialization.load_pem_private_key(open(key_path, "rb").read(), None)

def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

now = int(time.time())
header = {"typ": "JWT", "alg": "ES256", "kid": "c10-14-live"}
claims = {
    "iss": "https://spire." + trust_domain,
    "sub": "spiffe://" + trust_domain + "/agent/live",
    "aud": audience,
    "iat": now, "exp": now + 300, "jti": secrets.token_urlsafe(18),
}
signing_input = (
    b64u(json.dumps(header, separators=(",", ":")).encode())
    + "." + b64u(json.dumps(claims, separators=(",", ":")).encode())
)
der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
r, s = decode_dss_signature(der)
sys.stdout.write(
    signing_input + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
)
PY
}

token_request() {
  local tenant="$1" td="$2" label="$3"
  make_assertion "$tenant" "$td" "$SECRETS/$label.assertion"
  curl -sS --proto '=https' --connect-timeout 5 --max-time 60 \
    -D "$SECRETS/$label.headers" -o "$SECRETS/$label.body" -w '%{http_code}' \
    -X POST -H 'content-type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=client_credentials' \
    --data-urlencode \
      'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
    --data-urlencode "client_assertion@$SECRETS/$label.assertion" \
    --data-urlencode "resource=$RESOURCE" \
    --data-urlencode "scope=$SCOPE" \
    "https://$tenant.$ZONE/token"
}

[[ "$(token_request "$TENANT_A" "$TD_A" warm-a)" == "200" ]] ||
  fail "$TENANT_A could not mint the warm-up token"
[[ "$(token_request "$TENANT_B" "$TD_B" warm-b)" == "200" ]] ||
  fail "$TENANT_B could not mint the warm-up token"
check_ok "both tenants mint a real access token before the quota probe"

snapshot_bucket "$TENANT_A_BUCKET" "$WORK/a-before.json"
snapshot_bucket "$TENANT_B_BUCKET" "$WORK/b-before.json"
A_BEFORE_VERSION="$(bucket_version "$WORK/a-before.json")"
B_BEFORE_VERSION="$(bucket_version "$WORK/b-before.json")"
A_SEED_VERSION=$((A_BEFORE_VERSION + 1))
now="$(date +%s)"
future=$((now + 3600))
expires=$((now + 7200))

seed_args=(
  --profile "$PROFILE" --region "$REGION" --table-name "$RATE_TABLE"
  --item "$(jq -cn --arg key "$TENANT_A_BUCKET" --arg version "$A_SEED_VERSION" \
    --arg future "$future" --arg expires "$expires" '{
      key:{S:$key}, tokens:{N:"0"}, last_refill:{N:$future},
      version:{N:$version}, expires_at:{N:$expires}
    }')"
)
if jq -e 'has("Item")' "$WORK/a-before.json" >/dev/null; then
  seed_args+=(
    --condition-expression 'version = :expected'
    --expression-attribute-values "$(jq -cn --arg version "$A_BEFORE_VERSION" \
      '{":expected":{N:$version}}')"
  )
else
  seed_args+=(--condition-expression 'attribute_not_exists(version)')
fi
aws dynamodb put-item "${seed_args[@]}" >/dev/null
BUCKETS_MUTATED=1

A_STATUS="$(token_request "$TENANT_A" "$TD_A" exhausted-a)"
[[ "$A_STATUS" == "503" ]] ||
  fail "$TENANT_A returned HTTP $A_STATUS instead of tenant-quota 503"
grep -iq '^retry-after: [1-9][0-9]*' "$SECRETS/exhausted-a.headers" ||
  fail "$TENANT_A quota response has no positive Retry-After"
jq -e '.error == "temporarily_unavailable"' "$SECRETS/exhausted-a.body" >/dev/null ||
  fail "$TENANT_A quota response is not an OAuth temporarily_unavailable error"

B_STATUS="$(token_request "$TENANT_B" "$TD_B" isolated-b)"
[[ "$B_STATUS" == "200" ]] ||
  fail "$TENANT_B was affected by $TENANT_A quota exhaustion (HTTP $B_STATUS)"
jq -e '.access_token | type == "string" and length > 0' "$SECRETS/isolated-b.body" >/dev/null ||
  fail "$TENANT_B isolation response has no access token"

snapshot_bucket "$TENANT_A_BUCKET" "$WORK/a-after.json"
snapshot_bucket "$TENANT_B_BUCKET" "$WORK/b-after.json"
A_FINAL_VERSION="$(bucket_version "$WORK/a-after.json")"
B_FINAL_VERSION="$(bucket_version "$WORK/b-after.json")"
[[ "$A_FINAL_VERSION" -eq $((A_SEED_VERSION + 1)) ]] ||
  fail "tenant A shared bucket changed outside the one quota probe"
[[ "$B_FINAL_VERSION" -eq $((B_BEFORE_VERSION + 1)) ]] ||
  fail "tenant B shared bucket changed outside the one isolation probe"
printf '%s' "$A_FINAL_VERSION" >"$WORK/a-final-version"
printf '%s' "$B_FINAL_VERSION" >"$WORK/b-final-version"
check_ok "tenant A is shed while tenant B remains available"

restore_bucket "$TENANT_A_BUCKET" "$WORK/a-before.json" "$A_FINAL_VERSION"
restore_bucket "$TENANT_B_BUCKET" "$WORK/b-before.json" "$B_FINAL_VERSION"
BUCKETS_MUTATED=0
snapshot_bucket "$TENANT_A_BUCKET" "$WORK/a-restored.json"
snapshot_bucket "$TENANT_B_BUCKET" "$WORK/b-restored.json"
jq -S '.Item // null' "$WORK/a-before.json" >"$WORK/a-before.item"
jq -S '.Item // null' "$WORK/a-restored.json" >"$WORK/a-restored.item"
jq -S '.Item // null' "$WORK/b-before.json" >"$WORK/b-before.item"
jq -S '.Item // null' "$WORK/b-restored.json" >"$WORK/b-restored.item"
cmp "$WORK/a-before.item" "$WORK/a-restored.item" >/dev/null ||
  fail "tenant A shared bucket was not restored byte-for-byte"
cmp "$WORK/b-before.item" "$WORK/b-restored.item" >/dev/null ||
  fail "tenant B shared bucket was not restored byte-for-byte"

cleanup_resources || fail "temporary tenant quota fixtures did not cleanly converge"
scrub_secrets || fail "sensitive-file scrub did not complete"
if ! purge_work_files; then
  fail "temporary tenant quota work files did not cleanly converge"
fi
if ! rmdir "$WORK"; then
  fail "temporary tenant quota work directory did not cleanly converge"
fi
trap - EXIT INT TERM

jq -n \
  --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg commit "$EXPECTED_COMMIT" \
  --arg script_sha256 "$SCRIPT_SHA256" \
  --arg tenant_a "$TENANT_A" \
  --arg tenant_b "$TENANT_B" '{
    schema:"agent-auth-c10-14-evidence-v1",
    requirement:"C10.14",
    completed_at:$completed_at,
    deployment_commit:$commit,
    harness_commit:$commit,
    script_sha256:$script_sha256,
    tenant_ids:[$tenant_a,$tenant_b],
    assertions:{
      both_tenants_signed_before_probe:"pass",
      tenant_a_quota_status:503,
      retry_after_present:"pass",
      tenant_b_status:200,
      shared_bucket_versions_owned:"pass",
      shared_buckets_restored_exactly:"pass",
      temporary_authority_cleanup:"pass"
    },
    sensitive_values_in_evidence:false
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
printf 'PASS: C10.14 tenant signing quota evidence published\n'
printf 'C10.14 evidence: %s\n' "$EVIDENCE_FILE"
printf 'C10.14 evidence sha256: %s\n' \
  "$(sha256sum "$EVIDENCE_FILE" | cut -d' ' -f1)"

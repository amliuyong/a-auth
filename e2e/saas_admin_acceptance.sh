#!/usr/bin/env bash
# Read-only live acceptance for issue #17.
#
# Verifies the deployed SaaS platform/t1/t2 credential matrix, the retired
# pre-isolation platform credential, and the control-directory response. This
# script never writes Secrets Manager, Lambda, or CloudFormation state.
#
# Usage:
#   set -a
#   source .env
#   set +a
#   ./e2e/saas_admin_acceptance.sh
set -euo pipefail
set +x

PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
BROWSER="${BROWSER:-0}"

umask 077
WORK="$(mktemp -d)"
cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }
[[ "$REGION" == "us-east-1" ]] ||
  fail "issue #17 acceptance requires REGION=us-east-1"
for command in aws curl jq; do
  require "$command"
done
[[ "$BROWSER" == "0" || "$BROWSER" == "1" ]] ||
  fail "BROWSER must be 0 or 1"

declare -A ARN BASE PATH_PART TOKEN TRUSTED_ARN

stack_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

request_status() {
  local endpoint="$1" token_file="$2"
  local header_file="$WORK/header-${endpoint}-${RANDOM}"
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >"$header_file"
  curl -sS -o /dev/null -w '%{http_code}' \
    --proto '=https' \
    --connect-timeout 5 --max-time 20 \
    -H "@$header_file" "${BASE[$endpoint]}${PATH_PART[$endpoint]}"
  rm -f "$header_file"
}

request_body() {
  local endpoint="$1" token_file="$2" output="$3"
  local header_file="$WORK/header-${endpoint}-${RANDOM}"
  printf 'authorization: Bearer %s\n' "$(<"$token_file")" >"$header_file"
  curl -fsS --connect-timeout 5 --max-time 20 \
    --proto '=https' \
    -H "@$header_file" "${BASE[$endpoint]}${PATH_PART[$endpoint]}" >"$output"
  rm -f "$header_file"
}

expect_status() {
  local endpoint="$1" token_file="$2" expected="$3" label="$4"
  local actual
  actual="$(request_status "$endpoint" "$token_file")"
  [[ "$actual" == "$expected" ]] ||
    fail "$label expected HTTP $expected, got $actual"
}

load_target_credentials() {
  local owner="$1" arn="$2"
  local credential_set="$WORK/${owner}-credential-set.json"
  local output="$WORK/${owner}-current-token"
  aws secretsmanager get-secret-value \
    --secret-id "$arn" --profile "$PROFILE" --region "$REGION" \
    --output json |
    jq -er '
      .SecretString
      | fromjson
      | select(.current.secret | type == "string" and length >= 16)
      | select(
          (has("next") | not)
          or (.next == null)
          or (.next.secret | type == "string" and length >= 16)
        )
    ' >"$credential_set"
  jq -er '
    .current.secret
    | select(test("^[A-Za-z0-9._~+/=-]+$"))
  ' "$credential_set" >"$output"
  jq -e '
    [.current.secret, .next.secret?]
    | map(select(type == "string"))
  ' "$credential_set" >"$WORK/${owner}-active-bearers.json"
  chmod 0600 "$output"
  ARN["$owner"]="$arn"
  TOKEN["$owner"]="$output"
}

load_trusted_runtime_config() {
  local resources="$WORK/stack-resources.json"
  local runtime="$WORK/runtime-config.json"
  aws cloudformation list-stack-resources \
    --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
    --output json >"$resources"

  local auth_fn
  auth_fn="$(jq -er '
    [
      .StackResourceSummaries[]
      | select(
          .ResourceType == "AWS::Lambda::Function"
          and (.LogicalResourceId | startswith("AuthFn"))
        )
      | .PhysicalResourceId
    ]
    | unique
    | if length == 1 then .[0] else error("expected exactly one AuthFn") end
  ' "$resources")"
  aws lambda get-function-configuration \
    --function-name "$auth_fn" --profile "$PROFILE" --region "$REGION" \
    --query 'Environment.Variables.{form:AGENT_AUTH_FORM,zone:AGENT_AUTH_ZONE,control_host:AGENT_AUTH_CONTROL_HOST,bootstrap:AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN}' \
    --output json >"$runtime"
  aws secretsmanager get-secret-value \
    --secret-id "$(jq -er '.bootstrap' "$runtime")" \
    --profile "$PROFILE" --region "$REGION" \
    --query SecretString --output text >"$WORK/runtime-bootstrap.json"

  jq -e '
    .form == "saas"
    and (.zone | type == "string" and length > 0)
    and (.control_host | type == "string" and length > 0)
  ' "$runtime" >/dev/null ||
    fail "deployed AuthFn does not expose the expected t1/t2 SaaS registry"
  jq -e '
    .schema_version == 1
    and (.saas_tenants == ["t1", "t2"])
    and ((.tenant_admin_secret_arns | keys | sort) == ["t1", "t2"])
    and (.admin_credential_secret_arn | type == "string" and contains(":secretsmanager:"))
  ' "$WORK/runtime-bootstrap.json" >/dev/null ||
    fail "deployed AuthFn bootstrap config is not the expected t1/t2 registry"

  ZONE="$(jq -er '.zone' "$runtime")"
  CONTROL_HOST="$(jq -er '.control_host' "$runtime")"
  [[ "$ZONE" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] ||
    fail "deployed SaaS zone is not a DNS name"
  [[ "$CONTROL_HOST" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ &&
    "$CONTROL_HOST" == *".$ZONE" ]] ||
    fail "deployed control host is outside the SaaS zone"

  TRUSTED_ARN[platform]="$(
    jq -er '.admin_credential_secret_arn' "$WORK/runtime-bootstrap.json"
  )"
  for tenant in t1 t2; do
    TRUSTED_ARN["$tenant"]="$(jq -er --arg tenant "$tenant" \
      '.tenant_admin_secret_arns[$tenant]' "$WORK/runtime-bootstrap.json")"
    [[ "${TRUSTED_ARN[$tenant]}" == arn:aws:secretsmanager:*:secret:* ]] ||
      fail "$tenant runtime Secret ARN is invalid"
  done
}

discover_retired_shared_source() {
  local resources="$WORK/stack-resources.json"
  if [[ ! -f "$resources" ]]; then
    aws cloudformation list-stack-resources \
      --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
      --output json >"$resources"
  fi

  local secret description
  while IFS= read -r secret; do
    description="$(aws secretsmanager describe-secret \
      --secret-id "$secret" --profile "$PROFILE" --region "$REGION" \
      --query Description --output text)"
    if [[ "$description" == *"rollback source"* ]]; then
      printf '%s\n' "$secret"
      return 0
    fi
  done < <(
    jq -r '.StackResourceSummaries[]
      | select(.ResourceType == "AWS::SecretsManager::Secret")
      | .PhysicalResourceId' "$resources"
  )
  return 1
}

STACK_STATUS="$(aws cloudformation describe-stacks \
  --stack-name "$SAAS_STACK" --profile "$PROFILE" --region "$REGION" \
  --query 'Stacks[0].StackStatus' --output text)"
[[ "$STACK_STATUS" == "UPDATE_COMPLETE" ]] ||
  fail "$SAAS_STACK must be UPDATE_COMPLETE, got $STACK_STATUS"
pass "$SAAS_STACK is UPDATE_COMPLETE"

load_trusted_runtime_config

BASE[platform]="https://${CONTROL_HOST}"
PATH_PART[platform]="/admin/control/tenants"
[[ "$(stack_output AdminUrl)" == "${BASE[platform]}/admin" ]] ||
  fail "AdminUrl output does not match the deployed control host"
[[ "$(stack_output AdminSecretArn)" == "${TRUSTED_ARN[platform]}" ]] ||
  fail "AdminSecretArn output does not match the deployed AuthFn"
load_target_credentials platform "${TRUSTED_ARN[platform]}"

CONTROL_BODY="$WORK/control-tenants.json"
request_body platform "${TOKEN[platform]}" "$CONTROL_BODY"
jq -e '
  (type == "object")
  and ((keys | sort) == ["tenants"])
  and (.tenants | type == "array")
  and ((.tenants | length) == 2)
  and ([.tenants[].tenant_id] == ["t1", "t2"])
  and (all(
    .tenants[];
    ((keys | sort) == ["admin_secret_arn", "admin_url", "issuer", "tenant_id"])
  ))
' "$CONTROL_BODY" >/dev/null ||
  fail "control directory must contain exactly the sorted t1/t2 public fields"

for tenant in t1 t2; do
  BASE["$tenant"]="https://${tenant}.${ZONE}"
  PATH_PART["$tenant"]="/admin/overview"
  jq -e \
    --arg tenant "$tenant" \
    --arg issuer "${BASE[$tenant]}" \
    --arg arn "${TRUSTED_ARN[$tenant]}" '
    .tenants[]
    | select(.tenant_id == $tenant)
    | .issuer == $issuer
      and .admin_url == ($issuer + "/admin")
      and .admin_secret_arn == $arn
  ' "$CONTROL_BODY" >/dev/null ||
    fail "$tenant control-directory fields do not match the deployed runtime registry"
  load_target_credentials "$tenant" "${TRUSTED_ARN[$tenant]}"
done

[[ "${ARN[platform]}" != "${ARN[t1]}" && "${ARN[platform]}" != "${ARN[t2]}" &&
  "${ARN[t1]}" != "${ARN[t2]}" ]] ||
  fail "platform, t1, and t2 target Secret ARNs must be distinct"
for left in platform t1; do
  for right in t1 t2; do
    [[ "$left" == "$right" ]] && continue
    cmp -s "${TOKEN[$left]}" "${TOKEN[$right]}" &&
      fail "$left and $right current credentials must be distinct"
  done
done

for token_owner in platform t1 t2; do
  for endpoint in platform t1 t2; do
    expected=401
    [[ "$token_owner" == "$endpoint" ]] && expected=200
    expect_status "$endpoint" "${TOKEN[$token_owner]}" "$expected" \
      "$token_owner current credential on $endpoint endpoint"
  done
done
pass "platform/t1/t2 current credentials pass the three successes and six cross-domain rejections"

RETIRED_SOURCE_ARN="$(discover_retired_shared_source)" ||
  fail "cannot discover the pre-isolation platform rollback source"
RETIRED_TOKEN="$WORK/retired-shared-token"
aws secretsmanager get-secret-value \
  --secret-id "$RETIRED_SOURCE_ARN" --profile "$PROFILE" --region "$REGION" \
  --output json |
  jq -er '
    .SecretString
    | select(
        type == "string"
        and length >= 16
        and test("^[A-Za-z0-9._~+/=-]+$")
      )
  ' >"$RETIRED_TOKEN"
chmod 0600 "$RETIRED_TOKEN"
[[ -s "$RETIRED_TOKEN" ]] || fail "retired shared credential source is empty"
for owner in platform t1 t2; do
  cmp -s "$RETIRED_TOKEN" "${TOKEN[$owner]}" &&
    fail "retired shared credential still equals $owner current credential"
done
for endpoint in platform t1 t2; do
  expect_status "$endpoint" "$RETIRED_TOKEN" 401 \
    "retired shared credential on $endpoint endpoint"
done
pass "retired shared credential is rejected by control, t1, and t2"

ALL_BEARERS="$WORK/all-bearers.json"
jq -s 'add | unique' \
  "$WORK/platform-active-bearers.json" \
  "$WORK/t1-active-bearers.json" \
  "$WORK/t2-active-bearers.json" \
  >"$ALL_BEARERS"
jq -Rn --rawfile token "$RETIRED_TOKEN" \
  '[($token | rtrimstr("\n"))]' >"$WORK/retired-bearer.json"
jq -s 'add | unique' "$ALL_BEARERS" "$WORK/retired-bearer.json" \
  >"$WORK/sensitive-bearers.json"
jq -e --slurpfile secrets "$WORK/sensitive-bearers.json" '
  [.. | strings] as $values
  | all(
      $secrets[0][];
      . as $secret
      | all($values[]; contains($secret) | not)
    )
' "$CONTROL_BODY" >/dev/null ||
  fail "control response exposes a current, next, or retired bearer"
pass "control response contains only public tenant metadata and no bearer value"

if [[ "$BROWSER" == "1" ]]; then
  require node
  SAAS_CONTROL_URL="${BASE[platform]}" \
    SAAS_T1_URL="${BASE[t1]}" \
    SAAS_T2_URL="${BASE[t2]}" \
    SAAS_PLATFORM_TOKEN_FILE="${TOKEN[platform]}" \
    SAAS_T1_TOKEN_FILE="${TOKEN[t1]}" \
    SAAS_T2_TOKEN_FILE="${TOKEN[t2]}" \
    node web/live/admin-control.mjs
fi

#!/usr/bin/env bash
# C1.1b live gate: per-tenant OIDC subject profile on one SaaS fleet.
#
# Tenant A uses the SaaS privacy default (pairwise); tenant B is explicitly
# configured public. The gate proves discovery, client metadata validation and
# real authorization-code ID-token issuance all use the same tenant resolver.
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
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c1-1b-evidence-$(date -u +%Y%m%dT%H%M%SZ).json}"

for command in awk aws cp curl find git jq openssl python3 rmdir seq sha256sum sleep tail; do
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

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  rm -f "$EVIDENCE_FILE"
  exit 1
}
check_ok() { printf 'OK: %s\n' "$1"; }

WORK="$(mktemp -d)"
SECRETS="$WORK/secrets"
mkdir -m 700 "$SECRETS"
RUN_ID="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
EMAIL="c1-1b-$RUN_ID@example.com"
CLEANED=0

declare -A USER_IDS=(
  ["$TENANT_A"]="user:$EMAIL"
  ["$TENANT_B"]="user:$EMAIL"
)
declare -A USER_INTENTS=(["$TENANT_A"]=0 ["$TENANT_B"]=0)
declare -A CLIENT_IDS=(["$TENANT_A"]="" ["$TENANT_B"]="")
declare -A CLIENT_INTENTS=(["$TENANT_A"]=0 ["$TENANT_B"]=0)
declare -A SECOND_CLIENT_IDS=(["$TENANT_A"]="" ["$TENANT_B"]="")
declare -A SECOND_CLIENT_INTENTS=(["$TENANT_A"]=0 ["$TENANT_B"]=0)
EXTRA_PUBLIC_CLIENT=""
EXTRA_PUBLIC_INTENT=0
EXTRA_PAIRWISE_CLIENT=""
EXTRA_PAIRWISE_INTENT=0

tpk() {
  printf '%s\x1f%s' "$1" "$2"
}

urlencode() {
  python3 -c \
    'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
    "$1"
}

admin_request() {
  local tenant="$1" method="$2" path="$3" body="$4" output="$5"
  local args=(
    --silent --show-error --output "$output" --write-out '%{http_code}'
    --request "$method" --config "$SECRETS/$tenant-admin.curl"
    "https://$tenant.$ZONE$path"
  )
  if [[ -n "$body" ]]; then
    args+=(--header 'content-type: application/json' --data-binary "@$body")
  fi
  curl "${args[@]}"
}

recover_client_id() {
  local tenant="$1" redirect="$2" output="$3"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --consistent-read --projection-expression 'client_id,redirect_uris' \
    --output json >"$output" || return 1
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

client_absent() {
  local tenant="$1" client="$2" output="$3"
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --key "$(jq -cn --arg key "$(tpk "$tenant" "$client")" \
      '{client_id:{S:$key}}')" --consistent-read --output json >"$output" ||
    return 1
  [[ ! -s "$output" ]] || jq -e 'has("Item") | not' "$output" >/dev/null
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
  local status=$? stable_started=-1 round_failed client user_path response
  local had_errexit=0 scrubbed=1
  [[ $- == *e* ]] && had_errexit=1
  trap '' INT TERM
  trap - EXIT
  set +e
  for _ in $(seq 1 60); do
    round_failed=0
    for tenant in "$TENANT_A" "$TENANT_B"; do
      if [[ "${CLIENT_INTENTS[$tenant]}" == "1" ]]; then
        client="${CLIENT_IDS[$tenant]}"
        if [[ -z "$client" ]]; then
          response="$(recover_client_id "$tenant" "$WORK/$tenant.redirect" \
            "$WORK/$tenant-client-recovery.json")" || round_failed=1
          [[ "$response" == "__absent__" ]] || client="$response"
          CLIENT_IDS[$tenant]="$client"
        fi
        if [[ -n "$client" ]]; then
          response="$(admin_request "$tenant" DELETE "/admin/clients/$client" "" \
            "$WORK/$tenant-client-delete.json")" || round_failed=1
          [[ "$response" == "200" || "$response" == "404" ]] || round_failed=1
          client_absent "$tenant" "$client" \
            "$WORK/$tenant-client-absent.json" || round_failed=1
        fi
      fi
      if [[ "${SECOND_CLIENT_INTENTS[$tenant]}" == "1" ]]; then
        client="${SECOND_CLIENT_IDS[$tenant]}"
        if [[ -z "$client" ]]; then
          response="$(recover_client_id "$tenant" "$WORK/$tenant-secondary.redirect" \
            "$WORK/$tenant-secondary-client-recovery.json")" || round_failed=1
          [[ "$response" == "__absent__" ]] || client="$response"
          SECOND_CLIENT_IDS[$tenant]="$client"
        fi
        if [[ -n "$client" ]]; then
          response="$(admin_request "$tenant" DELETE "/admin/clients/$client" "" \
            "$WORK/$tenant-secondary-client-delete.json")" || round_failed=1
          [[ "$response" == "200" || "$response" == "404" ]] || round_failed=1
          client_absent "$tenant" "$client" \
            "$WORK/$tenant-secondary-client-absent.json" || round_failed=1
        fi
      fi
      if [[ "${USER_INTENTS[$tenant]}" == "1" ]]; then
        user_path="$(urlencode "${USER_IDS[$tenant]}")"
        response="$(admin_request "$tenant" DELETE "/admin/users/$user_path" "" \
          "$WORK/$tenant-user-delete.json")" || round_failed=1
        [[ "$response" == "200" || "$response" == "404" ]] || round_failed=1
        response="$(admin_request "$tenant" GET "/admin/users/$user_path" "" \
          "$WORK/$tenant-user-after.json")" || round_failed=1
        if [[ "$response" == "200" ]]; then
          jq -e '
            .status == "tombstoned"
            and .active_grants == 0
            and .sessions == 0
            and .passkeys == 0
            and .password_status == "not_configured"
            and .has_recovery == false
          ' "$WORK/$tenant-user-after.json" >/dev/null || round_failed=1
        elif [[ "$response" != "404" ]]; then
          round_failed=1
        fi
      fi
    done
    if [[ "$EXTRA_PUBLIC_INTENT" == "1" ]]; then
      if [[ -z "$EXTRA_PUBLIC_CLIENT" ]]; then
        response="$(recover_client_id "$TENANT_B" "$WORK/multi-a.redirect" \
          "$WORK/extra-client-recovery.json")" || round_failed=1
        [[ "$response" == "__absent__" ]] || EXTRA_PUBLIC_CLIENT="$response"
      fi
      if [[ -n "$EXTRA_PUBLIC_CLIENT" ]]; then
        response="$(admin_request "$TENANT_B" DELETE \
          "/admin/clients/$EXTRA_PUBLIC_CLIENT" "" \
          "$WORK/extra-client-delete.json")" || round_failed=1
        [[ "$response" == "200" || "$response" == "404" ]] || round_failed=1
        client_absent "$TENANT_B" "$EXTRA_PUBLIC_CLIENT" \
          "$WORK/extra-client-absent.json" || round_failed=1
      fi
    fi
    if [[ "$EXTRA_PAIRWISE_INTENT" == "1" ]]; then
      if [[ -z "$EXTRA_PAIRWISE_CLIENT" ]]; then
        response="$(recover_client_id "$TENANT_A" "$WORK/multi-a.redirect" \
          "$WORK/extra-pairwise-client-recovery.json")" || round_failed=1
        [[ "$response" == "__absent__" ]] || EXTRA_PAIRWISE_CLIENT="$response"
      fi
      if [[ -n "$EXTRA_PAIRWISE_CLIENT" ]]; then
        response="$(admin_request "$TENANT_A" DELETE \
          "/admin/clients/$EXTRA_PAIRWISE_CLIENT" "" \
          "$WORK/extra-pairwise-client-delete.json")" || round_failed=1
        [[ "$response" == "200" || "$response" == "404" ]] || round_failed=1
        client_absent "$TENANT_A" "$EXTRA_PAIRWISE_CLIENT" \
          "$WORK/extra-pairwise-client-absent.json" || round_failed=1
      fi
    fi
    if [[ "$round_failed" == "0" ]]; then
      if [[ "$stable_started" -lt 0 ]]; then
        stable_started="$SECONDS"
      elif ((SECONDS - stable_started >= 15)); then
        CLEANED=1
        break
      fi
    else
      stable_started=-1
    fi
    sleep 1
  done
  scrub_secrets || {
    echo "FAIL: sensitive-file scrub did not complete" >&2
    scrubbed=0
    status=1
  }
  if [[ "$CLEANED" != "1" || "$status" != "0" ]]; then
    status=1
    rm -f "$EVIDENCE_FILE"
    if [[ "$scrubbed" == "1" ]] && purge_work_files; then
      jq -n \
        --arg status "$status" \
        --arg run_id "$RUN_ID" \
        --arg tenant_a "$TENANT_A" \
        --arg tenant_b "$TENANT_B" \
        '{
          result:"fail",
          exit_status:($status|tonumber),
          cleanup_verified:false,
          run_id:$run_id,
          tenant_ids:[$tenant_a,$tenant_b],
          sensitive_values_retained:false
        }' >"$WORK/failure.json"
      printf 'cleanup did not converge; redacted recovery directory: %s\n' "$WORK" >&2
    else
      echo "Sensitive-file deletion could not be proven; no redacted-only diagnostic claim was written" >&2
    fi
  else
    purge_work_files && rmdir "$WORK" || status=1
  fi
  ((had_errexit == 1)) && set -e
  return "$status"
}

on_exit() {
  local status=$?
  trap '' INT TERM
  trap - EXIT
  cleanup || status=1
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

INITIAL_PASSWORD="$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')"
ACTIVE_PASSWORD="$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')"
printf '%s' "$INITIAL_PASSWORD" >"$SECRETS/initial.password"
printf '%s' "$ACTIVE_PASSWORD" >"$SECRETS/active.password"
unset INITIAL_PASSWORD ACTIVE_PASSWORD

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
[[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] ||
  fail "harness and deployment must use the same exact commit"
[[ -z "$(git -C "$REPO_ROOT" status --porcelain)" ]] ||
  fail "live evidence requires a clean worktree"
SCRIPT_SHA256="$(sha256sum "$SCRIPT_DIR/tenant_subject_profile_live.sh" | cut -d' ' -f1)"
COMMITTED_SCRIPT_SHA256="$(
  git -C "$REPO_ROOT" show "$EXPECTED_COMMIT:e2e/tenant_subject_profile_live.sh" |
    sha256sum | cut -d' ' -f1
)"
[[ "$SCRIPT_SHA256" == "$COMMITTED_SCRIPT_SHA256" ]] ||
  fail "subject profile harness does not match the exact deployed commit"

AUTH_FN="$(stack_output AuthFnName)"
CLIENTS_TABLE="$(stack_output ClientsTableName)"
aws lambda get-function-configuration \
  --function-name "$AUTH_FN" --profile "$PROFILE" --region "$REGION" \
  --output json >"$SECRETS/auth.json"
jq -e --arg commit "$EXPECTED_COMMIT" '
  .State == "Active"
  and .LastUpdateStatus == "Successful"
  and .Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  and .Environment.Variables.AGENT_AUTH_FORM == "saas"
  and .Environment.Variables.AGENT_AUTH_ENABLE_TENANT_PARTITIONING == "1"
' "$SECRETS/auth.json" >/dev/null ||
  fail "runtime is not the expected active tenant-partitioned deployment"
ZONE="$(jq -er '.Environment.Variables.AGENT_AUTH_ZONE' "$SECRETS/auth.json")"
BOOTSTRAP_ARN="$(
  jq -er '.Environment.Variables.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN' \
    "$SECRETS/auth.json"
)"
aws secretsmanager get-secret-value \
  --secret-id "$BOOTSTRAP_ARN" --profile "$PROFILE" --region "$REGION" \
  --query SecretString --output text >"$SECRETS/bootstrap.json"
jq -e --arg a "$TENANT_A" --arg b "$TENANT_B" '
  .tenant_subject_types[$a] == null
  and .tenant_subject_types[$b] == "public"
' "$SECRETS/bootstrap.json" >/dev/null ||
  fail "runtime bootstrap does not encode pairwise-default tenant A and public tenant B"

for tenant in "$TENANT_A" "$TENANT_B"; do
  admin_arn="$(jq -er --arg tenant "$tenant" \
    '.tenant_admin_secret_arns[$tenant]' "$SECRETS/bootstrap.json")"
  aws secretsmanager get-secret-value \
    --secret-id "$admin_arn" --profile "$PROFILE" --region "$REGION" \
    --output json |
    jq -jer '.SecretString | fromjson | .current.secret
      | select(type == "string" and length >= 16)' >"$SECRETS/$tenant-admin.token"
  printf 'header = "authorization: Bearer %s"\n' \
    "$(<"$SECRETS/$tenant-admin.token")" >"$SECRETS/$tenant-admin.curl"
  rm -f "$SECRETS/$tenant-admin.token"
done
rm -f "$SECRETS/bootstrap.json"

for tenant in "$TENANT_A" "$TENANT_B"; do
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    "https://$tenant.$ZONE/.well-known/openid-configuration" \
    >"$WORK/$tenant-discovery.json"
done
jq -e --arg issuer "https://$TENANT_A.$ZONE" '
  .issuer == $issuer and .subject_types_supported == ["pairwise"]
' "$WORK/$TENANT_A-discovery.json" >/dev/null ||
  fail "tenant A discovery does not declare its pairwise profile"
jq -e --arg issuer "https://$TENANT_B.$ZONE" '
  .issuer == $issuer and .subject_types_supported == ["public"]
' "$WORK/$TENANT_B-discovery.json" >/dev/null ||
  fail "tenant B discovery does not declare its public profile"

printf '%s' "https://c1-1b-$RUN_ID.invalid/cb" >"$WORK/$TENANT_A.redirect"
cp "$WORK/$TENANT_A.redirect" "$WORK/$TENANT_B.redirect"
printf '%s' "https://c1-1b-secondary-$RUN_ID.invalid/cb" \
  >"$WORK/$TENANT_A-secondary.redirect"
cp "$WORK/$TENANT_A-secondary.redirect" "$WORK/$TENANT_B-secondary.redirect"
printf '%s' "https://c1-1b-a-$RUN_ID.invalid/cb" >"$WORK/multi-a.redirect"
printf '%s' "https://c1-1b-b-$RUN_ID.invalid/cb" >"$WORK/multi-b.redirect"

jq -n --rawfile a "$WORK/multi-a.redirect" --rawfile b "$WORK/multi-b.redirect" '{
  redirect_uris:[$a,$b],
  application_type:"web",
  token_endpoint_auth_method:"none"
}' >"$WORK/multi-host-client.json"
EXTRA_PAIRWISE_INTENT=1
MULTI_A_STATUS="$(admin_request "$TENANT_A" POST /admin/clients \
  "$WORK/multi-host-client.json" "$WORK/multi-a-response.json")"
[[ "$MULTI_A_STATUS" == "400" ]] ||
  fail "pairwise tenant accepted ambiguous multi-host client metadata"
EXTRA_PUBLIC_INTENT=1
MULTI_B_STATUS="$(admin_request "$TENANT_B" POST /admin/clients \
  "$WORK/multi-host-client.json" "$WORK/multi-b-response.json")"
[[ "$MULTI_B_STATUS" == "201" ]] ||
  fail "public tenant rejected valid multi-host client metadata"
EXTRA_PUBLIC_CLIENT="$(jq -er '.client_id' "$WORK/multi-b-response.json")"

for tenant in "$TENANT_A" "$TENANT_B"; do
  python3 - "$EMAIL" "$SECRETS/initial.password" >"$SECRETS/$tenant-create-user.json" <<'PY'
import json
import pathlib
import sys
print(json.dumps({
    "email": sys.argv[1],
    "initial_password": pathlib.Path(sys.argv[2]).read_text(),
}))
PY
  USER_INTENTS[$tenant]=1
  status="$(admin_request "$tenant" POST /admin/users \
    "$SECRETS/$tenant-create-user.json" "$SECRETS/$tenant-create-user-response.json")"
  [[ "$status" == "201" ]] || fail "$tenant user creation returned HTTP $status"
  USER_IDS[$tenant]="$(jq -er '.user_id' "$SECRETS/$tenant-create-user-response.json")"

  python3 - "$EMAIL" "$SECRETS/initial.password" "$SECRETS/active.password" \
    >"$SECRETS/$tenant-change-password.json" <<'PY'
import json
import pathlib
import sys
print(json.dumps({
    "email": sys.argv[1],
    "current_password": pathlib.Path(sys.argv[2]).read_text(),
    "new_password": pathlib.Path(sys.argv[3]).read_text(),
}))
PY
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o "$SECRETS/$tenant-change-response.json" -w '%{http_code}' \
    --cookie-jar "$SECRETS/$tenant.cookies" -X POST \
    -H 'content-type: application/json' \
    --data-binary "@$SECRETS/$tenant-change-password.json" \
    "https://$tenant.$ZONE/login/password/change")"
  [[ "$status" == "200" ]] || fail "$tenant password activation returned HTTP $status"

  jq -n --rawfile redirect "$WORK/$tenant.redirect" '{
    redirect_uris:[$redirect],
    application_type:"web",
    token_endpoint_auth_method:"none"
  }' >"$WORK/$tenant-create-client.json"
  CLIENT_INTENTS[$tenant]=1
  status="$(admin_request "$tenant" POST /admin/clients \
    "$WORK/$tenant-create-client.json" "$WORK/$tenant-create-client-response.json")"
  [[ "$status" == "201" ]] || fail "$tenant client creation returned HTTP $status"
  CLIENT_IDS[$tenant]="$(jq -er '.client_id' "$WORK/$tenant-create-client-response.json")"

  jq -n --rawfile redirect "$WORK/$tenant-secondary.redirect" '{
    redirect_uris:[$redirect],
    application_type:"web",
    token_endpoint_auth_method:"none"
  }' >"$WORK/$tenant-secondary-create-client.json"
  SECOND_CLIENT_INTENTS[$tenant]=1
  status="$(admin_request "$tenant" POST /admin/clients \
    "$WORK/$tenant-secondary-create-client.json" \
    "$WORK/$tenant-secondary-create-client-response.json")"
  [[ "$status" == "201" ]] ||
    fail "$tenant secondary client creation returned HTTP $status"
  SECOND_CLIENT_IDS[$tenant]="$(
    jq -er '.client_id' "$WORK/$tenant-secondary-create-client-response.json"
  )"
done

run_code_flow() {
  local tenant="$1" label="$2" client="$3" redirect_file="$4"
  local redirect verifier challenge query status location consent_query csrf code
  redirect="$(<"$redirect_file")"
  verifier="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
  challenge="$(python3 - "$verifier" <<'PY'
import base64
import hashlib
import sys
print(base64.urlsafe_b64encode(
    hashlib.sha256(sys.argv[1].encode()).digest()
).rstrip(b"=").decode())
PY
)"
  query="$(python3 - "$client" "$redirect" "$challenge" "$tenant" <<'PY'
import sys
import urllib.parse
print(urllib.parse.urlencode({
    "response_type":"code", "client_id":sys.argv[1],
    "redirect_uri":sys.argv[2], "scope":"openid",
    "state":"c1-1b-" + sys.argv[4],
    "code_challenge":sys.argv[3], "code_challenge_method":"S256",
}))
PY
)"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o /dev/null -D "$SECRETS/$tenant-$label-authorize.headers" -w '%{http_code}' \
    --cookie "$SECRETS/$tenant.cookies" \
    "https://$tenant.$ZONE/authorize?$query")"
  [[ "$status" == "303" ]] || fail "$tenant authorization did not enter consent"
  location="$(awk '
    BEGIN { IGNORECASE=1 }
    /^location:/ {
      sub(/\r$/, ""); sub(/^[^:]+:[[:space:]]*/, ""); print
    }
  ' "$SECRETS/$tenant-$label-authorize.headers" | tail -1)"
  consent_query="$(python3 - "$location" "$client" <<'PY'
import sys
import urllib.parse
parsed = urllib.parse.urlparse(sys.argv[1])
params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
assert parsed.path == "/consent"
assert params.get("client_id") == [sys.argv[2]]
assert len(params.get("authz_session_id", [])) == 1
print(parsed.query)
PY
)" || fail "$tenant consent redirect is malformed"
  csrf="$(curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    --cookie "$SECRETS/$tenant.cookies" \
    "https://$tenant.$ZONE/consent/context?$consent_query" |
    jq -er '.csrf_token')"
  jq -n --arg csrf "$csrf" --arg query "$consent_query" \
    '{decision:"approve",csrf:$csrf,authorize_query:$query}' \
    >"$SECRETS/$tenant-$label-consent.json"
  curl -fsS --proto '=https' --connect-timeout 5 --max-time 30 \
    --cookie "$SECRETS/$tenant.cookies" -X POST \
    -H 'content-type: application/json' \
    --data-binary "@$SECRETS/$tenant-$label-consent.json" \
    "https://$tenant.$ZONE/consent/decision" \
    >"$SECRETS/$tenant-$label-consent-response.json"
  code="$(python3 - "$SECRETS/$tenant-$label-consent-response.json" <<'PY'
import json
import pathlib
import sys
import urllib.parse
body = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(urllib.parse.parse_qs(
    urllib.parse.urlparse(body["redirect"]).query)["code"][0])
PY
)"
  python3 - "$code" "$verifier" "$redirect" "$client" \
    >"$SECRETS/$tenant-$label-token.form" <<'PY'
import sys
import urllib.parse
print(urllib.parse.urlencode({
    "grant_type":"authorization_code", "code":sys.argv[1],
    "code_verifier":sys.argv[2], "redirect_uri":sys.argv[3],
    "client_id":sys.argv[4],
}), end="")
PY
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 60 \
    -o "$SECRETS/$tenant-$label-token.json" -w '%{http_code}' -X POST \
    -H 'content-type: application/x-www-form-urlencoded' \
    --data-binary "@$SECRETS/$tenant-$label-token.form" \
    "https://$tenant.$ZONE/token")"
  [[ "$status" == "200" ]] || fail "$tenant code exchange returned HTTP $status"
  jq -jer '.id_token | select(type == "string" and length > 0)' \
    "$SECRETS/$tenant-$label-token.json" >"$SECRETS/$tenant-$label.id-token"
  jq -jer '.access_token | select(type == "string" and length > 0)' \
    "$SECRETS/$tenant-$label-token.json" >"$SECRETS/$tenant-$label-access.token"
  printf 'header = "authorization: Bearer %s"\n' \
    "$(<"$SECRETS/$tenant-$label-access.token")" >"$SECRETS/$tenant-$label-userinfo.curl"
  rm -f "$SECRETS/$tenant-$label-access.token"
  status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
    -o "$SECRETS/$tenant-$label-userinfo.json" -w '%{http_code}' \
    --config "$SECRETS/$tenant-$label-userinfo.curl" \
    "https://$tenant.$ZONE/userinfo")"
  [[ "$status" == "200" ]] || fail "$tenant userinfo returned HTTP $status"
  python3 - "$SECRETS/$tenant-$label.id-token" \
    >"$SECRETS/$tenant-$label-claims.json" <<'PY'
import base64
import json
import pathlib
import sys
parts = pathlib.Path(sys.argv[1]).read_text().split(".")
assert len(parts) == 3
payload = parts[1] + "=" * (-len(parts[1]) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), sort_keys=True))
PY
  rm -f \
    "$SECRETS/$tenant-$label.id-token" \
    "$SECRETS/$tenant-$label-token.json" \
    "$SECRETS/$tenant-$label-userinfo.curl"
  jq -e --arg sub "$(jq -er '.sub' "$SECRETS/$tenant-$label-claims.json")" \
    '.sub == $sub' "$SECRETS/$tenant-$label-userinfo.json" >/dev/null ||
    fail "$tenant userinfo subject differs from the ID token"
}

run_code_flow "$TENANT_A" primary "${CLIENT_IDS[$TENANT_A]}" \
  "$WORK/$TENANT_A.redirect"
run_code_flow "$TENANT_A" secondary "${SECOND_CLIENT_IDS[$TENANT_A]}" \
  "$WORK/$TENANT_A-secondary.redirect"
run_code_flow "$TENANT_B" primary "${CLIENT_IDS[$TENANT_B]}" \
  "$WORK/$TENANT_B.redirect"
run_code_flow "$TENANT_B" secondary "${SECOND_CLIENT_IDS[$TENANT_B]}" \
  "$WORK/$TENANT_B-secondary.redirect"
A_SUB="$(jq -er '.sub' "$SECRETS/$TENANT_A-primary-claims.json")"
A_SECOND_SUB="$(jq -er '.sub' "$SECRETS/$TENANT_A-secondary-claims.json")"
B_SUB="$(jq -er '.sub' "$SECRETS/$TENANT_B-primary-claims.json")"
B_SECOND_SUB="$(jq -er '.sub' "$SECRETS/$TENANT_B-secondary-claims.json")"
jq -e --arg issuer "https://$TENANT_A.$ZONE" '.iss == $issuer' \
  "$SECRETS/$TENANT_A-primary-claims.json" >/dev/null ||
  fail "tenant A ID token issuer is wrong"
jq -e --arg issuer "https://$TENANT_B.$ZONE" '.iss == $issuer' \
  "$SECRETS/$TENANT_B-primary-claims.json" >/dev/null ||
  fail "tenant B ID token issuer is wrong"
[[ "$A_SUB" != "${USER_IDS[$TENANT_A]}" && "$A_SUB" != "$EMAIL" ]] ||
  fail "pairwise tenant exposed the canonical user identifier"
[[ "$A_SECOND_SUB" != "${USER_IDS[$TENANT_A]}" && "$A_SECOND_SUB" != "$EMAIL" ]] ||
  fail "pairwise tenant secondary sector exposed the canonical user identifier"
[[ "$A_SUB" != "$A_SECOND_SUB" ]] ||
  fail "pairwise tenant reused one subject across distinct sectors"
[[ "$B_SUB" == "${USER_IDS[$TENANT_B]}" ]] ||
  fail "public tenant did not issue its canonical user identifier"
[[ "$B_SECOND_SUB" == "${USER_IDS[$TENANT_B]}" ]] ||
  fail "public tenant changed subject across distinct sectors"
[[ "$A_SUB" != "$B_SUB" ]] ||
  fail "pairwise and public tenant subjects unexpectedly match"
check_ok "discovery, metadata, cross-sector and userinfo subjects use tenant profiles"

cleanup || fail "temporary authority cleanup did not converge"
trap - EXIT INT TERM
[[ "$CLEANED" == "1" ]] || fail "temporary authority cleanup was not verified"

jq -n \
  --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg commit "$EXPECTED_COMMIT" \
  --arg script_sha256 "$SCRIPT_SHA256" \
  --arg tenant_a "$TENANT_A" \
  --arg tenant_b "$TENANT_B" '{
    schema:"agent-auth-c1-1b-evidence-v1",
    requirement:"C1.1b",
    completed_at:$completed_at,
    deployment_commit:$commit,
    harness_commit:$commit,
    script_sha256:$script_sha256,
    tenant_ids:[$tenant_a,$tenant_b],
    assertions:{
      tenant_a_discovery_pairwise:"pass",
      tenant_b_discovery_public:"pass",
      pairwise_multi_host_metadata_rejected:"pass",
      public_multi_host_metadata_accepted:"pass",
      tenant_a_id_token_pairwise:"pass",
      tenant_b_id_token_public:"pass",
      pairwise_cross_sector_subjects_differ:"pass",
      public_cross_sector_subjects_match:"pass",
      id_token_and_userinfo_subjects_match:"pass",
      issuer_and_subject_profiles_isolated:"pass",
      temporary_authority_cleanup:"pass"
    },
    sensitive_values_in_evidence:false
  }' >"$EVIDENCE_FILE"
chmod 0600 "$EVIDENCE_FILE"
printf 'PASS: C1.1b tenant subject profile evidence published\n'
printf 'C1.1b evidence: %s\n' "$EVIDENCE_FILE"
printf 'C1.1b evidence sha256: %s\n' \
  "$(sha256sum "$EVIDENCE_FILE" | cut -d' ' -f1)"

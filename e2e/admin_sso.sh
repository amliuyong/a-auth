#!/usr/bin/env bash
# Live Admin OIDC SSO acceptance for issue #20 / C12.3.
#
# The script discovers AgentAuthDev and AgentAuthSaas, creates disposable
# Cognito clients plus one test user, provisions tenant-local SCIM users/groups,
# and runs real Hosted UI OIDC round trips for Dev, t1, and t2. It restores any
# prior OIDC config and fixed client-secret value on exit.
#
# Required:
#   AWS profile with CloudFormation/Lambda/Secrets Manager/DynamoDB/Cognito access.
#   Existing .env values FED_COGNITO_{POOL_ID,ISSUER,AUTHORIZE,TOKEN,JWKS}.
#
# Usage:
#   AWS_PROFILE=default ./e2e/admin_sso.sh
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

PROFILE="${PROFILE:-${AWS_PROFILE:-default}}"
REGION="${REGION:-${AWS_REGION:-us-east-1}}"
DEV_STACK="${DEV_STACK:-AgentAuthDev}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
POOL_ID="${FED_COGNITO_POOL_ID:?FED_COGNITO_POOL_ID is required}"
OIDC_ISSUER="${FED_COGNITO_ISSUER:?FED_COGNITO_ISSUER is required}"
OIDC_AUTHORIZE="${FED_COGNITO_AUTHORIZE:?FED_COGNITO_AUTHORIZE is required}"
OIDC_TOKEN="${FED_COGNITO_TOKEN:?FED_COGNITO_TOKEN is required}"
OIDC_JWKS="${FED_COGNITO_JWKS:?FED_COGNITO_JWKS is required}"
RUN_ID="${ADMIN_SSO_RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$RANDOM}"

umask 077
WORK="$(mktemp -d)"
TARGETS=(dev t1 t2)
declare -A BASE TENANT STORAGE ROLE ADMIN_ARN SCIM_ARN USERS_TABLE
declare -A ADMIN_TOKEN SCIM_TOKEN CLIENT_ID CLIENT_SECRET_FILE SECRET_NAME
declare -A SECRET_EXISTED SECRET_PRESENT ORIGINAL_SECRET_VERSION TEST_SECRET_VERSION SECRET_MUTATED
declare -A ORIGINAL_CONFIG ORIGINAL_CONFIG_STATUS TEST_CONFIG_REVISION CONFIG_MUTATED
declare -A USER_ID GROUP_ID
COGNITO_USERNAME=""
CLIENT_IDS=()

pass() { printf 'PASS: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
require() { command -v "$1" >/dev/null || fail "missing command: $1"; }

for command in aws curl jq openssl python3; do
  require "$command"
done

stack_output() {
  local stack="$1" key="$2"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$stack" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

auth_runtime() {
  local stack="$1" output="$2"
  local resources="$WORK/$stack.resources.json" fn
  aws cloudformation list-stack-resources \
    --profile "$PROFILE" --region "$REGION" --stack-name "$stack" \
    --output json >"$resources"
  fn="$(
    jq -er '
      [.StackResourceSummaries[]
       | select(.ResourceType == "AWS::Lambda::Function")
       | select(.LogicalResourceId | startswith("AuthFn"))
       | .PhysicalResourceId]
      | unique
      | if length == 1 then .[0] else error("expected exactly one AuthFn") end
    ' "$resources"
  )"
  aws lambda get-function-configuration \
    --profile "$PROFILE" --region "$REGION" --function-name "$fn" \
    --query 'Environment.Variables' --output json >"$output"
}

load_credential() {
  local name="$1" arn="$2"
  local output="$WORK/$name.token"
  aws secretsmanager get-secret-value \
    --profile "$PROFILE" --region "$REGION" --secret-id "$arn" \
    --query SecretString --output text |
    jq -er '.current.secret | select(type == "string" and length >= 16)' >"$output"
  chmod 0600 "$output"
  printf '%s\n' "$output"
}

request() {
  local name="$1" method="$2" url="$3" token_file="${4:-}" body_file="${5:-}"
  local content_type="${6:-application/json}"
  local headers="$WORK/$name.request-headers"
  local -a args=(
    -sS --proto '=https' --connect-timeout 5 --max-time 30
    -X "$method" -H "@$headers"
    -D "$WORK/$name.headers" -o "$WORK/$name.body"
    -w '%{http_code}' "$url"
  )
  : >"$headers"
  if [[ -n "$token_file" ]]; then
    printf 'authorization: Bearer %s\n' "$(<"$token_file")" >>"$headers"
  fi
  if [[ -n "$body_file" ]]; then
    printf 'content-type: %s\n' "$content_type" >>"$headers"
    args+=(--data-binary "@$body_file")
  fi
  curl "${args[@]}" >"$WORK/$name.status"
}

assert_status() {
  local name="$1" expected="$2" actual
  actual="$(<"$WORK/$name.status")"
  [[ "$actual" == "$expected" ]] ||
    fail "$name expected HTTP $expected, got $actual: $(<"$WORK/$name.body")"
}

physical_user_id() {
  local storage="$1" logical="$2"
  if [[ -n "$storage" ]]; then
    printf '%s\x1f%s' "$storage" "$logical"
  else
    printf '%s' "$logical"
  fi
}

delete_scim_user_rows() {
  local target="$1" logical_id="$2" canonical values rows
  [[ -n "$logical_id" ]] || return 0
  canonical="$(physical_user_id "${STORAGE[$target]}" "$logical_id")"
  values="$(jq -cn --arg canonical "$canonical" '{":canonical":{S:$canonical}}')"
  rows="$WORK/$target.user-rows.json"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" \
    --table-name "${USERS_TABLE[$target]}" \
    --projection-expression user_id \
    --filter-expression 'user_id = :canonical OR canonical_user_id = :canonical' \
    --expression-attribute-values "$values" --output json >"$rows"
  while IFS= read -r physical; do
    [[ -n "$physical" ]] || continue
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" \
      --table-name "${USERS_TABLE[$target]}" \
      --key "$(jq -cn --arg value "$physical" '{user_id:{S:$value}}')" >/dev/null
  done < <(jq -r '.Items[].user_id.S' "$rows")
}

restore_target() {
  local target="$1" payload name current_secret_version restore_status config_needs_restore=0
  [[ "${SECRET_MUTATED[$target]:-0}" == "1" ||
    "${CONFIG_MUTATED[$target]:-0}" == "1" ]] || return 0

  if [[ "${CONFIG_MUTATED[$target]:-0}" == "1" ]]; then
    name="cleanup-$target-config-get"
    request "$name" GET "${BASE[$target]}/admin/oidc" "${ADMIN_TOKEN[$target]}" || return 1
    case "$(<"$WORK/$name.status")" in
      200)
        if jq -e \
          --arg client_id "${CLIENT_ID[$target]}" \
          --argjson revision "${TEST_CONFIG_REVISION[$target]}" \
          '.client_id == $client_id and .client_secret_configured == true and
           .revision == $revision' "$WORK/$name.body" >/dev/null; then
          config_needs_restore=1
        elif [[ "${ORIGINAL_CONFIG_STATUS[$target]}" == "200" ]] &&
          jq -e --slurpfile old "${ORIGINAL_CONFIG[$target]}" \
            '. == $old[0]' "$WORK/$name.body" >/dev/null; then
          config_needs_restore=0
        else
          printf 'CLEANUP REFUSED: %s Admin OIDC config changed concurrently\n' "$target" >&2
          return 1
        fi
        ;;
      404)
        if [[ "${ORIGINAL_CONFIG_STATUS[$target]}" != "404" ]]; then
          printf 'CLEANUP REFUSED: %s Admin OIDC config was removed concurrently\n' "$target" >&2
          return 1
        fi
        ;;
      *)
        printf 'CLEANUP FAILED: %s cannot read current Admin OIDC config\n' "$target" >&2
        return 1
        ;;
    esac
  fi

  if [[ "${SECRET_MUTATED[$target]:-0}" == "1" ]]; then
    current_secret_version="$(
      aws secretsmanager get-secret-value \
        --profile "$PROFILE" --region "$REGION" \
        --secret-id "${SECRET_NAME[$target]}" \
        --query VersionId --output text
    )" || return 1
    [[ "$current_secret_version" == "${TEST_SECRET_VERSION[$target]}" ]] || {
      printf 'CLEANUP REFUSED: %s Admin OIDC secret changed concurrently\n' "$target" >&2
      return 1
    }
  fi

  if [[ "$config_needs_restore" == "1" ]]; then
    if [[ "${ORIGINAL_CONFIG_STATUS[$target]}" == "200" ]]; then
      payload="$WORK/$target.restore-config.json"
      jq -n \
        --slurpfile old "${ORIGINAL_CONFIG[$target]}" \
        --arg secret "${SECRET_NAME[$target]}" \
        --argjson revision "${TEST_CONFIG_REVISION[$target]}" '{
          issuer:$old[0].issuer,
          client_id:$old[0].client_id,
          client_secret_ref:$secret,
          authorization_endpoint:$old[0].authorization_endpoint,
          token_endpoint:$old[0].token_endpoint,
          jwks_uri:$old[0].jwks_uri,
          redirect_uri:$old[0].redirect_uri,
          scopes:$old[0].scopes,
          strong_acr_values:($old[0].strong_acr_values // []),
          identity_claim:$old[0].identity_claim,
          identity_field:$old[0].identity_field,
          expected_revision:$revision
        }' >"$payload"
      name="cleanup-$target-config-put"
      request "$name" PUT "${BASE[$target]}/admin/oidc" \
        "${ADMIN_TOKEN[$target]}" "$payload" || return 1
      restore_status="200"
    else
      name="cleanup-$target-config-delete"
      request "$name" DELETE \
        "${BASE[$target]}/admin/oidc?expected_revision=${TEST_CONFIG_REVISION[$target]}" \
        "${ADMIN_TOKEN[$target]}" || return 1
      restore_status="204"
    fi
    [[ "$(<"$WORK/$name.status")" == "$restore_status" ]] || {
      printf 'CLEANUP FAILED: %s Admin OIDC config restore returned HTTP %s\n' \
        "$target" "$(<"$WORK/$name.status")" >&2
      return 1
    }
  fi

  if [[ "${SECRET_MUTATED[$target]:-0}" == "1" ]]; then
    if [[ "${SECRET_EXISTED[$target]}" == "1" ]]; then
      aws secretsmanager update-secret-version-stage \
        --profile "$PROFILE" --region "$REGION" \
        --secret-id "${SECRET_NAME[$target]}" \
        --version-stage AWSCURRENT \
        --move-to-version-id "${ORIGINAL_SECRET_VERSION[$target]}" \
        --remove-from-version-id "${TEST_SECRET_VERSION[$target]}" >/dev/null || return 1
    else
      aws secretsmanager delete-secret \
        --profile "$PROFILE" --region "$REGION" \
        --secret-id "${SECRET_NAME[$target]}" \
        --force-delete-without-recovery >/dev/null || return 1
    fi
  fi
}

cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT INT TERM
  set +e
  for target in "${TARGETS[@]}"; do
    restore_target "$target" || cleanup_failed=1
  done
  for target in "${TARGETS[@]}"; do
    if [[ -n "${GROUP_ID[$target]:-}" && -n "${SCIM_TOKEN[$target]:-}" ]]; then
      request "cleanup-$target-group" DELETE \
        "${BASE[$target]}/scim/v2/Groups/${GROUP_ID[$target]}" \
        "${SCIM_TOKEN[$target]}" || cleanup_failed=1
      case "$(<"$WORK/cleanup-$target-group.status")" in
        204|404) ;;
        *) cleanup_failed=1 ;;
      esac
    fi
    if [[ -n "${USER_ID[$target]:-}" && -n "${USERS_TABLE[$target]:-}" ]]; then
      delete_scim_user_rows "$target" "${USER_ID[$target]}" || cleanup_failed=1
    fi
  done
  for client_id in "${CLIENT_IDS[@]}"; do
    aws cognito-idp delete-user-pool-client \
      --profile "$PROFILE" --region "$REGION" \
      --user-pool-id "$POOL_ID" --client-id "$client_id" >/dev/null 2>&1 ||
      cleanup_failed=1
  done
  if [[ -n "$COGNITO_USERNAME" ]]; then
    aws cognito-idp admin-delete-user \
      --profile "$PROFILE" --region "$REGION" \
      --user-pool-id "$POOL_ID" --username "$COGNITO_USERNAME" >/dev/null 2>&1 ||
      cleanup_failed=1
  fi
  if [[ "$cleanup_failed" == "1" ]]; then
    printf 'CLEANUP FAILED: inspect Admin OIDC config/secret and disposable resources\n' >&2
    [[ "$status" -ne 0 ]] || status=1
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT INT TERM

for stack in "$DEV_STACK" "$SAAS_STACK"; do
  status="$(
    aws cloudformation describe-stacks \
      --profile "$PROFILE" --region "$REGION" --stack-name "$stack" \
      --query 'Stacks[0].StackStatus' --output text
  )"
  [[ "$status" == "UPDATE_COMPLETE" ]] ||
    fail "$stack must be UPDATE_COMPLETE, got $status"
done

auth_runtime "$DEV_STACK" "$WORK/dev.runtime.json"
auth_runtime "$SAAS_STACK" "$WORK/saas.runtime.json"
aws secretsmanager get-secret-value \
  --profile "$PROFILE" --region "$REGION" \
  --secret-id "$(jq -er '.AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN' "$WORK/saas.runtime.json")" \
  --query SecretString --output text >"$WORK/saas.bootstrap.json"
jq -e '
  .schema_version == 1 and
  (.saas_tenants == ["t1", "t2"]) and
  (.tenant_admin_secret_arns | keys | sort) == ["t1", "t2"]
' "$WORK/saas.bootstrap.json" >/dev/null ||
  fail "deployed SaaS bootstrap config is malformed"

BASE[dev]="$(stack_output "$DEV_STACK" AdminUrl)"
BASE[dev]="${BASE[dev]%/admin}"
BASE[t1]="https://t1.$(jq -er '.AGENT_AUTH_ZONE' "$WORK/saas.runtime.json")"
BASE[t2]="https://t2.$(jq -er '.AGENT_AUTH_ZONE' "$WORK/saas.runtime.json")"
TENANT[dev]="default"
TENANT[t1]="t1"
TENANT[t2]="t2"
STORAGE[dev]=""
STORAGE[t1]="t1"
STORAGE[t2]="t2"
ROLE[dev]="owner"
ROLE[t1]="auditor"
ROLE[t2]="admin"

ADMIN_ARN[dev]="$(stack_output "$DEV_STACK" AdminSecretArn)"
SCIM_ARN[dev]="$(stack_output "$DEV_STACK" ScimSecretArn)"
USERS_TABLE[dev]="$(stack_output "$DEV_STACK" UsersTableName)"
SAAS_ADMIN_ARNS="$(jq -cer '.tenant_admin_secret_arns' "$WORK/saas.bootstrap.json")"
SAAS_SCIM_ARNS="$(stack_output "$SAAS_STACK" ScimSecretArns)"
for target in t1 t2; do
  ADMIN_ARN[$target]="$(jq -er --arg tenant "$target" '.[$tenant]' <<<"$SAAS_ADMIN_ARNS")"
  SCIM_ARN[$target]="$(jq -er --arg tenant "$target" '.[$tenant]' <<<"$SAAS_SCIM_ARNS")"
  USERS_TABLE[$target]="$(stack_output "$SAAS_STACK" UsersTableName)"
done

for target in "${TARGETS[@]}"; do
  [[ "${BASE[$target]}" == https://* ]] || fail "$target origin is not HTTPS"
  ADMIN_TOKEN[$target]="$(load_credential "$target-admin" "${ADMIN_ARN[$target]}")"
  SCIM_TOKEN[$target]="$(load_credential "$target-scim" "${SCIM_ARN[$target]}")"
  SECRET_NAME[$target]="agent-auth/admin-oidc/${TENANT[$target]}"
  ORIGINAL_CONFIG[$target]="$WORK/$target.original-config.json"
  USER_ID[$target]=""
  GROUP_ID[$target]=""
  SECRET_MUTATED[$target]="0"
  CONFIG_MUTATED[$target]="0"

  request "$target-config-save" GET "${BASE[$target]}/admin/oidc" \
    "${ADMIN_TOKEN[$target]}"
  ORIGINAL_CONFIG_STATUS[$target]="$(<"$WORK/$target-config-save.status")"
  case "${ORIGINAL_CONFIG_STATUS[$target]}" in
    200) cp "$WORK/$target-config-save.body" "${ORIGINAL_CONFIG[$target]}" ;;
    404) printf '{}\n' >"${ORIGINAL_CONFIG[$target]}" ;;
    *) fail "$target cannot read current OIDC config" ;;
  esac

  secret_description="$WORK/$target.secret-description.json"
  if aws secretsmanager describe-secret \
    --profile "$PROFILE" --region "$REGION" \
    --secret-id "${SECRET_NAME[$target]}" >"$secret_description" 2>/dev/null; then
    if jq -e '.DeletedDate != null' "$secret_description" >/dev/null; then
      fail "$target Admin OIDC secret is pending deletion; restore or remove it deliberately before acceptance"
    else
      SECRET_EXISTED[$target]="1"
      SECRET_PRESENT[$target]="1"
      aws secretsmanager get-secret-value \
        --profile "$PROFILE" --region "$REGION" \
        --secret-id "${SECRET_NAME[$target]}" \
        --query VersionId --output text >"$WORK/$target.original-secret-version"
      ORIGINAL_SECRET_VERSION[$target]="$(<"$WORK/$target.original-secret-version")"
    fi
  else
    SECRET_EXISTED[$target]="0"
    SECRET_PRESENT[$target]="0"
  fi
done
pass "discovered Dev/t1/t2 origins and saved existing OIDC state"

TEST_EMAIL="admin-sso-$RUN_ID@example.invalid"
TEST_PASSWORD_FILE="$WORK/cognito.password"
printf 'Aa1!%s%s\n' "$RANDOM" "$(openssl rand -hex 12)" >"$TEST_PASSWORD_FILE"
chmod 0600 "$TEST_PASSWORD_FILE"

aws cognito-idp admin-create-user \
  --profile "$PROFILE" --region "$REGION" --user-pool-id "$POOL_ID" \
  --username "$TEST_EMAIL" \
  --user-attributes Name=email,Value="$TEST_EMAIL" Name=email_verified,Value=true \
  --temporary-password "$(<"$TEST_PASSWORD_FILE")" --message-action SUPPRESS \
  --output json >"$WORK/cognito-user.json"
COGNITO_USERNAME="$(jq -er '.User.Username' "$WORK/cognito-user.json")"
aws cognito-idp admin-set-user-password \
  --profile "$PROFILE" --region "$REGION" --user-pool-id "$POOL_ID" \
  --username "$COGNITO_USERNAME" --password "$(<"$TEST_PASSWORD_FILE")" \
  --permanent >/dev/null
pass "created disposable Cognito Admin identity"

for target in "${TARGETS[@]}"; do
  client_json="$WORK/$target.cognito-client.json"
  aws cognito-idp create-user-pool-client \
    --profile "$PROFILE" --region "$REGION" --user-pool-id "$POOL_ID" \
    --client-name "agent-auth-admin-$target-$RUN_ID" --generate-secret \
    --callback-urls "${BASE[$target]}/admin/sso/callback" \
    --logout-urls "${BASE[$target]}/admin" \
    --allowed-o-auth-flows code \
    --allowed-o-auth-scopes openid email \
    --allowed-o-auth-flows-user-pool-client \
    --supported-identity-providers COGNITO \
    --prevent-user-existence-errors ENABLED \
    --output json >"$client_json"
  CLIENT_ID[$target]="$(jq -er '.UserPoolClient.ClientId' "$client_json")"
  CLIENT_IDS+=("${CLIENT_ID[$target]}")
  CLIENT_SECRET_FILE[$target]="$WORK/$target.client-secret"
  jq -jr '.UserPoolClient.ClientSecret' "$client_json" >"${CLIENT_SECRET_FILE[$target]}"
  chmod 0600 "${CLIENT_SECRET_FILE[$target]}"

  if [[ "${SECRET_PRESENT[$target]}" == "1" ]]; then
    aws secretsmanager put-secret-value \
      --profile "$PROFILE" --region "$REGION" \
      --secret-id "${SECRET_NAME[$target]}" \
      --secret-string "file://${CLIENT_SECRET_FILE[$target]}" \
      --query VersionId --output text >"$WORK/$target.test-secret-version"
  else
    aws secretsmanager create-secret \
      --profile "$PROFILE" --region "$REGION" \
      --name "${SECRET_NAME[$target]}" \
      --description "Disposable Admin OIDC live acceptance secret" \
      --secret-string "file://${CLIENT_SECRET_FILE[$target]}" \
      --query VersionId --output text >"$WORK/$target.test-secret-version"
  fi
  TEST_SECRET_VERSION[$target]="$(<"$WORK/$target.test-secret-version")"
  SECRET_MUTATED[$target]="1"
done
pass "created three tenant-specific Cognito clients and fixed-name secrets"

for target in "${TARGETS[@]}"; do
  user_body="$WORK/$target.scim-user.json"
  external_id="admin-sso-user-$target-$RUN_ID"
  jq -n \
    --arg external "$external_id" --arg email "$TEST_EMAIL" '{
      schemas:["urn:ietf:params:scim:schemas:core:2.0:User"],
      externalId:$external,
      userName:$email,
      displayName:"Admin SSO live acceptance",
      active:true
    }' >"$user_body"
  request "$target-user-create" POST "${BASE[$target]}/scim/v2/Users" \
    "${SCIM_TOKEN[$target]}" "$user_body" application/scim+json
  user_status="$(<"$WORK/$target-user-create.status")"
  [[ "$user_status" == "200" || "$user_status" == "201" ]] ||
    fail "$target SCIM User create returned $user_status"
  USER_ID[$target]="$(jq -er '.id' "$WORK/$target-user-create.body")"

  group_body="$WORK/$target.scim-group.json"
  group_external="admin-sso-group-$target-$RUN_ID"
  jq -n \
    --arg external "$group_external" --arg user "${USER_ID[$target]}" '{
      schemas:["urn:ietf:params:scim:schemas:core:2.0:Group"],
      externalId:$external,
      displayName:"Admin SSO live acceptance",
      members:[{value:$user,type:"User"}]
    }' >"$group_body"
  request "$target-group-create" POST "${BASE[$target]}/scim/v2/Groups" \
    "${SCIM_TOKEN[$target]}" "$group_body" application/scim+json
  assert_status "$target-group-create" 201
  GROUP_ID[$target]="$(jq -er '.id' "$WORK/$target-group-create.body")"

  role_body="$WORK/$target.role.json"
  jq -n --arg role "${ROLE[$target]}" '{role:$role}' >"$role_body"
  request "$target-role-map" PUT \
    "${BASE[$target]}/admin/scim/group-role-mappings/$group_external" \
    "${ADMIN_TOKEN[$target]}" "$role_body"
  assert_status "$target-role-map" 200

  expected_revision=0
  if [[ "${ORIGINAL_CONFIG_STATUS[$target]}" == "200" ]]; then
    expected_revision="$(jq -er '.revision' "${ORIGINAL_CONFIG[$target]}")"
  fi
  config_body="$WORK/$target.test-config.json"
  jq -n \
    --arg issuer "$OIDC_ISSUER" \
    --arg client_id "${CLIENT_ID[$target]}" \
    --arg secret "${SECRET_NAME[$target]}" \
    --arg authorize "$OIDC_AUTHORIZE" \
    --arg token "$OIDC_TOKEN" \
    --arg jwks "$OIDC_JWKS" \
    --arg redirect "${BASE[$target]}/admin/sso/callback" \
    --argjson revision "$expected_revision" '{
      issuer:$issuer,
      client_id:$client_id,
      client_secret_ref:$secret,
      authorization_endpoint:$authorize,
      token_endpoint:$token,
      jwks_uri:$jwks,
      redirect_uri:$redirect,
      scopes:["openid","email"],
      strong_acr_values:["urn:agent-auth:e2e:cognito-mfa"],
      identity_claim:"email",
      identity_field:"user_name",
      expected_revision:$revision
    }' >"$config_body"
  TEST_CONFIG_REVISION[$target]="$((expected_revision + 1))"
  CONFIG_MUTATED[$target]="1"
  request "$target-config-put" PUT "${BASE[$target]}/admin/oidc" \
    "${ADMIN_TOKEN[$target]}" "$config_body"
  assert_status "$target-config-put" 200
  jq -e --argjson revision "${TEST_CONFIG_REVISION[$target]}" \
    '.revision == $revision' "$WORK/$target-config-put.body" >/dev/null ||
    fail "$target Admin OIDC config returned an unexpected revision"
done
pass "provisioned tenant-local SCIM identities, role mappings, and OIDC configs"

jq -n \
  --arg dev "${BASE[dev]}" --arg t1 "${BASE[t1]}" --arg t2 "${BASE[t2]}" '[
    {name:"dev",base_url:$dev,role:"owner"},
    {name:"t1",base_url:$t1,role:"auditor"},
    {name:"t2",base_url:$t2,role:"admin"}
  ]' >"$WORK/targets.json"

ADMIN_SSO_TARGETS_FILE="$WORK/targets.json" \
TEST_USER="$TEST_EMAIL" \
TEST_PASSWORD_FILE="$TEST_PASSWORD_FILE" \
python3 "$ROOT/e2e/admin_sso_roundtrip.py"

pass "real Dev/t1/t2 Admin OIDC round trips, RBAC, isolation, and logout passed"
printf '\n=== Admin OIDC SSO live acceptance passed; cleanup will restore prior state ===\n'

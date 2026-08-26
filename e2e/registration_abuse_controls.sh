#!/usr/bin/env bash
# C10.8 live gate: tenant-global anonymous DCR quota on Dev plus CloudFront
# IP/Host/ASN WAF fallback on SaaS. The gate does not generate a production
# flood. It conditionally snapshots/exhausts/restores the Dev global bucket and
# uses an exact-commit block-only WAF probe header on SaaS.
set -euo pipefail
set +x

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
DEV_STACK="${DEV_STACK:-AgentAuthDev}"
SAAS_STACK="${SAAS_STACK:-AgentAuthSaas}"
TENANT="${TENANT:-t1}"
EXPECTED_COMMIT="${EXPECTED_COMMIT:-$(git -C "$ROOT" rev-parse HEAD)}"
EVIDENCE_FILE="${EVIDENCE_FILE:-/tmp/agent-auth-c10-8-$(date -u +%Y%m%dT%H%M%SZ).json}"
LOCAL_ASSET="$ROOT/target/lambda/agent-auth-lambda"
LOCAL_BOOTSTRAP="$LOCAL_ASSET/bootstrap"
LOCAL_PROVENANCE="$LOCAL_ASSET/deployment-provenance.json"

for command in aws base64 cmp curl git grep jq openssl python3 seq sha256sum sleep tr unzip; do
  command -v "$command" >/dev/null || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done
[[ "$EXPECTED_COMMIT" =~ ^[0-9a-f]{40}$ ]] || {
  echo "EXPECTED_COMMIT must be a full lowercase Git SHA" >&2
  exit 1
}
[[ -z "$(git -C "$ROOT" status --porcelain)" ]] || {
  echo "live evidence requires a clean worktree" >&2
  exit 1
}
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$EXPECTED_COMMIT" ]] || {
  echo "worktree HEAD does not match EXPECTED_COMMIT" >&2
  exit 1
}
[[ -x "$LOCAL_BOOTSTRAP" && -f "$LOCAL_PROVENANCE" ]] || {
  echo "exact-commit local Auth artifact/provenance is missing" >&2
  exit 1
}
LOCAL_BOOTSTRAP_SHA="$(sha256sum "$LOCAL_BOOTSTRAP" | cut -d' ' -f1)"
jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$LOCAL_BOOTSTRAP_SHA" '
  (keys | sort) == (["bootstrap_sha256","commit","schema"] | sort)
  and .schema == "agent-auth-lambda-provenance-v1"
  and .commit == $commit
  and .bootstrap_sha256 == $sha
' "$LOCAL_PROVENANCE" >/dev/null || {
  echo "local Auth provenance does not bind the exact commit/bootstrap" >&2
  exit 1
}

umask 077
WORK="$(mktemp -d)"
RUN_HEX="$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
GLOBAL_KEY="global-register-quota"
IP_A="2001:db8:${RUN_HEX:0:4}:${RUN_HEX:4:4}::1"
IP_B="2001:db8:${RUN_HEX:8:4}:${RUN_HEX:12:4}::2"
REDIRECT_A="https://c10-8-a-$RUN_HEX.invalid/callback"
REDIRECT_B="https://c10-8-b-$RUN_HEX.invalid/callback"
FUTURE_REFILL="$(( $(date +%s) + 300 + 16#${RUN_HEX:4:2} % 60 ))"
GLOBAL_SEEDED=0
GLOBAL_EXISTED=0
GLOBAL_SEEDED_VERSION=0
GLOBAL_EXPECTED_VERSION=0
IP_ROWS_OWNED=0
CLEANED=0

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  rm -f "$EVIDENCE_FILE"
  exit 1
}

stack_output() {
  local file="$1" key="$2"
  jq -er --arg key "$key" '
    .Stacks[0].Outputs[]
    | select(.OutputKey == $key)
    | .OutputValue
  ' "$file"
}

ddb_get() {
  local table="$1" key="$2" output="$3"
  aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$table" \
    --consistent-read --key "$(jq -cn --arg key "$key" '{key:{S:$key}}')" \
    --output json >"$output"
}

ddb_absent() {
  local table="$1" key="$2" output="$3"
  ddb_get "$table" "$key" "$output" || return 1
  [[ ! -s "$output" ]] && return 0
  jq -e 'has("Item") | not' "$output" >/dev/null
}

restore_global_bucket() {
  [[ "$GLOBAL_SEEDED" == "1" ]] || return 0
  local names values current
  current="$WORK/global.cleanup-current.json"
  ddb_get "$DEV_RATE_TABLE" "$GLOBAL_KEY" "$current" || return 1

  if [[ "$GLOBAL_EXISTED" == "1" ]]; then
    if [[ -s "$current" ]] && jq -e 'has("Item")' "$current" >/dev/null; then
      jq -S '.Item' "$WORK/global.before.json" >"$WORK/global.before.item"
      jq -S '.Item' "$current" >"$WORK/global.current.item"
      if cmp -s "$WORK/global.before.item" "$WORK/global.current.item"; then
        GLOBAL_SEEDED=0
        return 0
      fi
    fi
  elif [[ ! -s "$current" ]] || jq -e 'has("Item") | not' "$current" >/dev/null; then
    GLOBAL_SEEDED=0
    return 0
  fi

  jq -e --arg future "$FUTURE_REFILL" --arg seeded "$GLOBAL_SEEDED_VERSION" \
    --arg expected "$GLOBAL_EXPECTED_VERSION" '
      .Item.last_refill.N == $future
      and (.Item.version.N | tonumber) >= ($seeded | tonumber)
      and (.Item.version.N | tonumber) <= ($expected | tonumber)
    ' "$current" >/dev/null || return 1
  names='{"#last":"last_refill","#version":"version"}'
  values="$(jq -cn --arg future "$FUTURE_REFILL" \
    --arg seeded "$GLOBAL_SEEDED_VERSION" --arg expected "$GLOBAL_EXPECTED_VERSION" '{
      ":future":{N:$future},":seeded":{N:$seeded},":expected":{N:$expected}
    }')"
  if [[ "$GLOBAL_EXISTED" == "1" ]]; then
    aws dynamodb put-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$DEV_RATE_TABLE" \
      --item "$(jq -c '.Item' "$WORK/global.before.json")" \
      --condition-expression \
        '#last = :future AND #version BETWEEN :seeded AND :expected' \
      --expression-attribute-names "$names" \
      --expression-attribute-values "$values" >/dev/null || return 1
    ddb_get "$DEV_RATE_TABLE" "$GLOBAL_KEY" "$WORK/global.restored.json" || return 1
    jq -S '.Item' "$WORK/global.restored.json" >"$WORK/global.restored.item"
    cmp "$WORK/global.before.item" "$WORK/global.restored.item" || return 1
  else
    aws dynamodb delete-item \
      --profile "$PROFILE" --region "$REGION" --table-name "$DEV_RATE_TABLE" \
      --key "$(jq -cn --arg key "$GLOBAL_KEY" '{key:{S:$key}}')" \
      --condition-expression \
        '#last = :future AND #version BETWEEN :seeded AND :expected' \
      --expression-attribute-names "$names" \
      --expression-attribute-values "$values" >/dev/null || return 1
    ddb_absent "$DEV_RATE_TABLE" "$GLOBAL_KEY" "$WORK/global.absent.json" || return 1
  fi
  GLOBAL_SEEDED=0
}

cleanup() {
  local cleanup_failed=0
  set +e
  if [[ "$IP_ROWS_OWNED" == "1" && -n "${DEV_RATE_TABLE:-}" ]]; then
    for key in "reg-ip:$IP_A" "reg-ip:$IP_B"; do
      key_hash="$(printf '%s' "$key" | sha256sum | cut -c1-8)"
      if ! ddb_get "$DEV_RATE_TABLE" "$key" "$WORK/ip-cleanup-$key_hash.json"; then
        cleanup_failed=1
        continue
      fi
      if [[ ! -s "$WORK/ip-cleanup-$key_hash.json" ]] ||
        jq -e 'has("Item") | not' "$WORK/ip-cleanup-$key_hash.json" >/dev/null; then
        continue
      fi
      if ! jq -e '.Item.version.N == "1"' "$WORK/ip-cleanup-$key_hash.json" >/dev/null; then
        cleanup_failed=1
        continue
      fi
      if ! aws dynamodb delete-item \
        --profile "$PROFILE" --region "$REGION" --table-name "$DEV_RATE_TABLE" \
        --key "$(jq -cn --arg key "$key" '{key:{S:$key}}')" \
        --condition-expression '#version = :expected' \
        --expression-attribute-names '{"#version":"version"}' \
        --expression-attribute-values '{":expected":{"N":"1"}}' >/dev/null; then
        cleanup_failed=1
        continue
      fi
      ddb_absent "$DEV_RATE_TABLE" "$key" "$WORK/ip-deleted-$key_hash.json" ||
        cleanup_failed=1
    done
  fi
  restore_global_bucket || cleanup_failed=1
  if [[ "$cleanup_failed" == "0" ]]; then
    CLEANED=1
  else
    rm -f "$EVIDENCE_FILE"
    printf 'cleanup did not restore the Dev rate-limit state; recovery files: %s\n' \
      "$WORK" >&2
  fi
  set -e
  [[ "$cleanup_failed" == "0" ]]
}

on_exit() {
  local status=$?
  if [[ "$CLEANED" != "1" ]]; then
    cleanup || status=1
  fi
  if [[ "$status" != "0" ]]; then
    rm -f "$EVIDENCE_FILE"
  fi
  if [[ "$status" == "0" ]]; then
    rm -rf "$WORK"
  fi
  exit "$status"
}
trap on_exit EXIT INT TERM

for stack in "$DEV_STACK" "$SAAS_STACK"; do
  label="$(tr '[:upper:]' '[:lower:]' <<<"$stack")"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$stack" \
    --output json >"$WORK/$label-stack.json"
  jq -e --arg commit "$EXPECTED_COMMIT" '
    .Stacks[0].StackStatus == "UPDATE_COMPLETE"
    and any(.Stacks[0].Outputs[];
      .OutputKey == "DeploymentCommit" and .OutputValue == $commit)
  ' "$WORK/$label-stack.json" >/dev/null ||
    fail "$stack is not UPDATE_COMPLETE at the exact commit"
done

validate_auth_artifact() {
  local stack_file="$1" label="$2"
  local function_name function_json zip_file unpacked code_sha
  function_name="$(stack_output "$stack_file" AuthFnName)"
  function_json="$WORK/$label-function.json"
  zip_file="$WORK/$label-function.zip"
  unpacked="$WORK/$label-unpacked"
  aws lambda get-function \
    --profile "$PROFILE" --region "$REGION" --function-name "$function_name" \
    --output json >"$function_json"
  jq -e --arg commit "$EXPECTED_COMMIT" '
    .Configuration.State == "Active"
    and .Configuration.LastUpdateStatus == "Successful"
    and .Configuration.Environment.Variables.AGENT_AUTH_DEPLOYMENT_COMMIT == $commit
  ' "$function_json" >/dev/null ||
    fail "$label Auth runtime identity is not the exact commit"
  curl -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
    "$(jq -er '.Code.Location' "$function_json")" -o "$zip_file"
  code_sha="$(openssl dgst -sha256 -binary "$zip_file" | base64 | tr -d '\n')"
  [[ "$code_sha" == "$(jq -er '.Configuration.CodeSha256' "$function_json")" ]] ||
    fail "$label downloaded package does not match AWS CodeSha256"
  mkdir "$unpacked"
  unzip -q "$zip_file" -d "$unpacked"
  cmp "$unpacked/bootstrap" "$LOCAL_BOOTSTRAP" ||
    fail "$label deployed bootstrap differs from the exact local artifact"
  jq -e --arg commit "$EXPECTED_COMMIT" --arg sha "$LOCAL_BOOTSTRAP_SHA" '
    .schema == "agent-auth-lambda-provenance-v1"
    and .commit == $commit
    and .bootstrap_sha256 == $sha
  ' "$unpacked/deployment-provenance.json" >/dev/null ||
    fail "$label deployed provenance does not bind the exact artifact"
}

DEV_FILE="$WORK/$(tr '[:upper:]' '[:lower:]' <<<"$DEV_STACK")-stack.json"
SAAS_FILE="$WORK/$(tr '[:upper:]' '[:lower:]' <<<"$SAAS_STACK")-stack.json"
validate_auth_artifact "$DEV_FILE" dev
validate_auth_artifact "$SAAS_FILE" saas

DEV_RATE_TABLE="$(stack_output "$DEV_FILE" RateLimitTableName)"
DEV_CLIENTS_TABLE="$(stack_output "$DEV_FILE" ClientsTableName)"
DEV_ADMIN_URL="$(stack_output "$DEV_FILE" AdminUrl)"
DEV_ORIGIN="${DEV_ADMIN_URL%/admin}"
SAAS_AUTH_FN="$(stack_output "$SAAS_FILE" AuthFnName)"
SAAS_WAF_ARN="$(stack_output "$SAAS_FILE" RegistrationWebAclArn)"
SAAS_WAF_LOG_GROUP="$(stack_output "$SAAS_FILE" RegistrationWafLogGroupName)"
SAAS_DISTRIBUTION_ID="$(stack_output "$SAAS_FILE" FrontendDistributionId)"

aws lambda get-function-configuration \
  --profile "$PROFILE" --region "$REGION" --function-name "$SAAS_AUTH_FN" \
  --output json >"$WORK/saas-auth.json"
SAAS_ZONE="$(jq -er '
  .Environment.Variables.AGENT_AUTH_FORM == "saas"
  and (.Environment.Variables.AGENT_AUTH_ZONE | type == "string" and length > 0)
  | if . then . else error("invalid SaaS runtime") end
' "$WORK/saas-auth.json" >/dev/null && jq -er '.Environment.Variables.AGENT_AUTH_ZONE' "$WORK/saas-auth.json")"
SAAS_ORIGIN="https://$TENANT.$SAAS_ZONE"

aws cloudfront get-distribution-config \
  --profile "$PROFILE" --id "$SAAS_DISTRIBUTION_ID" \
  --output json >"$WORK/distribution.json"
[[ "$(jq -er '.DistributionConfig.WebACLId' "$WORK/distribution.json")" == "$SAAS_WAF_ARN" ]] ||
  fail "SaaS CloudFront distribution is not associated with the expected WebACL"
WAF_NAME_AND_ID="${SAAS_WAF_ARN#*/webacl/}"
WAF_NAME="${WAF_NAME_AND_ID%%/*}"
WAF_ID="${WAF_NAME_AND_ID##*/}"
[[ -n "$WAF_NAME" && -n "$WAF_ID" && "$WAF_NAME" != "$WAF_ID" ]] ||
  fail "SaaS WebACL ARN is malformed"
aws wafv2 get-web-acl \
  --profile "$PROFILE" --region "$REGION" --scope CLOUDFRONT \
  --name "$WAF_NAME" --id "$WAF_ID" --output json >"$WORK/web-acl.json"
jq -e --arg probe "c10-8-$EXPECTED_COMMIT" '
  # CloudFormation accepts ByteMatch search strings as text, while
  # GetWebACL serializes the same blob as base64.
  def search_is($plain): . == $plain or . == ($plain | @base64);
  def has_register_scope:
    .ScopeDownStatement.AndStatement.Statements as $statements
    | any($statements[];
        (.ByteMatchStatement.SearchString | search_is("POST"))
        and (.ByteMatchStatement.FieldToMatch | has("Method")))
      and any($statements[];
        (.ByteMatchStatement.SearchString | search_is("/register"))
        and (.ByteMatchStatement.FieldToMatch | has("UriPath")));
  (.WebACL.Rules | length) == 4
  and all(.WebACL.Rules[]; .VisibilityConfig.SampledRequestsEnabled == false)
  and any(.WebACL.Rules[];
    .Name == "RegistrationProbe"
    and (.Action | has("Block"))
    and (
      .Statement.AndStatement.Statements[2].ByteMatchStatement.SearchString
      | search_is($probe)
    ))
  and any(.WebACL.Rules[];
    .Name == "RegistrationIpRateLimit"
    and (.Action | has("Block"))
    and .Statement.RateBasedStatement.AggregateKeyType == "IP"
    and .Statement.RateBasedStatement.Limit == 100
    and (.Statement.RateBasedStatement | has_register_scope))
  and any(.WebACL.Rules[];
    .Name == "RegistrationHostRateLimit"
    and (.Action | has("Block"))
    and .Statement.RateBasedStatement.AggregateKeyType == "CUSTOM_KEYS"
    and .Statement.RateBasedStatement.Limit == 300
    and .Statement.RateBasedStatement.CustomKeys[0].Header.Name == "host"
    and (.Statement.RateBasedStatement | has_register_scope))
  and any(.WebACL.Rules[];
    .Name == "RegistrationAsnRateLimit"
    and (.Action | has("Block"))
    and .Statement.RateBasedStatement.AggregateKeyType == "CUSTOM_KEYS"
    and .Statement.RateBasedStatement.Limit == 1000
    and (
      .Statement.RateBasedStatement.CustomKeys[0]
      | (has("Asn") or has("ASN"))
    )
    and (.Statement.RateBasedStatement | has_register_scope))
' "$WORK/web-acl.json" >/dev/null ||
  fail "deployed SaaS WebACL does not contain the reviewed POST /register rules"

ddb_get "$DEV_RATE_TABLE" "$GLOBAL_KEY" "$WORK/global.before.json"
if [[ -s "$WORK/global.before.json" ]] &&
  jq -e 'has("Item")' "$WORK/global.before.json" >/dev/null; then
  GLOBAL_EXISTED=1
  OLD_VERSION="$(jq -er '.Item.version.N | tonumber' "$WORK/global.before.json")"
  GLOBAL_SEEDED_VERSION=$((OLD_VERSION + 1))
  GLOBAL_EXPECTED_VERSION=$((GLOBAL_SEEDED_VERSION + 2))
  GLOBAL_SEEDED=1
  aws dynamodb update-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$DEV_RATE_TABLE" \
    --key "$(jq -cn --arg key "$GLOBAL_KEY" '{key:{S:$key}}')" \
    --update-expression \
      'SET tokens = :zero, last_refill = :future, version = :next, expires_at = :expires' \
    --condition-expression 'version = :old' \
    --expression-attribute-values "$(jq -cn \
      --arg zero "0" --arg future "$FUTURE_REFILL" \
      --arg next "$GLOBAL_SEEDED_VERSION" --arg old "$OLD_VERSION" \
      --arg expires "$((FUTURE_REFILL + 3600))" '{
        ":zero":{N:$zero},":future":{N:$future},":next":{N:$next},
        ":old":{N:$old},":expires":{N:$expires}
      }')" >/dev/null
else
  GLOBAL_SEEDED_VERSION=1
  GLOBAL_EXPECTED_VERSION=3
  GLOBAL_SEEDED=1
  aws dynamodb put-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$DEV_RATE_TABLE" \
    --item "$(jq -cn --arg key "$GLOBAL_KEY" --arg future "$FUTURE_REFILL" \
      --arg expires "$((FUTURE_REFILL + 3600))" '{
        key:{S:$key},tokens:{N:"0"},last_refill:{N:$future},
        version:{N:"1"},expires_at:{N:$expires}
      }')" \
    --condition-expression 'attribute_not_exists(#key)' \
    --expression-attribute-names '{"#key":"key"}' >/dev/null
fi

for key in "reg-ip:$IP_A" "reg-ip:$IP_B"; do
  ddb_absent "$DEV_RATE_TABLE" "$key" \
    "$WORK/ip-before-$(printf '%s' "$key" | sha256sum | cut -c1-8).json" ||
    fail "temporary per-IP rate key already exists"
done
IP_ROWS_OWNED=1

register_request() {
  local label="$1" ip="$2" redirect="$3"
  local status
  status="$(curl -sS --proto '=https' --connect-timeout 10 --max-time 30 \
    -D "$WORK/$label.headers" -o "$WORK/$label.body" -w '%{http_code}' \
    -X POST -H 'content-type: application/json' -H "x-forwarded-for: $ip" \
    --data-binary "$(jq -cn --arg redirect "$redirect" \
      '{redirect_uris:[$redirect],token_endpoint_auth_method:"none"}')" \
    "$DEV_ORIGIN/register")"
  [[ "$status" == "429" ]] || fail "$label returned HTTP $status instead of 429"
  grep -Eiq '^retry-after: [1-9][0-9]*' "$WORK/$label.headers" ||
    fail "$label has no positive Retry-After"
  jq -e '
    .error == "temporarily_unavailable"
    and (.error_description | contains("全局配额"))
  ' "$WORK/$label.body" >/dev/null ||
    fail "$label is not the tenant-global anonymous quota response"
}

register_request dev-a "$IP_A" "$REDIRECT_A"
register_request dev-b "$IP_B" "$REDIRECT_B"
for key in "reg-ip:$IP_A" "reg-ip:$IP_B"; do
  key_hash="$(printf '%s' "$key" | sha256sum | cut -c1-8)"
  ddb_get "$DEV_RATE_TABLE" "$key" "$WORK/ip-after-$key_hash.json"
  jq -e '.Item.version.N == "1"' "$WORK/ip-after-$key_hash.json" >/dev/null ||
    fail "Dev request did not use the expected distinct per-IP bucket"
done
ddb_get "$DEV_RATE_TABLE" "$GLOBAL_KEY" "$WORK/global.after.json"
jq -e --arg version "$GLOBAL_EXPECTED_VERSION" --arg future "$FUTURE_REFILL" '
  .Item.version.N == $version
  and .Item.tokens.N == "0"
  and .Item.last_refill.N == $future
' "$WORK/global.after.json" >/dev/null ||
  fail "Dev global bucket did not record both distinct-IP rejections"

for redirect in "$REDIRECT_A" "$REDIRECT_B"; do
  count="$(aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$DEV_CLIENTS_TABLE" \
    --consistent-read --select COUNT \
    --filter-expression 'contains(redirect_uris, :redirect)' \
    --expression-attribute-values "$(jq -cn --arg redirect "$redirect" \
      '{":redirect":{S:$redirect}}')" --query Count --output text)"
  [[ "$count" == "0" ]] || fail "globally rejected registration created a client"
done

PROBE="c10-8-$EXPECTED_COMMIT"
PROBE_STARTED_MS="$(( $(date +%s) * 1000 ))"
WAF_STATUS="$(curl -sS --proto '=https' --connect-timeout 10 --max-time 30 \
  -o "$WORK/waf.body" -D "$WORK/waf.headers" -w '%{http_code}' \
  -X POST -H 'content-type: application/json' \
  -H "x-agent-auth-waf-probe: $PROBE" \
  --data-binary '{"redirect_uris":["https://waf-probe.invalid/callback"]}' \
  "$SAAS_ORIGIN/register")"
[[ "$WAF_STATUS" == "403" ]] ||
  fail "SaaS registration WAF probe returned HTTP $WAF_STATUS instead of 403"

WAF_LOGGED=0
for _ in $(seq 1 30); do
  if ! aws logs filter-log-events \
    --profile "$PROFILE" --region "$REGION" \
    --log-group-name "$SAAS_WAF_LOG_GROUP" \
    --start-time "$PROBE_STARTED_MS" --output json >"$WORK/waf-logs.json"; then
    sleep 2
    continue
  fi
  if jq -e --arg probe "$PROBE" '
    any(.events[].message | fromjson?;
      .terminatingRuleId == "RegistrationProbe"
      and any(.httpRequest.headers[]?;
        (.name | ascii_downcase) == "x-agent-auth-waf-probe"
        and .value == $probe))
  ' "$WORK/waf-logs.json" >/dev/null; then
    WAF_LOGGED=1
    break
  fi
  sleep 2
done
[[ "$WAF_LOGGED" == "1" ]] ||
  fail "SaaS WAF block was not observed in the redacted block-only log"

cleanup || fail "temporary Dev rate-limit state did not cleanly restore"
for key in "reg-ip:$IP_A" "reg-ip:$IP_B"; do
  ddb_absent "$DEV_RATE_TABLE" "$key" "$WORK/ip-absent-$(sha256sum <<<"$key" | cut -c1-8).json" ||
    fail "temporary per-IP rate row remains"
done

jq -n \
  --arg tested_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg commit "$EXPECTED_COMMIT" \
  --arg bootstrap_sha256 "$LOCAL_BOOTSTRAP_SHA" \
  --arg web_acl_arn_sha256 "$(printf '%s' "$SAAS_WAF_ARN" | sha256sum | cut -d' ' -f1)" \
  '{
    schema:"agent-auth-c10-8-evidence-v1",
    result:"pass",
    tested_at:$tested_at,
    deployment_commit:$commit,
    deployed_auth_bootstrap_sha256:$bootstrap_sha256,
    dev_global_quota:{
      distinct_source_ips:2,
      responses_429:2,
      retry_after:true,
      clients_created:0,
      rate_state_restored:true
    },
    saas_waf:{
      cloudfront_associated:true,
      ip_rate_rule_verified:true,
      host_rate_rule_verified:true,
      asn_rate_rule_verified:true,
      exact_commit_probe_403:true,
      terminating_rule:"RegistrationProbe",
      block_log_observed:true,
      web_acl_arn_sha256:$web_acl_arn_sha256
    },
    cleanup:{
      global_bucket_restored:true,
      temporary_ip_rows_absent:true,
      local_credentials_created:false
    }
  }' >"$EVIDENCE_FILE"
CLEANED=1
printf 'PASS: C10.8 evidence %s\n' "$EVIDENCE_FILE"
sha256sum "$EVIDENCE_FILE"

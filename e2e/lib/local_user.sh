#!/usr/bin/env bash

# Shared local-user provisioning for deployed e2e scripts. The public login
# surface never creates users; Admin creates a temporary credential and the
# first password change activates it.

agent_auth_admin_token() {
  if [ -n "${ADMIN_TOKEN:-}" ]; then
    return
  fi
  local lib_dir
  lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  ADMIN_TOKEN=$(STACK="${STACK:-AgentAuthDev}" \
    REGION="${REGION:-us-east-1}" \
    PROFILE="${PROFILE:-${AWS_PROFILE:-default}}" \
    "$lib_dir/../get-admin-token.sh")
}

agent_auth_provision_local_user() {
  local base_url="${1:?base URL required}"
  local email="${2:?email required}"
  local cookie_jar="${3:-}"
  local initial="${AGENT_AUTH_E2E_INITIAL_PASSWORD:-}"
  local permanent="${AGENT_AUTH_E2E_PASSWORD:-}"
  local create_body change_body status

  if [ -z "$initial" ]; then
    initial=$(python3 -c 'import secrets; print("Init-" + secrets.token_urlsafe(24))')
  fi
  if [ -z "$permanent" ]; then
    permanent=$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')
  fi

  agent_auth_admin_token
  create_body=$(EMAIL="$email" PASSWORD="$initial" python3 -c \
    'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"initial_password":os.environ["PASSWORD"]}))')
  status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$base_url/admin/users" \
    -H "authorization: Bearer $ADMIN_TOKEN" \
    -H "content-type: application/json" \
    -d "$create_body")
  [ "$status" = "201" ] || {
    echo "❌ Admin 创建 e2e 用户失败(email=$email,status=$status)" >&2
    return 1
  }

  change_body=$(EMAIL="$email" CURRENT="$initial" NEW="$permanent" python3 -c \
    'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"current_password":os.environ["CURRENT"],"new_password":os.environ["NEW"]}))')
  local curl_args=(-s -o /dev/null -w '%{http_code}' -X POST "$base_url/login/password/change"
    -H "content-type: application/json" -d "$change_body")
  if [ -n "$cookie_jar" ]; then
    curl_args+=(-c "$cookie_jar")
  fi
  status=$(curl "${curl_args[@]}")
  [ "$status" = "200" ] || {
    echo "❌ e2e 用户首次改密失败(email=$email,status=$status)" >&2
    return 1
  }
}

#!/usr/bin/env bash
# P1a 真机 e2e:RP-logout(C9.6)+ prompt/max_age(C9.5a)。
#
# 验证:magic-link 登录建会话 → /end-session 清会话(cookie 失效 + 再 authorize 需重登)→
# 未注册 post_logout_redirect_uri 拒 / 已注册回跳 → prompt=none 无会话 login_required /
# 有会话续流 → prompt=login 强制重认证 → max_age=0 强制重认证。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default ./e2e/logout_prompt.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-logout-client"
REDIRECT="http://127.0.0.1/cb"
PLR="http://127.0.0.1/after-logout"
V="0123456789012345678901234567890123456789abc"
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$V'.encode()).digest()).rstrip(b'=').decode())")
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT

echo "== 0. seed client(带 post_logout_redirect_uris)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"post_logout_redirect_uris\":{\"L\":[{\"S\":\"$PLR\"}]}}" >/dev/null

login() {
  local email="lo-$(python3 -c 'import random;print(random.randint(1,999999))')@example.com"
  local resp link pq
  agent_auth_provision_local_user "$API_URL" "$email"
  resp=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" -d "{\"email\":\"$email\",\"authorize_query\":\"\"}")
  link=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin)['dev_link'])")
  pq=$(echo "$link" | sed 's|.*/login/callback|/login/callback|')
  curl -s -b "$JAR" -c "$JAR" -o /dev/null "$API_URL$pq"
}

echo "== 1. 登录建会话 =="
login
PROBE=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$API_URL/consent/context?client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid")
[ "$PROBE" = "200" ] || { echo "❌ 登录后会话应有效(got $PROBE)"; exit 1; }
echo "  ✅ 会话有效"

echo "== 2. /end-session 清会话 → 再探针 401 =="
curl -s -b "$JAR" -c "$JAR" -o /dev/null "$API_URL/end-session"
PROBE=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$API_URL/consent/context?client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid")
[ "$PROBE" = "401" ] || { echo "❌ 登出后会话应失效(got $PROBE)"; exit 1; }
echo "  ✅ 登出后会话失效"

echo "== 3. 未注册 post_logout_redirect_uri → 400;已注册 → 303 回跳 =="
login
BAD=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$API_URL/end-session?client_id=$CLIENT&post_logout_redirect_uri=http://evil.example.com/x")
[ "$BAD" = "400" ] || { echo "❌ 未注册 post_logout 应 400(got $BAD)"; exit 1; }
login
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' "$API_URL/end-session?client_id=$CLIENT&post_logout_redirect_uri=$PLR&state=xyz")
echo "$LOC" | grep -q "state=xyz" || { echo "❌ 回跳未 echo state: $LOC"; exit 1; }
echo "$LOC" | grep -q "^$PLR" || { echo "❌ 回跳非注册值: $LOC"; exit 1; }
echo "  ✅ 未注册拒 / 已注册回跳 echo state"

echo "== 4. prompt=none 无会话 → error=login_required(不去 /login)=="
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s&prompt=none")
echo "$LOC" | grep -q "error=login_required" || { echo "❌ prompt=none 无会话应 login_required: $LOC"; exit 1; }
echo "$LOC" | grep -q "^$REDIRECT" || { echo "❌ 应回跳 client redirect: $LOC"; exit 1; }
echo "  ✅ prompt=none 无会话 → login_required"

echo "== 5. prompt=none 有会话 → 续流去 consent(不误拒)=="
login
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s&prompt=none")
echo "$LOC" | grep -q "/consent?" || { echo "❌ 有会话 prompt=none 应去 consent: $LOC"; exit 1; }
echo "  ✅ prompt=none 有会话 → 续流"

echo "== 6. prompt=login 强制重认证(去 /login)=="
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s&prompt=login")
echo "$LOC" | grep -q "/login?" || { echo "❌ prompt=login 应去 /login: $LOC"; exit 1; }
echo "  ✅ prompt=login 强制重认证"

echo "== 7. max_age=0 强制重认证 =="
LOC=$(curl -s -b "$JAR" -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s&max_age=0")
echo "$LOC" | grep -q "/login?" || { echo "❌ max_age=0 应去 /login: $LOC"; exit 1; }
echo "  ✅ max_age=0 强制重认证"

echo "✅ P1a RP-logout + prompt/max_age 真机 e2e 全绿"

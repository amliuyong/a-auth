#!/usr/bin/env bash
# P0.5 真机 e2e:magic-link 登录 → consent → 签发 code → 换 token(假用户,Notifier dev 回显链接)。
#
# 验证 P0.5 登录/consent 后端在真机(API Gateway→Lambda→DynamoDB)端到端成立:
# 请求 magic-link(C9.1 冷却/短命)→ callback(C9.2 login-CSRF nonce 绑定)建会话 →
# consent/context(C10.9 anti-CSRF)→ approve 签发 code(iss C1.4 + state)→ /token 换 access+refresh。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表> AWS_PROFILE=default ./e2e/login_consent.sh
#
# 依赖:curl、python3。dev 栈须开 AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER(magic-link dev 回显链接)。
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-login-client"
REDIRECT="http://127.0.0.1/cb"
EMAIL="e2e-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
VERIFIER="0123456789012345678901234567890123456789abc"
JAR="$(mktemp)"

echo "== 0. seed client =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"
agent_auth_provision_local_user "$API_URL" "$EMAIL"

CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
AQ="client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid&state=st9&code_challenge=$CHALLENGE&code_challenge_method=S256"

echo "== 1. POST /login/magic-link(存 nonce cookie)=="
RESP=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"$AQ\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || { echo "❌ 无 dev_link(dev 占位未开?)"; exit 1; }
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')

echo "== 2. GET callback(带 nonce cookie → 建会话,login-CSRF C9.2)=="
CODE_HTTP=$(curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' "$API_URL$PQ")
[ "$CODE_HTTP" = "303" ] || { echo "❌ callback 未 303(got $CODE_HTTP)"; exit 1; }

echo "== 3. 冷却:同 email 立即再请求 → 429(C9.1)=="
COOL=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"$AQ\"}")
[ "$COOL" = "429" ] || { echo "❌ 冷却未生效(got $COOL)"; exit 1; }

echo "== 4. GET /consent/context(带 session cookie → anti-CSRF token,C10.9)=="
CSRF=$(curl -s -b "$JAR" "$API_URL/consent/context?$AQ" | python3 -c "import sys,json;print(json.load(sys.stdin).get('csrf_token',''))")
[ -n "$CSRF" ] || { echo "❌ 无 csrf_token"; exit 1; }

echo "== 5. 错误 anti-CSRF → 403(C10.9)=="
BAD=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$API_URL/consent/decision" -H "content-type: application/json" \
  -d "{\"decision\":\"approve\",\"csrf\":\"WRONG\",\"authorize_query\":\"$AQ\"}")
[ "$BAD" = "403" ] || { echo "❌ 错误 anti-CSRF 未拒(got $BAD)"; exit 1; }

echo "== 6. POST /consent/decision approve → 回跳 code+iss+state =="
REDIR=$(curl -s -b "$JAR" -X POST "$API_URL/consent/decision" -H "content-type: application/json" \
  -d "{\"decision\":\"approve\",\"csrf\":\"$CSRF\",\"authorize_query\":\"$AQ\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('redirect',''))")
echo "$REDIR" | grep -q "code=" || { echo "❌ 回跳无 code"; exit 1; }
echo "$REDIR" | grep -q "iss=" || { echo "❌ 回跳无 iss(C1.4)"; exit 1; }
echo "$REDIR" | grep -q "state=st9" || { echo "❌ state 未 echo"; exit 1; }
CODE=$(echo "$REDIR" | sed 's/.*code=\([^&]*\).*/\1/')

echo "== 7. consent 签发的 code 换 token(完整闭环)=="
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
echo "$TOK" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d.get('access_token'), 'no access_token'
assert d.get('refresh_token'), 'no refresh_token'
print('  ✅ 换出 access + refresh;登录 sub 进 token')
"
rm -f "$JAR"
echo "✅ P0.5 magic-link 登录 + consent 真机 e2e 全绿"

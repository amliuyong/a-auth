#!/usr/bin/env bash
# spec 006 §3.3 真机 e2e:refresh scope 下采样(RFC 6749 §6 / DESIGN §1:156)。
#   magic-link 登录 → consent(scope=openid profile)→ code 换 access+refresh →
#   ①refresh 下采样 scope=openid → 签出 token scope claim 收窄为 openid;
#   ②refresh 请求超集 scope=openid admin(admin 未授权)→ invalid_scope(不改状态);
#   ③超集拒后原 refresh 仍可用(read-gate 置 consume 前的证明)→ 不带 scope refresh → 仍返回全集(C3.6)。
#
# 用法(走 CloudFront 统一入口域):
#   API_URL=https://<cf-host> CLIENTS_TABLE=<ClientsTableName> AWS_PROFILE=default ./e2e/refresh_downscope.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-downscope-client"
REDIRECT="http://127.0.0.1/cb"
EMAIL="ds-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
VERIFIER="0123456789012345678901234567890123456789abc"
JAR="$(mktemp)"

scope_of() { python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')
c=json.loads(base64.urlsafe_b64decode(p[1]+'='*(-len(p[1])%4)))
print(c.get('scope',''))
"; }

echo "== 0. seed client =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"

CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
# 授权 scope = openid profile(下采样源)。
AQ="client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid%20profile&state=st&code_challenge=$CHALLENGE&code_challenge_method=S256"

agent_auth_provision_local_user "$API_URL" "$EMAIL"
echo "== 1. 已置备用户 magic-link 登录 =="
RESP=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"$AQ\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || { echo "❌ 无 dev_link: $RESP"; exit 1; }
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')
curl -s -b "$JAR" -c "$JAR" -o /dev/null "$API_URL$PQ"

echo "== 2. consent approve → code → 换 access+refresh(scope=openid profile)=="
CSRF=$(curl -s -b "$JAR" "$API_URL/consent/context?$AQ" | python3 -c "import sys,json;print(json.load(sys.stdin).get('csrf_token',''))")
REDIR=$(curl -s -b "$JAR" -X POST "$API_URL/consent/decision" -H "content-type: application/json" \
  -d "{\"decision\":\"approve\",\"csrf\":\"$CSRF\",\"authorize_query\":\"$AQ\"}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('redirect',''))")
CODE=$(echo "$REDIR" | sed 's/.*code=\([^&]*\).*/\1/')
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
REFRESH=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
[ -n "$REFRESH" ] || { echo "❌ 无 refresh_token: $TOK"; exit 1; }
echo "  换出 refresh ✅"

echo "== 3. refresh 下采样 scope=openid → 签出 scope claim 收窄为 openid =="
R1=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT&scope=openid")
AT1=$(echo "$R1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$AT1" ] || { echo "❌ 下采样 refresh 未签出 token: $R1"; exit 1; }
SC1=$(echo "$AT1" | scope_of)
[ "$SC1" = "openid" ] || { echo "❌ 签发 scope 应收窄为 openid,得 '$SC1'"; exit 1; }
echo "  scope claim=openid(已收窄)✅"
REFRESH2=$(echo "$R1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")

echo "== 4. 超集 scope=openid admin(admin 未授权)→ invalid_scope(不改状态)=="
R2=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH2&client_id=$CLIENT&scope=openid%20admin")
ERR=$(echo "$R2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$ERR" = "invalid_scope" ] || { echo "❌ 超集应 invalid_scope,得 '$ERR': $R2"; exit 1; }
echo "  超集拒 invalid_scope ✅"

echo "== 5. C3.6 + read-gate:超集拒后 refresh2 仍可用,不带 scope → 仍返回全集 =="
R3=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH2&client_id=$CLIENT")
AT3=$(echo "$R3" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$AT3" ] || { echo "❌ 超集拒后 refresh2 应仍可用(read-gate 未消费版本): $R3"; exit 1; }
SC3=$(echo "$AT3" | scope_of | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
[ "$SC3" = "openid profile" ] || { echo "❌ 不带 scope 应返回全集 'openid profile',得 '$SC3'"; exit 1; }
echo "  超集拒未消费版本 + 不带 scope 返回全集(C3.6)✅"

rm -f "$JAR"
echo "✅ spec 006 §3.3 refresh scope 下采样真机 e2e 全绿(交集签发 + 超集拒 + read-gate + C3.6 保全集)"

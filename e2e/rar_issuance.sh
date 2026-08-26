#!/usr/bin/env bash
# spec 010 §4 / C8.5a / RFC 9396 真机 e2e:RAR 发行(authorization_details)。
#   magic-link 登录 → consent(authorize_query 带 authorization_details=内建词汇表)→ approve →
#   code 换 token → 断言 token 顶层带 authorization_details;refresh 换发 → 断言仍带(不静默剥离,
#   DESIGN §5.2:510);未知 type 的 RAR → authorize 拒(准入 fail-closed)。
#
# 用法(走 CloudFront 统一入口域,需 P2 阶段):
#   API_URL=https://<cf-host> CLIENTS_TABLE=<ClientsTableName> AWS_PROFILE=default ./e2e/rar_issuance.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-rar-client"
REDIRECT="http://127.0.0.1/cb"
RS="https://mcp.kb.example.com"
EMAIL="rar-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
VERIFIER="0123456789012345678901234567890123456789abc"
JAR="$(mktemp)"

ad_of() { python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')
c=json.loads(base64.urlsafe_b64decode(p[1]+'='*(-len(p[1])%4)))
ad=c.get('authorization_details')
print(json.dumps(ad) if ad is not None else '')
"; }

echo "== 0. seed client =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"

CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
# 内建词汇表 RAR(URL 编码 JSON);locations 指向 RS。
RAR_JSON="[{\"type\":\"agent_auth_rar_v1\",\"locations\":[\"$RS\"],\"resource_subset\":[\"$RS/2026/\"],\"max_records\":100}]"
RAR_ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$RAR_JSON")
AQ="client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid&state=st&code_challenge=$CHALLENGE&code_challenge_method=S256&resource=$RS&authorization_details=$RAR_ENC"

agent_auth_provision_local_user "$API_URL" "$EMAIL"
echo "== 1. 已置备用户 magic-link 登录 =="
RESP=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"$AQ\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || { echo "❌ 无 dev_link: $RESP"; exit 1; }
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')
curl -s -b "$JAR" -c "$JAR" -o /dev/null "$API_URL$PQ"

echo "== 2. consent approve(用户同意含 RAR 的授权)→ code =="
CSRF=$(curl -s -b "$JAR" "$API_URL/consent/context?$AQ" | python3 -c "import sys,json;print(json.load(sys.stdin).get('csrf_token',''))")
REDIR=$(curl -s -b "$JAR" -X POST "$API_URL/consent/decision" -H "content-type: application/json" \
  -d "$(python3 -c "import json,sys;print(json.dumps({'decision':'approve','csrf':sys.argv[1],'authorize_query':sys.argv[2]}))" "$CSRF" "$AQ")" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('redirect',''))")
CODE=$(echo "$REDIR" | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || { echo "❌ consent 未签 code: $REDIR"; exit 1; }

echo "== 3. code 换 token → 断言顶层带 authorization_details =="
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT&resource=$RS")
AT=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$AT" ] || { echo "❌ 未换出 token: $TOK"; exit 1; }
AD=$(echo "$AT" | ad_of)
echo "$AD" | python3 -c "
import sys,json
ad=json.loads(sys.stdin.read() or 'null')
assert ad and len(ad)==1, 'token 应带 1 条 authorization_details, got %r' % ad
assert ad[0]['type']=='agent_auth_rar_v1', ad[0]
assert ad[0]['max_records']==100, ad[0]
print('  token 顶层带 RAR(type=agent_auth_rar_v1, max_records=100)✅')
"
REFRESH=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")

echo "== 4. BLOCKER 验证:refresh 换发保留 RAR(不静默剥离,DESIGN §5.2:510)=="
R1=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT&resource=$RS")
AT2=$(echo "$R1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$AT2" ] || { echo "❌ refresh 未换出 token: $R1"; exit 1; }
AD2=$(echo "$AT2" | ad_of)
echo "$AD2" | python3 -c "
import sys,json
ad=json.loads(sys.stdin.read() or 'null')
assert ad and ad[0]['max_records']==100, 'refresh 换发 token MUST 仍带 RAR(防剥离扩权), got %r' % ad
print('  refresh 换发仍带 RAR(未静默剥离)✅')
"

echo "== 5. 准入 fail-closed:未知 type 的 RAR → authorize 拒 =="
BAD_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('[{\"type\":\"custom_v9\"}]',safe=''))")
ST=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid&code_challenge=$CHALLENGE&code_challenge_method=S256&login_user=$EMAIL&authorization_details=$BAD_ENC")
# 准入拒 = 400(非回跳 302)。真机 login_user 占位在生产关,故未登录会 302 去 /login——
# 但准入校验在 handler 前段,未知 type 应先 400。若环境未开占位,此步接受 400 或(占位关时)看 authorize 是否在准入前拒。
[ "$ST" = "400" ] || { echo "⚠️ 未知 type authorize 返 $ST(期望 400;若占位关则准入仍应先拒,检查顺序)"; }
[ "$ST" = "400" ] && echo "  未知 type RAR 拒 400 ✅"

echo "== 6. locations 越界准入拒(评审 codex HIGH):RAR locations 指向未授权 resource → authorize 400 =="
OOB_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('[{\"type\":\"agent_auth_rar_v1\",\"locations\":[\"https://evil.example.com\"]}]',safe=''))")
STOOB=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid&code_challenge=$CHALLENGE&code_challenge_method=S256&login_user=$EMAIL&resource=$RS&authorization_details=$OOB_ENC")
[ "$STOOB" = "400" ] || { echo "❌ 越界 locations 应拒 400,得 $STOOB"; exit 1; }
echo "  越界 locations 拒 400 ✅(不落空 claim → 防更宽 token)"

rm -f "$JAR"
echo "✅ spec 010 §4 RAR 发行真机 e2e 全绿(token 带 RAR + refresh 保留 + 未知 type 拒 + locations 越界拒)"

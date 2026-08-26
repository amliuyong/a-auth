#!/usr/bin/env bash
# P1 真机 e2e:授权会话状态机(spec 004,C6)—— code flow 建会话→code_issued→complete +
# confidential 发现/查询 + 只凭 id 裸查拒 + exchange_failed 态。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default ./e2e/session_state.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-sess-client"
SECRET="e2e-sess-secret"
REDIRECT="http://127.0.0.1/cb"
V="0123456789012345678901234567890123456789abc"
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
BASIC=$(printf '%s:%s' "$CLIENT" "$SECRET" | base64)

echo "== 0. seed confidential client(client_secret_basic)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"client_secret_basic\"},\"client_secret\":{\"S\":\"$SECRET\"}}" >/dev/null

echo "== 1. authorize(占位)→ code(建授权会话,推进 code_issued)=="
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$V'.encode()).digest()).rstrip(b'=').decode())")
# GSI 无序:记 authorize 前的会话集,取新出现的那个(不靠 [-1] 顺序)。
BEFORE1=$(curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions?client_id=me" | python3 -c "import sys,json;print(' '.join(json.load(sys.stdin).get('sessions',[])))")
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s&login_user=alice")
CODE=$(echo "$LOC" | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || { echo "❌ 无 code"; exit 1; }

echo "== 2. confidential 发现自己名下会话(GET /sessions?client_id=me;取新增)=="
# GSI 最终一致(Kiro L2):authorize 后 GSI 传播有延迟,轮询几次直到看到新会话。
SID=""
for i in 1 2 3 4 5; do
  SID=$(curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions?client_id=me" \
    | BEFORE="$BEFORE1" python3 -c "import sys,json,os;before=set(os.environ['BEFORE'].split());new=[s for s in json.load(sys.stdin)['sessions'] if s not in before];print(new[0] if new else '')")
  [ -n "$SID" ] && break
  sleep 1
done
[ -n "$SID" ] || { echo "❌ 未发现新会话(GSI 传播超时)"; exit 1; }
echo "  session_id=$SID"

echo "== 3. 按 id 查(confidential owner)→ code_issued_awaiting_exchange =="
ST=$(curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions/$SID" | python3 -c "import sys,json;print(json.load(sys.stdin)['state'])")
[ "$ST" = "code_issued_awaiting_exchange" ] || { echo "❌ 期望 code_issued,得 $ST"; exit 1; }
echo "  ✅ $ST"

echo "== 4. 只凭 id 裸查(无鉴权)→ 404(C6.1)=="
HTTP=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/sessions/$SID")
[ "$HTTP" = "404" ] || { echo "❌ 裸查应 404,得 $HTTP"; exit 1; }
echo "  ✅ 裸查 → 404"

echo "== 5. 兑换 code → complete =="
curl -s -X POST "$API_URL/token" -H "authorization: Basic $BASIC" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$V&redirect_uri=$REDIRECT&client_id=$CLIENT&client_secret=$SECRET" \
  | python3 -c "import sys,json;assert json.load(sys.stdin).get('access_token'),'no token'"
ST=$(curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions/$SID" | python3 -c "import sys,json;print(json.load(sys.stdin)['state'])")
[ "$ST" = "complete" ] || { echo "❌ 兑换后应 complete,得 $ST"; exit 1; }
echo "  ✅ 兑换成功 → complete"

echo "== 6. exchange_failed:新 code 用错 redirect_uri 兑换 → 会话 exchange_failed + last_error =="
# GSI 无序:记 authorize 前的会话集,取新出现的那个(不靠 [-1] 顺序)。
BEFORE=$(curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions?client_id=me" | python3 -c "import sys,json;print(' '.join(json.load(sys.stdin).get('sessions',[])))")
LOC2=$(curl -s -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s2&login_user=alice")
CODE2=$(echo "$LOC2" | sed 's/.*code=\([^&]*\).*/\1/')
SID2=""
for i in 1 2 3 4 5; do
  SID2=$(curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions?client_id=me" \
    | BEFORE="$BEFORE" python3 -c "import sys,json,os;before=set(os.environ['BEFORE'].split());new=[s for s in json.load(sys.stdin)['sessions'] if s not in before];print(new[0] if new else '')")
  [ -n "$SID2" ] && break
  sleep 1
done
[ -n "$SID2" ] || { echo "❌ 未定位到新会话(GSI 传播超时)"; exit 1; }
FAIL_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/token" -H "authorization: Basic $BASIC" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE2&code_verifier=$V&redirect_uri=https://evil.example.com/cb&client_id=$CLIENT&client_secret=$SECRET")
[ "$FAIL_HTTP" = "400" ] || { echo "❌ 错 redirect 应 400,得 $FAIL_HTTP"; exit 1; }
curl -s -H "authorization: Basic $BASIC" "$API_URL/sessions/$SID2" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['state']=='exchange_failed', d
assert d['last_error']['at']=='token_endpoint', d
print('  ✅ exchange_failed + last_error.at=token_endpoint')
"
echo "== 7. C6.3a:同 code 重放 → 拒(code 已消费)=="
REPLAY=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/token" -H "authorization: Basic $BASIC" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE2&code_verifier=$V&redirect_uri=$REDIRECT&client_id=$CLIENT&client_secret=$SECRET")
[ "$REPLAY" = "400" ] || { echo "❌ 重放同 code 应拒,得 $REPLAY"; exit 1; }
echo "  ✅ 同 code 重放 → 拒"

echo "✅ P1 授权会话状态机(spec 004)真机 e2e 全绿"

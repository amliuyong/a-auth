#!/usr/bin/env bash
# P2 用户自助 Grant 管理真机 e2e(spec 011 §5.1 / C7.6b):
#   magic-link 登录建会话 → seed 一个该 user 的 Grant(直写 GrantsTable)→ GET /grants(见)→
#   GET /grants/{id} → DELETE(吊销)→ GET(status=revoked)。IDOR/CSRF/级联吊销由进程内 e2e 覆盖。
#
# 用法:
#   API_URL=https://<host> GRANTS_TABLE=<cdk 输出> AWS_PROFILE=default ./e2e/grants_api.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
GRANTS_TABLE="${GRANTS_TABLE:?需 GRANTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
EMAIL="grants-e2e-$RANDOM-$RANDOM@example.com"
USER_ID="user:$EMAIL"
GID="e2e-grant-$RANDOM"
CJAR=$(mktemp)
trap 'rm -f "$CJAR"' EXIT

agent_auth_provision_local_user "$API_URL" "$EMAIL"
echo "== 1. 已置备用户 magic-link 登录 → 会话 cookie(dev_link 从响应取,不真发邮件)=="
RESP=$(curl -s -c "$CJAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"\"}")
DEV_LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$DEV_LINK" ] || { echo "❌ 无 dev_link: $RESP"; exit 1; }
# 打开 callback(带 nonce cookie)→ 建会话 cookie(存进 cookie jar)。
PQ=$(echo "$DEV_LINK" | sed 's#.*/login/callback##')
curl -s -b "$CJAR" -c "$CJAR" -o /dev/null "$API_URL/login/callback$PQ"
grep -q "agent_auth_session" "$CJAR" || { echo "❌ 未建会话 cookie"; exit 1; }
echo "  登录成功,会话 cookie 已建 ✅"

echo "== 2. seed 一个该 user 的 Grant(直写 GrantsTable;真机由 code flow 建,此处 e2e 便利)=="
GRANT_JSON=$(GID="$GID" USER_ID="$USER_ID" python3 -c "
import os,json
print(json.dumps({
  'grant_id':os.environ['GID'],'user_id':os.environ['USER_ID'],'client_id':'app-3lo',
  'per_resource':[{'resource':'https://mcp.kb.example.com','scopes':['kb:read'],'authorization_details':[]}],
  'constraints':{'max_act_chain':1,'actor_allowlist':[],'expires_at':4000000000},
  'status':'active'}))")
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
  --item "{\"grant_id\":{\"S\":\"$GID\"},\"user_id\":{\"S\":\"$USER_ID\"},\"grant_json\":{\"S\":$(python3 -c "import json,sys;print(json.dumps(sys.stdin.read()))" <<<"$GRANT_JSON")}}" >/dev/null
echo "  Grant $GID 写入 ✅"

echo "== 3. GET /grants(会话鉴权,应见该 Grant)=="
LIST=$(curl -s -b "$CJAR" "$API_URL/grants")
echo "$LIST" | python3 -c "
import sys,json
gs=json.load(sys.stdin)
assert any(g['grant_id']=='$GID' for g in gs), gs
g=[g for g in gs if g['grant_id']=='$GID'][0]
assert g['status']=='active' and g['resources'][0]['resource']=='https://mcp.kb.example.com', g
print('  列表含该 Grant(status=active)✅')
"

echo "== 4. 未登录 GET /grants → 401 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/grants")
[ "$ST" = "401" ] || { echo "❌ 未登录应 401(got $ST)"; exit 1; }
echo "  401 ✅"

echo "== 5. DELETE /grants/{id}(吊销)→ 204 =="
ST=$(curl -s -b "$CJAR" -o /dev/null -w '%{http_code}' -X DELETE "$API_URL/grants/$GID")
[ "$ST" = "204" ] || { echo "❌ DELETE 应 204(got $ST)"; exit 1; }
echo "  204 ✅"

echo "== 6. GET /grants/{id} → status=revoked(吊销不删记录)=="
G=$(curl -s -b "$CJAR" "$API_URL/grants/$GID")
echo "$G" | python3 -c "import sys,json;g=json.load(sys.stdin);assert g['status']=='revoked',g;print('  status=revoked ✅')"

echo "== 清理 =="
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" --key "{\"grant_id\":{\"S\":\"$GID\"}}" >/dev/null && echo "  grant 删"

echo "✅ P2 /grants 用户自助管理真机 e2e 全绿"

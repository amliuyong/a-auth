#!/usr/bin/env bash
# device 批准**页链路**真机 e2e(spec 013 §2b + 评审 codex/Kiro HIGH:批准 body 须 form-urlencoded)。
#
# 复刻前端 /approve 页(DeviceApprove)的真实请求:magic-link 登录建会话 → device_authorization 铸码 →
# **POST /device(form-urlencoded,会话 cookie 鉴权)批准** → 轮询 /token 签出 3LO token。
# 与 device_flow.sh 的区别:那个直写 DeviceTable 模拟批准(handler 未接线时);本脚本走**真 handler +
# 真 form 编码**,专验前端页与后端 Form(...) 提取器的 body 编码契约(HIGH 修复的回归防线)。
#
# 用法:
#   API_URL=https://<host> CLIENTS_TABLE=<cdk 输出 ClientsTableName> AWS_PROFILE=default \
#     ./e2e/device_approve_page.sh
#   (自动 seed 一个 public client;device flow 仅限 public,同 device_flow.sh)
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE(cdk 输出 ClientsTableName)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT_ID="dev-approve-e2e-app"
EMAIL="device-approve-e2e-$RANDOM-$RANDOM@example.com"
CJAR=$(mktemp)
trap 'rm -f "$CJAR"' EXIT

echo "== 0. seed public client(device flow 仅限 public,token_endpoint_auth_method=none)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT_ID\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
echo "  client $CLIENT_ID 就绪 ✅"

agent_auth_provision_local_user "$API_URL" "$EMAIL"
echo "== 1. 已置备用户 magic-link 登录 → 会话 cookie(dev_link 从响应取,不真发)=="
RESP=$(curl -s -c "$CJAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"\"}")
DEV_LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$DEV_LINK" ] || { echo "❌ 无 dev_link: $RESP"; exit 1; }
PQ=$(echo "$DEV_LINK" | sed 's#.*/login/callback##')
curl -s -b "$CJAR" -c "$CJAR" -o /dev/null "$API_URL/login/callback$PQ"
grep -q "agent_auth_session" "$CJAR" || { echo "❌ 未建会话 cookie"; exit 1; }
echo "  登录成功,会话 cookie 已建 ✅"

echo "== 2. POST /device_authorization 铸 device_code + user_code =="
DA=$(curl -s -X POST "$API_URL/device_authorization" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "scope=openid")
DEVICE_CODE=$(echo "$DA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('device_code',''))")
USER_CODE=$(echo "$DA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('user_code',''))")
VURI=$(echo "$DA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('verification_uri',''))")
[ -n "$DEVICE_CODE" ] && [ -n "$USER_CODE" ] || { echo "❌ 无 device_code/user_code: $DA"; exit 1; }
echo "  device_code=${DEVICE_CODE:0:8}… user_code=$USER_CODE verification_uri=$VURI ✅"
# verification_uri MUST 指向前端批准页 /approve(评审 codex MED / spec 013 §2b)。
echo "$VURI" | grep -q "/approve$" || { echo "❌ verification_uri 未指向 /approve: $VURI"; exit 1; }
echo "  verification_uri 指向前端 /approve 页 ✅"

echo "== 3. 未批准轮询 → authorization_pending =="
P1=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=$DEVICE_CODE" --data-urlencode "client_id=$CLIENT_ID")
echo "$P1" | grep -q "authorization_pending" || { echo "❌ 期望 authorization_pending: $P1"; exit 1; }
echo "  authorization_pending ✅"

echo "== 4. POST /device(form-urlencoded + 会话 cookie)批准 —— 复刻前端 /approve 页 =="
# 关键:前端 formBody 序列化器发 application/x-www-form-urlencoded(HIGH 修复);approve=true 布尔串。
APPROVE_CODE=$(curl -s -b "$CJAR" -o /dev/null -w '%{http_code}' -X POST "$API_URL/device" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "user_code=$USER_CODE" --data-urlencode "approve=true")
[ "$APPROVE_CODE" = "204" ] || { echo "❌ POST /device 批准应 204(form 编码),实得 $APPROVE_CODE"; exit 1; }
echo "  POST /device 批准返 204(form 编码契约通过,HIGH 修复验证)✅"

echo "== 5. 批准后轮询 → 签出 3LO access token =="
sleep 5  # 避 slow_down(interval=5)
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=$DEVICE_CODE" --data-urlencode "client_id=$CLIENT_ID")
AT=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$AT" ] || { echo "❌ 未签出 access_token: $TOK"; exit 1; }
echo "  签出 access_token(len=${#AT})✅"

echo "== 6. 无会话 POST /device → 401(防匿名批准)=="
NOAUTH=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/device" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "user_code=ABCD1234" --data-urlencode "approve=true")
[ "$NOAUTH" = "401" ] || { echo "❌ 无会话批准应 401,实得 $NOAUTH"; exit 1; }
echo "  无会话批准拒 401 ✅"

echo ""
echo "==== device 批准页链路真机 e2e 全绿(form 编码 HIGH 修复验证)✅ ===="

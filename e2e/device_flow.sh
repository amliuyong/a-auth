#!/usr/bin/env bash
# P2 device flow 真机 e2e(RFC 8628,spec 013 C7b.4):
#   discovery 宣告 device_authorization_endpoint → /device_authorization 铸 device_code+user_code →
#   轮询 authorization_pending → (批准:直写 DeviceTable status=approved+user_id,批准页 handler 未接线)→
#   轮询签出 3LO access token(sub=用户、含 jti)→ 重放 invalid_grant(一次性)。
#
# 批准环节:真机批准页 UI 尚未落地(spec 013 §2b backlog),此处用 aws dynamodb update-item 直改记录
# 模拟"用户已在批准页批准"——e2e 只验协议面(铸码/轮询/签发/一次性),不验 UI。
#
# 用法:
#   API_URL=https://<cf-or-apigw-host> DEVICE_TABLE=<cdk 输出 DeviceTableName> \
#   CLIENTS_TABLE=<cdk 输出 ClientsTableName> AWS_PROFILE=default ./e2e/device_flow.sh
#
# 依赖:aws cli、curl、python3。账号号/资源名不硬编码——由环境传入。
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
DEVICE_TABLE="${DEVICE_TABLE:?需 DEVICE_TABLE(cdk 输出 DeviceTableName)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE(cdk 输出 ClientsTableName)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-device-client"
CCG="urn:ietf:params:oauth:grant-type:device_code"

echo "== 1. seed 一个 public 客户端(device flow 仅限 public)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"

echo "== 2. discovery 断言 device_authorization_endpoint 已宣告(P2)=="
DAE=$(curl -s "$API_URL/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin).get('device_authorization_endpoint',''))")
[ "$DAE" = "$API_URL/device_authorization" ] || { echo "❌ device_authorization_endpoint=$DAE"; exit 1; }
echo "  $DAE ✅"

echo "== 3. POST /device_authorization 铸 device_code + user_code =="
DA=$(curl -s -X POST "$API_URL/device_authorization" -H "content-type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT&scope=openid kb:read")
DEVICE_CODE=$(echo "$DA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('device_code',''))")
USER_CODE=$(echo "$DA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('user_code',''))")
INTERVAL=$(echo "$DA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('interval',''))")
[ -n "$DEVICE_CODE" ] && [ -n "$USER_CODE" ] || { echo "❌ 无 device_code/user_code: $DA"; exit 1; }
echo "  device_code=${DEVICE_CODE:0:8}… user_code=$USER_CODE interval=$INTERVAL ✅"

echo "== 4. 未批准轮询 → authorization_pending =="
P1=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=$CCG&device_code=$DEVICE_CODE&client_id=$CLIENT")
ERR=$(echo "$P1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$ERR" = "authorization_pending" ] || { echo "❌ 未批准应 authorization_pending(got: $P1)"; exit 1; }
echo "  authorization_pending ✅"

echo "== 5. 模拟批准(直写 DeviceTable:status=approved + user_id=alice)=="
aws dynamodb update-item --profile "$PROFILE" --region "$REGION" --table-name "$DEVICE_TABLE" \
  --key "{\"device_code\":{\"S\":\"$DEVICE_CODE\"}}" \
  --update-expression "SET #s = :a, user_id = :u" \
  --expression-attribute-names '{"#s":"status"}' \
  --expression-attribute-values '{":a":{"S":"approved"},":u":{"S":"alice"}}' >/dev/null
echo "  批准写入 ✅"

echo "== 6. 轮询签出 3LO access token(sub=alice、含 jti)=="
# 若刚轮询过可能 slow_down;等 interval+1s 再轮询。
sleep $((INTERVAL + 1))
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=$CCG&device_code=$DEVICE_CODE&client_id=$CLIENT")
JWT=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$JWT" ] || { echo "❌ 批准后未签出 token(got: $TOK)"; exit 1; }
echo "$JWT" | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')
c=json.loads(base64.urlsafe_b64decode(p[1]+'='*(-len(p[1])%4)))
assert c['sub']=='alice', c['sub']
assert c.get('jti'), 'no jti'
ns=c.get('https://a-auth.com/c',{})
assert ns.get('sub_type')=='user', ns
print('  sub=alice sub_type=user jti✓ ✅')
"
echo "$TOK" | python3 -c "import sys,json; assert json.load(sys.stdin).get('refresh_token') is None, 'device flow 不应发 refresh'; print('  无 refresh_token ✅')"

echo "== 7. 一次性:重放同 device_code → invalid_grant =="
sleep $((INTERVAL + 1))
REPLAY=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=$CCG&device_code=$DEVICE_CODE&client_id=$CLIENT")
RERR=$(echo "$REPLAY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$RERR" = "invalid_grant" ] || { echo "❌ 已消费 device_code 重放应 invalid_grant(got: $REPLAY)"; exit 1; }
echo "  重放 → invalid_grant ✅"

echo "✅ P2 device flow 真机 e2e 全绿"

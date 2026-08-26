#!/usr/bin/env bash
# CIBA 防批准疲劳节流真机 e2e(spec 013 Task 3.1/3.4,C7b.6)。
#
# 同一 login_hint 狂发 /bc-authorize → 首发 200、冷却窗(60s)内再发 429 slow_down;不同 login_hint
# 不受影响(per-login_hint 非全局)。防 MFA 推送轰炸(与 magic-link per-email 冷却对称)。
#
# 用法:  API_URL=https://<host> CLIENTS_TABLE=<cdk ClientsTableName> AWS_PROFILE=default ./e2e/ciba_throttle.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT_ID="ciba-throttle-e2e-app"
# login_hint MUST 为**已注册** email(spec 013 §2b.5:未注册 → invalid_request,先于节流判定)。
# 用带随机后缀的 email,避免上次运行的冷却窗残留污染(60s TTL)。
RAND="$RANDOM-$RANDOM"
HINT="ciba-victim-$RAND@example.com"
HINT2="ciba-other-$RAND@example.com"
HINT3="ciba-carol-$RAND@example.com"
pass=0; fail=0

echo "== 0. seed public client(CIBA 仅限 public)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT_ID\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
echo "  client $CLIENT_ID 就绪 ✅"

# 被代表用户须先由 Admin 置备(§2b.5 存在性校验先于节流)。
echo "== 0b. Admin 置备被代表用户(§2b.5 存在性校验)=="
agent_auth_provision_local_user "$API_URL" "$HINT"
agent_auth_provision_local_user "$API_URL" "$HINT2"
agent_auth_provision_local_user "$API_URL" "$HINT3"
echo "  ✅ 3 个 login_hint 用户已注册"

bc() { # login_hint → "http_code body"
  curl -s -o /tmp/ciba_body -w '%{http_code}' -X POST "$API_URL/bc-authorize" \
    -H "content-type: application/x-www-form-urlencoded" \
    --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "scope=openid" \
    --data-urlencode "login_hint=$1"
}

echo "== 1. 首发同 login_hint → 200 =="
C=$(bc "$HINT"); B=$(cat /tmp/ciba_body)
if [ "$C" = "200" ]; then echo "  ✅ 首发 200"; pass=$((pass+1)); else echo "  ❌ 首发应 200 实得 $C: $B"; fail=$((fail+1)); fi

echo "== 2. 冷却窗内再发同 login_hint → 429 temporarily_unavailable =="
C=$(bc "$HINT"); B=$(cat /tmp/ciba_body)
if [ "$C" = "429" ] && echo "$B" | grep -q "temporarily_unavailable"; then
  echo "  ✅ 冷却拦截 429 temporarily_unavailable"; pass=$((pass+1))
else echo "  ❌ 应 429 temporarily_unavailable 实得 $C: $B"; fail=$((fail+1)); fi

echo "== 2b. 大小写变体不绕过节流(归一 lowercase,M2)=="
C=$(bc "$(echo "$HINT" | tr '[:lower:]' '[:upper:]')"); B=$(cat /tmp/ciba_body)
if [ "$C" = "429" ]; then echo "  ✅ 大写变体同键被节流"; pass=$((pass+1)); else echo "  ❌ 大写变体应 429 实得 $C: $B"; fail=$((fail+1)); fi

echo "== 3. 不同 login_hint 不受影响 → 200 =="
C=$(bc "$HINT2"); B=$(cat /tmp/ciba_body)
if [ "$C" = "200" ]; then echo "  ✅ 异 login_hint 200(per-login_hint 非全局)"; pass=$((pass+1)); else echo "  ❌ 异 hint 应 200 实得 $C: $B"; fail=$((fail+1)); fi

echo "== 4. 非法请求(缺 openid)不占冷却窗 =="
curl -s -o /dev/null -X POST "$API_URL/bc-authorize" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=$CLIENT_ID" --data-urlencode "scope=kb:read" --data-urlencode "login_hint=$HINT3" >/dev/null
C=$(bc "$HINT3"); B=$(cat /tmp/ciba_body)
if [ "$C" = "200" ]; then echo "  ✅ 非法请求未占冷却窗(后续合法 200)"; pass=$((pass+1)); else echo "  ❌ 应 200 实得 $C: $B"; fail=$((fail+1)); fi

rm -f /tmp/ciba_body
echo ""
echo "==== 结果:$pass 通过, $fail 失败 ===="
[ "$fail" -eq 0 ] || exit 1

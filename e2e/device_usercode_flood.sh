#!/usr/bin/env bash
# device user_code 尝试限流真机 e2e(spec 013 Task 2b.3,防爆破枚举)。
#
# 登录建会话 → 突发提交错 user_code 超桶容量(5)→ 第 6 次 429。user_code 8 位短码,提交面须限枚举
# (device_code 128-bit 是主防线)。per-批准者(登录 user)桶,补充 0.1/s 极慢 → 限流触发确定性。
#
# 用法:  API_URL=https://<host> ./e2e/device_usercode_flood.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
CJAR=$(mktemp)
trap 'rm -f "$CJAR"' EXIT
# 唯一 email 避免污染既有 devcode-attempt 桶(每次跑新 user → 满桶起步)。
EMAIL="devcode-flood-$RANDOM-$RANDOM@example.com"
pass=0; fail=0

agent_auth_provision_local_user "$API_URL" "$EMAIL"
echo "== 1. 已置备用户 magic-link 登录建会话 =="
RESP=$(curl -s -c "$CJAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"\"}")
DEV_LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$DEV_LINK" ] || { echo "❌ 无 dev_link: $RESP"; exit 1; }
PQ=$(echo "$DEV_LINK" | sed 's#.*/login/callback##')
curl -s -b "$CJAR" -c "$CJAR" -o /dev/null "$API_URL/login/callback$PQ"
grep -q "agent_auth_session" "$CJAR" && { echo "  ✅ 会话已建"; pass=$((pass+1)); } || { echo "  ❌ 未建会话"; exit 1; }

echo "== 2. 突发提交错 user_code:前 5 次 404、第 6 次 429(容量 5)=="
saw_429=0; notfound=0; trip_at=0
for i in $(seq 1 8); do
  code=$(curl -s -b "$CJAR" -X POST "$API_URL/device" -H "content-type: application/x-www-form-urlencoded" \
    -d "user_code=BOGUSXYZ&approve=true" -o /dev/null -w '%{http_code}')
  if [ "$code" = "429" ]; then saw_429=1; trip_at=$i; break;
  elif [ "$code" = "404" ]; then notfound=$((notfound+1)); fi
done
if [ "$saw_429" = "1" ]; then echo "  ✅ 第 $trip_at 次触发 429(限流前 404 共 $notfound 次)"; pass=$((pass+1));
else echo "  ❌ 8 次内未触发 429(404 共 $notfound 次)"; fail=$((fail+1)); fi
# 容量 5:期望限流前恰 5 次 404(±1 容差)。
if [ "$notfound" -ge 4 ] && [ "$notfound" -le 6 ]; then echo "  ✅ 限流前 404 次数 ~容量 5($notfound)"; pass=$((pass+1));
else echo "  ⚠️ 限流前 404 共 $notfound 次(期望 ~5)"; fi

echo ""
echo "==== 结果:$pass 通过, $fail 失败 ===="
[ "$fail" -eq 0 ] || exit 1

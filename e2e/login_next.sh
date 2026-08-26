#!/usr/bin/env bash
# 登录 next 回跳 open-redirect 防护真机 e2e(spec 003 §"登录后 next 回跳",P0.5)。
#
# 复刻前端 /account、/approve 会话过期引导 /login?next=<原页> 的链路:magic-link 请求带 next →
# callback 回跳。断言:合法同源相对 next 回原页;恶意 next(绝对/协议相对/编码斜杠)fail-closed 回落首页,
# 绝不 open-redirect(Location 不指向外部)。校验点在后端 sanitize_next(评审 codex+Kiro 收敛)。
#
# 用法:  API_URL=https://<host> ./e2e/login_next.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
pass=0; fail=0

# 发起带 next 的 magic-link,打开 callback,返回回跳 Location(不跟随)。
# ⚠️ 每次用**不同 email**(带随机后缀):per-email 冷却 60s,同 email 连发会被 429 限流(C9.1)。
login_next_loc() { # next → echo Location
  local next="$1" cjar resp devlink pq email
  email="next-e2e-$RANDOM-$RANDOM@example.com"
  cjar=$(mktemp)
  agent_auth_provision_local_user "$API_URL" "$email"
  resp=$(curl -s -c "$cjar" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
    -d "$(EMAIL="$email" python3 -c "import json,sys,os;print(json.dumps({'email':os.environ['EMAIL'],'authorize_query':'','next':sys.argv[1]}))" "$next")")
  devlink=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
  if [ -z "$devlink" ]; then rm -f "$cjar"; echo "ERR_NO_DEVLINK:$resp"; return; fi
  pq=$(echo "$devlink" | sed 's#.*/login/callback##')
  # -D - 拿响应头(取 Location);不 -L(不跟随)。
  curl -s -b "$cjar" -o /dev/null -D - "$API_URL/login/callback$pq" | grep -i '^location:' | sed 's/[Ll]ocation: //;s/\r//'
  rm -f "$cjar"
}

echo "== 1. 合法同源相对 next → 回原页 =="
LOC=$(login_next_loc "/approve?auth_req_id=abc-123")
if echo "$LOC" | grep -q "/approve?auth_req_id=abc-123"; then
  echo "  ✅ 合法 next 回原页: $LOC"; pass=$((pass+1))
else echo "  ❌ 合法 next 未回原页: $LOC"; fail=$((fail+1)); fi

echo "== 2. 恶意 next → fail-closed 回落首页,不 open-redirect =="
for bad in "https://evil.example/steal" "//evil.example" "/%2f%2fevil.example" "/%5c%5cevil.example" "javascript:alert(1)"; do
  LOC=$(login_next_loc "$bad")
  if echo "$LOC" | grep -qi "evil.example\|javascript:"; then
    echo "  ❌ open-redirect 泄漏! next=$bad → $LOC"; fail=$((fail+1))
  elif echo "$LOC" | grep -qE '/$'; then
    echo "  ✅ next=$bad fail-closed 回落首页: $LOC"; pass=$((pass+1))
  else
    echo "  ⚠️ next=$bad 未回落首页(但也未泄漏): $LOC"; fail=$((fail+1))
  fi
done

echo ""
echo "==== 结果:$pass 通过, $fail 失败 ===="
[ "$fail" -eq 0 ] || exit 1

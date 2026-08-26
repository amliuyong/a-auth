#!/usr/bin/env bash
# 前端交互页 CloudFront 路由真机 e2e(spec 011 §5.1 /account + spec 013 §2b /approve)。
#
# 验证**页/动作 path 分离**(spec 025 统一入口):SPA 页面 path 落 S3(返 index.html 壳),
# 同名 API 动作 path 落 default→API(返 JSON 401/其它),二者不冲突。这是本批前端页唯一的
# 部署特定风险(页面内部逻辑 + API 端点已由 grants_api.sh / device_flow.sh / ciba.sh 覆盖)。
#
# 用法:
#   SPA_URL=https://<cloudfront> API_URL=https://<apigw-or-cloudfront> ./e2e/frontend_pages.sh
set -euo pipefail

SPA_URL="${SPA_URL:?需 SPA_URL(CloudFront 域名)}"
# 统一入口下 API 与 SPA 同域;分域部署可单独给 API_URL。默认同 SPA_URL(走 CloudFront default→API)。
API_URL="${API_URL:-$SPA_URL}"

pass=0; fail=0
check() { # desc, actual, expected
  if [ "$2" = "$3" ]; then echo "  ✅ $1 ($2)"; pass=$((pass+1));
  else echo "  ❌ $1: 期望 $3 实得 $2"; fail=$((fail+1)); fi
}
# 取页面 body(判是否 SPA 壳)。
body_has_root() { curl -s "$1" | grep -q 'id="root"'; }

echo "== 1. SPA 页面 path → S3(index.html 壳,200)=="
for p in /login /consent /recover /account /approve /admin /error; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "$SPA_URL$p")
  check "GET $p 返 200(SPA 壳)" "$code" "200"
  if body_has_root "$SPA_URL$p"; then echo "  ✅ $p 含 SPA root 容器"; pass=$((pass+1));
  else echo "  ❌ $p 不含 id=\"root\"(未命中 SPA 壳,可能落 API)"; fail=$((fail+1)); fi
done

echo "== 2. API 动作 path → default→API(非 SPA 壳)=="
# GET /grants 无会话 cookie → 401(API 语义),证明 /grants 落 API 而非被 SPA 页吞。
code=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/grants")
check "GET /grants 无会话 → 401(API)" "$code" "401"
if body_has_root "$API_URL/grants"; then echo "  ❌ /grants 返回了 SPA 壳(path 冲突!)"; fail=$((fail+1));
else echo "  ✅ /grants 非 SPA 壳(正确落 API)"; pass=$((pass+1)); fi

# GET /bc-approve/{id} 无会话 → 401(API);且不是 SPA 壳。
code=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/bc-approve/nonexistent")
check "GET /bc-approve/x 无会话 → 401(API)" "$code" "401"

# POST /recovery/generate 无会话 → 401(spec 003 §2.3 / C9.3):恢复码生成须登录会话,
# 不留匿名可达面(安全底线)。/account 页的恢复码设置区消费此端点。
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/generate")
check "POST /recovery/generate 无会话 → 401(API)" "$code" "401"
if body_has_root "$API_URL/recovery/generate"; then echo "  ❌ /recovery/generate 返回了 SPA 壳(path 冲突!)"; fail=$((fail+1));
else echo "  ✅ /recovery/generate 非 SPA 壳(正确落 API)"; pass=$((pass+1)); fi

# GET /recovery/status 无会话 → 401(同鉴权面,不泄露他人是否配置恢复)。
code=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/recovery/status")
check "GET /recovery/status 无会话 → 401(API)" "$code" "401"

# /device 是 POST-only(spec 013);GET 该 path 不应返回 SPA 壳(避免与 /approve 页混淆)。
if body_has_root "$API_URL/device"; then echo "  ❌ /device 返回了 SPA 壳(path 冲突!)"; fail=$((fail+1));
else echo "  ✅ /device 非 SPA 壳(正确落 API)"; pass=$((pass+1)); fi

echo "== 3. /approve 页可带 query bookmark(user_code / auth_req_id 预填不改路由)=="
code=$(curl -s -o /dev/null -w '%{http_code}' "$SPA_URL/approve?user_code=ABCD1234")
check "GET /approve?user_code=.. 返 200" "$code" "200"
code=$(curl -s -o /dev/null -w '%{http_code}' "$SPA_URL/approve?auth_req_id=xyz")
check "GET /approve?auth_req_id=.. 返 200" "$code" "200"

echo "== 4. clickjacking 防护(C10.9b):交互页 CSP frame-ancestors 'none' + X-Frame-Options DENY =="
# CloudFront ResponseHeadersPolicy 对交互页下发安全头(consent/login 等禁 iframe 嵌套)。
for p in /consent /login; do
  hdrs=$(curl -sI "$SPA_URL$p")
  csp=$(echo "$hdrs" | grep -i "content-security-policy" | tr -d '\r')
  xfo=$(echo "$hdrs" | grep -i "x-frame-options" | tr -d '\r')
  if echo "$csp" | grep -qi "frame-ancestors 'none'"; then
    echo "  ✅ $p CSP 含 frame-ancestors 'none'"; pass=$((pass+1));
  else echo "  ❌ $p 缺 CSP frame-ancestors 'none'(得: $csp)"; fail=$((fail+1)); fi
  if echo "$xfo" | grep -qi "DENY"; then
    echo "  ✅ $p X-Frame-Options: DENY"; pass=$((pass+1));
  else echo "  ❌ $p 缺 X-Frame-Options: DENY(得: $xfo)"; fail=$((fail+1)); fi
done

echo ""
echo "==== 结果:$pass 通过, $fail 失败 ===="
[ "$fail" -eq 0 ] || exit 1

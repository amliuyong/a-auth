#!/usr/bin/env bash
# 真机 e2e:CORS 按端点五分类(spec 005 §6 / C10.10)。经 CloudFront 统一入口域。
#
# 验证 build_router 的 CORS 分组在真实 AWS(API GW→Lambda,经 CloudFront)上按端点分类:
#   ①公开 GET(discovery/JWKS)+ ②协议 POST(token/revoke/introspect/device_authorization/bc-authorize)
#     + ③open 档 /register → Access-Control-Allow-Origin: *;
#   ④会话端点(grants/sessions/consent/admin/register 管理)+ ⑤导航(authorize)→ 无 CORS 头;
#   任何端点不设 Access-Control-Allow-Credentials: true。
#
# 用法:BASE_URL=https://<cloudfront 域> ./e2e/cors.sh
# 依赖:curl。不碰 AWS 资源(纯 HTTP 头断言)。
set -euo pipefail

BASE_URL="${BASE_URL:?需 BASE_URL(CloudFront 统一入口域)}"
ORIGIN="https://app.example.com"

# 取某请求的 Access-Control-Allow-Origin 头(小写化);无则空。
ao_header() {
  local method="$1" path="$2" extra="${3:-}"
  curl -s -o /dev/null -D - -X "$method" "$BASE_URL$path" \
    -H "Origin: $ORIGIN" $extra 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}'
}
# preflight OPTIONS 的 Allow-Origin。
preflight_ao() {
  local path="$1" reqmethod="$2"
  curl -s -o /dev/null -D - -X OPTIONS "$BASE_URL$path" \
    -H "Origin: $ORIGIN" -H "Access-Control-Request-Method: $reqmethod" 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-origin"{print $2}'
}
# 任何端点都不该出现 Allow-Credentials: true。
ac_header() {
  local method="$1" path="$2"
  curl -s -o /dev/null -D - -X "$method" "$BASE_URL$path" \
    -H "Origin: $ORIGIN" 2>/dev/null \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="access-control-allow-credentials"{print $2}'
}

fail() { echo "❌ $1"; exit 1; }

echo "== ① 公开 GET → Allow-Origin: * =="
for p in "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server" "/jwks.json"; do
  ao=$(ao_header GET "$p")
  [ "$ao" = "*" ] || fail "$p Allow-Origin='$ao'(期望 *)"
  echo "  $p → * ✅"
done

echo "== ② 协议 POST preflight → Allow-Origin: * =="
for p in "/token" "/revoke" "/introspect" "/device_authorization" "/bc-authorize"; do
  ao=$(preflight_ao "$p" POST)
  [ "$ao" = "*" ] || fail "$p preflight Allow-Origin='$ao'(期望 *)"
  echo "  $p preflight → * ✅"
done

echo "== ③ open 档 /register preflight → Allow-Origin: * =="
ao=$(preflight_ao "/register" POST)
[ "$ao" = "*" ] || fail "/register preflight Allow-Origin='$ao'(期望 *)"
echo "  /register → * ✅"

echo "== ④ 会话端点 → 无 CORS 头 =="
for p in "/grants" "/sessions" "/admin/overview"; do
  ao=$(ao_header GET "$p")
  [ -z "$ao" ] || fail "$p 会话端点不应发 Allow-Origin(got '$ao')"
  echo "  $p → 无 Allow-Origin ✅"
done
ao=$(preflight_ao "/consent/decision" POST)
[ -z "$ao" ] || fail "/consent/decision 不应发 Allow-Origin(got '$ao')"
echo "  /consent/decision → 无 Allow-Origin ✅"

echo "== ④ RFC 7592 管理端点 → 无 CORS 头 =="
ao=$(ao_header GET "/register/some-id")
[ -z "$ao" ] || fail "/register/{id} 管理端点不应发 Allow-Origin(got '$ao')"
echo "  /register/{id} → 无 Allow-Origin ✅"

echo "== ⑤ 导航 /authorize → 无 CORS 头 =="
ao=$(ao_header GET "/authorize?response_type=code&client_id=x&redirect_uri=y")
[ -z "$ao" ] || fail "/authorize 导航不应发 Allow-Origin(got '$ao')"
echo "  /authorize → 无 Allow-Origin ✅"

echo "== 红线:任何 CORS 端点都不设 Allow-Credentials: true =="
for p in "/jwks.json" "/token" "/register"; do
  ac=$(ac_header GET "$p")
  [ "$ac" != "true" ] || fail "$p 出现 Allow-Credentials: true(与 * 组合浏览器禁止)"
done
echo "  无 Allow-Credentials: true ✅"

echo ""
echo "✅ CORS 五分类真机 e2e 全绿(公开GET/协议POST/open register=* · 会话/管理/导航无CORS · 无 Allow-Credentials — C10.10)"

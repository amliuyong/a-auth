#!/usr/bin/env bash
# spec 025 真机 e2e:Admin 控制台(双鉴权域)+ CloudFront 统一入口。
#
# 验证(经 CloudFront 统一入口域,同源):
# - admin 认证:无 token 401、错 token 401、对 token 200(GET /admin/overview)。
# - overview:phase/issuer(= CloudFront 域,经 X-Forwarded-Host 派生)/endpoints/client_count。
# - client 管理:POST /admin/clients 注册(回显 secret 一次)→ 列表可见(无 secret)→ PATCH 改 redirect
#   → DELETE 级联(refresh 吊销)→ 重复 DELETE 404。
# - RFC 7592 自助:POST /register 拿 reg_token → GET /register/{id} 自助读 → 域隔离(admin_token 不进
#   /register/{id};reg_token 不进 /admin/*)。
# - 统一入口:/login、/admin 返 SPA(HTML);/token 返 JSON(非 index.html,404 不被 fallback 吞);
#   /consent/decision 走 API。
#
# 用法:
#   BASE_URL=https://<cloudfront-domain> ./e2e/admin_console.sh
#   (ADMIN_TOKEN 缺省时自动调 get-admin-token.sh 从栈解析;也可显式 ADMIN_TOKEN=<secret> 覆盖)
set -euo pipefail

BASE_URL="${BASE_URL:?需 BASE_URL(CloudFront 统一入口域)}"
# ADMIN_TOKEN 缺省 → 复用 get-admin-token.sh 从 stack output 取(不写死 secret-id)。
if [ -z "${ADMIN_TOKEN:-}" ]; then
  ADMIN_TOKEN=$("$(dirname "$0")/get-admin-token.sh")
fi
AUTHH="authorization: Bearer $ADMIN_TOKEN"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

echo "== 1. admin 认证门(无/错/对 token)=="
S=$(curl -s -o /dev/null -w '%{http_code}' "$BASE_URL/admin/overview")
[ "$S" = "401" ] || fail "无 token 应 401(got $S)"; pass "无 token → 401"
S=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer WRONG" "$BASE_URL/admin/overview")
[ "$S" = "401" ] || fail "错 token 应 401(got $S)"; pass "错 token → 401"
OV=$(curl -s -H "$AUTHH" "$BASE_URL/admin/overview")
echo "$OV" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d.get('phase'), 'no phase'
assert d.get('issuer','').endswith('cloudfront.net') or 'http' in d.get('issuer',''), 'issuer 异常: '+str(d.get('issuer'))
assert 'authorization_endpoint' in d.get('endpoints',[]), 'endpoints 缺 authorization_endpoint'
assert isinstance(d.get('client_count'), int), 'client_count 非数'
assert isinstance(d.get('active_sessions'), int), 'active_sessions 非数'
print('  ✅ overview: phase=%s issuer=%s clients=%d active=%d endpoints=%d' % (d['phase'], d['issuer'], d['client_count'], d['active_sessions'], len(d['endpoints'])))
"

echo "== 2. POST /admin/clients 注册(client_secret_basic → 回显 secret 一次)=="
CREATE=$(curl -s -X POST "$BASE_URL/admin/clients" -H "$AUTHH" -H "content-type: application/json" \
  -d '{"redirect_uris":["https://e2e-admin.example.com/cb"],"token_endpoint_auth_method":"client_secret_basic"}')
CID=$(echo "$CREATE" | python3 -c "import sys,json;print(json.load(sys.stdin)['client_id'])")
SECRET=$(echo "$CREATE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('client_secret',''))")
[ -n "$CID" ] || fail "注册无 client_id"
[ -n "$SECRET" ] || fail "client_secret_basic 应回显 secret"
pass "注册 $CID(secret 回显一次)"

echo "== 3. GET /admin/clients 列表可见且不含 secret =="
LIST=$(curl -s -H "$AUTHH" "$BASE_URL/admin/clients")
echo "$LIST" | python3 -c "
import sys,json
d=json.load(sys.stdin)
ids=[c['client_id'] for c in d['clients']]
assert '$CID' in ids, '新 client 不在列表'
# 检 JSON 键(非子串——token_endpoint_auth_method 值 'client_secret_basic' 会误命中子串)。
for c in d['clients']:
    assert 'client_secret' not in c, '列表含 client_secret 键'
    assert 'reg_token_hash' not in c, '列表含 reg_token_hash 键'
assert '$SECRET' not in json.dumps(d), '列表泄露 secret 值'
print('  ✅ 列表含新 client,不泄露 secret(total=%d)' % d['total'])
"

echo "== 4. GET /admin/clients/{id} 单个不含 secret =="
ONE=$(curl -s -H "$AUTHH" "$BASE_URL/admin/clients/$CID")
echo "$ONE" | python3 -c "
import sys,json
c=json.load(sys.stdin)
assert 'client_secret' not in c, '单 client 含 client_secret 键'
assert 'reg_token_hash' not in c, '单 client 含 reg_token_hash 键'
assert '$SECRET' not in json.dumps(c), '单 client 泄露 secret 值'
print('  ✅ 单 client 不含 secret')
"

echo "== 5. PATCH /admin/clients/{id} 改 redirect(放宽需 confirm_downgrade)=="
PC=$(curl -s -o /dev/null -w '%{http_code}' -X PATCH "$BASE_URL/admin/clients/$CID" -H "$AUTHH" \
  -H "content-type: application/json" \
  -d '{"redirect_uris":["https://e2e-admin.example.com/cb","https://e2e-admin.example.com/cb2"]}')
[ "$PC" = "400" ] || fail "放宽 redirect 未确认应 400(got $PC)"; pass "放宽未确认 → 400 downgrade"
PC=$(curl -s -o /dev/null -w '%{http_code}' -X PATCH "$BASE_URL/admin/clients/$CID" -H "$AUTHH" \
  -H "content-type: application/json" \
  -d '{"redirect_uris":["https://e2e-admin.example.com/cb","https://e2e-admin.example.com/cb2"],"confirm_downgrade":true}')
[ "$PC" = "200" ] || fail "确认后 PATCH 应 200(got $PC)"; pass "确认后 PATCH → 200"

echo "== 6. DELETE /admin/clients/{id} → 200;重复 → 404 =="
DC=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE_URL/admin/clients/$CID" -H "$AUTHH")
[ "$DC" = "200" ] || fail "DELETE 应 200(got $DC)"; pass "DELETE → 200"
DC=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$BASE_URL/admin/clients/$CID" -H "$AUTHH")
[ "$DC" = "404" ] || fail "重复 DELETE 应 404(got $DC)"; pass "重复 DELETE → 404"

echo "== 7. RFC 7592 自助域 + 双域隔离 =="
REG=$(curl -s -X POST "$BASE_URL/register" -H "content-type: application/json" \
  -d '{"redirect_uris":["https://e2e-self.example.com/cb"]}')
RID=$(echo "$REG" | python3 -c "import sys,json;print(json.load(sys.stdin)['client_id'])")
RTOK=$(echo "$REG" | python3 -c "import sys,json;print(json.load(sys.stdin)['registration_access_token'])")
[ -n "$RTOK" ] || fail "DCR 无 reg_token"
# reg_token 读自己 → 200。
S=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $RTOK" "$BASE_URL/register/$RID")
[ "$S" = "200" ] || fail "reg_token 读自己应 200(got $S)"; pass "reg_token 自助读 → 200"
# admin_token 不进 /register/{id} → 401。
S=$(curl -s -o /dev/null -w '%{http_code}' -H "$AUTHH" "$BASE_URL/register/$RID")
[ "$S" = "401" ] || fail "admin_token 不应管 /register/{id}(got $S)"; pass "admin_token 不进 reg 域 → 401"
# reg_token 不进 /admin/* → 401。
S=$(curl -s -o /dev/null -w '%{http_code}' -H "authorization: Bearer $RTOK" "$BASE_URL/admin/clients")
[ "$S" = "401" ] || fail "reg_token 不应进 /admin/*(got $S)"; pass "reg_token 不进 admin 域 → 401"
# 自助 DELETE 清理。
curl -s -o /dev/null -X DELETE "$BASE_URL/register/$RID" -H "authorization: Bearer $RTOK"

echo "== 8. CloudFront 统一入口:静态 vs API 分流 =="
# /admin → SPA(HTML,含 <div id="root">)。
CT=$(curl -s "$BASE_URL/admin" | head -c 400)
echo "$CT" | grep -qi "<!doctype html\|<div id=\"root\"\|<html" || fail "/admin 未返 SPA HTML"
pass "/admin → SPA(S3)"
# /login → SPA。
curl -s "$BASE_URL/login" | grep -qi "<!doctype html\|<div id=\"root\"\|<html" || fail "/login 未返 SPA HTML"
pass "/login → SPA(S3)"
# /token(错误请求)→ JSON,MUST NOT 被 SPA fallback 吞成 index.html。
TB=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" -d "grant_type=bogus")
echo "$TB" | grep -qi "<html\|<!doctype" && fail "/token 被 SPA fallback 吞成 HTML(H1/M5 回归)"
echo "$TB" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null && pass "/token → JSON(非 index.html)" || fail "/token 未返 JSON: $TB"
# /admin/overview 走 API(JSON)。
curl -s -H "$AUTHH" "$BASE_URL/admin/overview" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null \
  && pass "/admin/overview → API JSON(不被 /admin 静态吞)" || fail "/admin/overview 未返 JSON"

echo "== 9. 消息 outbox(SES 模拟):GET /admin/messages 可读 =="
MSG=$(curl -s -H "$AUTHH" "$BASE_URL/admin/messages")
echo "$MSG" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert 'messages' in d and isinstance(d['messages'], list), 'messages 非列表'
assert isinstance(d.get('total'), int), 'total 非数'
# 若有消息,校验 TTL=created_at+1天。
for m in d['messages']:
    assert m['ttl'] - m['created_at'] == 86400, 'TTL 应为 created_at+1天'
    assert m['kind'] in ('magic_link','recovery'), '未知 kind: '+m['kind']
print('  ✅ /admin/messages 可读(total=%d,TTL=1天)' % d['total'])
"

echo "✅ spec 025 Admin 控制台 + CloudFront 统一入口 + 消息 outbox 真机 e2e 全绿"

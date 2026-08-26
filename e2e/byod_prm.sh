#!/usr/bin/env bash
# 真机 e2e:BYOD 数据面 PRM 托管(投放方式 b,spec 010 §5.4 / C8.1b,P3)。
#
# 验证 BYOD 在真实 AWS(API Gateway→Lambda→DynamoDB DomainMap)端到端成立:
# - admin 绑 domain→resource(全局 domain map 行,conditional put 全局唯一);
# - GET /.well-known/oauth-protected-resource(伪造 X-Forwarded-Host=已登记 BYOD 域名)→ 200 PRM,
#   ★ authorization_servers 从**存储 tenant_id + form 重建**(= 本 AS issuer),绝不用请求 Host;
# - 未登记 / 伪造 Host → 404;issuer-origin host(configured_host)自身 → 404(C8.1 不破);
# - 全局唯一:他人再绑同域名 → 409;注册期拒 issuer-origin host 作 prm_domain;
# - 删 client 级联清 map 行(well-known 不再命中)。
#
# ⚠ 前置:dev 栈须以 AGENT_AUTH_BYOD_ENABLED=1 部署(否则 well-known 短路 404、admin bind 拒)。
#   直连 execute-api API_URL 伪造 X-Forwarded-Host 即可验安全语义(不需真 CNAME/证书;那是路由便利)。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default ./e2e/byod_prm.sh
#   (ADMIN_TOKEN 未给则自动 e2e/get-admin-token.sh 取)
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${STACK:-AgentAuthDev}"

# admin token(登入 /admin/domains、/admin/clients)。未给则从栈取。
ADMIN_TOKEN="${ADMIN_TOKEN:-$(STACK="$STACK" REGION="$REGION" PROFILE="$PROFILE" "$(dirname "$0")/get-admin-token.sh")}"
[ -n "$ADMIN_TOKEN" ] || { echo "❌ 无 ADMIN_TOKEN"; exit 1; }
AUTH=(-H "authorization: Bearer $ADMIN_TOKEN")

# 随机后缀,避免与既有绑定/历史残留冲突(BYOD 域名全局唯一,重跑须新域名)。
RAND="$RANDOM$RANDOM"
BYOD_DOMAIN="mcp-e2e-$RAND.acme.example"       # 真第三方 BYOD 域名(非本 AS issuer zone,过 issuer-origin 护栏)
RS_RESOURCE="https://$BYOD_DOMAIN"
CID=""; CID2=""

cleanup() {
  # 幂等清理:解绑域名 + 删两个 client(忽略错误)。
  curl -s -X DELETE "${AUTH[@]}" "$API_URL/admin/domains/$BYOD_DOMAIN" >/dev/null 2>&1 || true
  [ -n "$CID" ]  && curl -s -X DELETE "${AUTH[@]}" "$API_URL/admin/clients/$CID"  >/dev/null 2>&1 || true
  [ -n "$CID2" ] && curl -s -X DELETE "${AUTH[@]}" "$API_URL/admin/clients/$CID2" >/dev/null 2>&1 || true
}
trap cleanup EXIT

jqget() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }
code_of() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "== 0. admin 建 client(resource_ids 含 $RS_RESOURCE)=="
RESP=$(curl -s -X POST "${AUTH[@]}" -H "content-type: application/json" \
  -d "{\"redirect_uris\":[\"https://rs.example/cb\"],\"introspect_enabled\":true,\"resource_ids\":[\"$RS_RESOURCE\"]}" \
  "$API_URL/admin/clients")
CID=$(echo "$RESP" | jqget "['client_id']")
[ -n "$CID" ] || { echo "❌ 建 client 失败:$RESP"; exit 1; }
echo "  ✅ client_id=$CID"

echo "== 1. BYOD 未启用短路自检:若 well-known 对已登记域名也 404,则栈未开 BYOD =="
# 先探测 flag:未绑定时任何域名都应 404(无从区分);真正判定在步骤 3 绑定后是否 200。

echo "== 2. admin 绑 domain→resource(全局唯一 conditional put)=="
ST=$(curl -s -o /tmp/byod_bind.$$ -w '%{http_code}' -X POST "${AUTH[@]}" -H "content-type: application/json" \
  -d "{\"domain\":\"$BYOD_DOMAIN\",\"resource_id\":\"$RS_RESOURCE\",\"client_id\":\"$CID\"}" \
  "$API_URL/admin/domains")
if [ "$ST" = "400" ] && grep -q "BYOD not enabled" /tmp/byod_bind.$$; then
  echo "❌ 栈未以 AGENT_AUTH_BYOD_ENABLED=1 部署——请带该 env 重部署 dev 栈后重跑。"; rm -f /tmp/byod_bind.$$; exit 2
fi
rm -f /tmp/byod_bind.$$
[ "$ST" = "201" ] || { echo "❌ 绑定应 201(got $ST)"; exit 1; }
echo "  ✅ 已绑定 $BYOD_DOMAIN → $RS_RESOURCE"

echo "== 3. well-known 命中:X-Forwarded-Host=BYOD 域名 → 200 + issuer 从存储重建(非请求 Host)=="
PRM=$(curl -s -H "x-forwarded-host: $BYOD_DOMAIN" "$API_URL/.well-known/oauth-protected-resource")
echo "$PRM" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['resource']=='$RS_RESOURCE', d
# ★ authorization_servers MUST 从存储 tenant_id + form 重建 = 本 AS issuer(SelfHosted=configured_host),
#   绝不指向 BYOD 域名自身(那是 misdirection)。
srv=d['authorization_servers']
assert isinstance(srv,list) and len(srv)==1, d
assert srv[0]!='https://$BYOD_DOMAIN', ('misdirection! authorization_servers 指向了 RS 自己域名', d)
assert srv[0].startswith('https://'), d
assert 'bearer_methods_supported' in d, d
print('  ✅ PRM.resource 匹配 + authorization_servers=%s(从存储重建,非请求 Host)' % srv[0])
"

echo "== 4. 未登记 / 伪造 Host → 404 =="
ST=$(code_of -H "x-forwarded-host: evil-$RAND.example" "$API_URL/.well-known/oauth-protected-resource")
[ "$ST" = "404" ] || { echo "❌ 未登记 Host 应 404(got $ST)"; exit 1; }
echo "  ✅ 伪造/未登记 Host → 404"

echo "== 5. 全局唯一:另一 client 抢注同域名 → 409 =="
RESP=$(curl -s -X POST "${AUTH[@]}" -H "content-type: application/json" \
  -d "{\"redirect_uris\":[\"https://rs2.example/cb\"],\"introspect_enabled\":true,\"resource_ids\":[\"$RS_RESOURCE\"]}" \
  "$API_URL/admin/clients")
CID2=$(echo "$RESP" | jqget "['client_id']")
ST=$(code_of -X POST "${AUTH[@]}" -H "content-type: application/json" \
  -d "{\"domain\":\"$BYOD_DOMAIN\",\"resource_id\":\"$RS_RESOURCE\",\"client_id\":\"$CID2\"}" \
  "$API_URL/admin/domains")
[ "$ST" = "409" ] || { echo "❌ 抢注已登记域名应 409(got $ST)"; exit 1; }
echo "  ✅ 已登记域名不可被他人抢注 → 409"

echo "== 6. 注册期拒 issuer-origin host 作 prm_domain(SelfHosted configured_host)=="
# configured_host 从 discovery issuer 反推(去 https://)。
ISS=$(curl -s "$API_URL/.well-known/openid-configuration" | jqget "['issuer']")
ISS_HOST=${ISS#https://}
ST=$(code_of -X POST "${AUTH[@]}" -H "content-type: application/json" \
  -d "{\"domain\":\"$ISS_HOST\",\"resource_id\":\"$RS_RESOURCE\",\"client_id\":\"$CID\"}" \
  "$API_URL/admin/domains")
[ "$ST" = "400" ] || { echo "❌ issuer-origin host 作 prm_domain 应 400(got $ST,issuer_host=$ISS_HOST)"; exit 1; }
echo "  ✅ issuer-origin host($ISS_HOST)被注册期护栏拒 → 400"

echo "== 7. issuer origin 自身命中 well-known 仍 404(C8.1 不破)=="
ST=$(code_of -H "x-forwarded-host: $ISS_HOST" "$API_URL/.well-known/oauth-protected-resource")
[ "$ST" = "404" ] || { echo "❌ issuer origin 上该路径应 404(got $ST)"; exit 1; }
echo "  ✅ issuer origin 上无全局 PRM → 404"

echo "== 8. 删 client 级联清 map 行 → well-known 不再命中 =="
curl -s -X DELETE "${AUTH[@]}" "$API_URL/admin/clients/$CID" >/dev/null
CID=""  # 已删,cleanup 不再重复
# 级联后该域名 well-known 应 404。
ST=$(code_of -H "x-forwarded-host: $BYOD_DOMAIN" "$API_URL/.well-known/oauth-protected-resource")
[ "$ST" = "404" ] || { echo "❌ 删 client 后其 BYOD 域名应级联清除 → 404(got $ST)"; exit 1; }
echo "  ✅ 删 client 级联清 domain map 行 → 404"

echo ""
echo "🎉 BYOD PRM 真机 e2e 全绿(spec 010 §5.4 / C8.1b)"

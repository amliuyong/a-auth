#!/usr/bin/env bash
# spec 012 真机 e2e:workload client 生命周期 + 信任绑定登记 + C5.6 拒 3LO(经 CloudFront 统一入口)。
#
# 验证:
# - admin 建 workload client(client_type=workload)→ 该 client /authorize 被拒(C5.6,unauthorized_client)。
# - admin 登记 OIDC 信任绑定(C5.5):绑到 workload client → 201;绑到非 workload → 400。
# - 列出租户信任绑定含刚登记的。
# - DCR 无法铸 workload(C5.5):workload auth method → 400。
#
# 用法:BASE_URL=https://<cf-domain> AWS_PROFILE=default ./e2e/workload_trust.sh
set -euo pipefail

BASE_URL="${BASE_URL:?需 BASE_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
WL_CLIENT="e2e-workload-agent"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

# admin token 自动取。
ADMIN_TOKEN="${ADMIN_TOKEN:-$("$(dirname "$0")/get-admin-token.sh")}"
AUTHH="authorization: Bearer $ADMIN_TOKEN"

echo "== 0. seed workload client(client_type=workload;真机直接写表)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$WL_CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"client_type\":{\"S\":\"workload\"}}" >/dev/null
pass "workload client 已建"

echo "== 1. C5.6:workload client 发起 /authorize → 拒(unauthorized_client)=="
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(b'v').digest()).rstrip(b'=').decode())")
BODY=$(curl -s "$BASE_URL/authorize?response_type=code&client_id=$WL_CLIENT&redirect_uri=https://x/cb&code_challenge=$CH&code_challenge_method=S256&scope=openid&login_user=alice")
echo "$BODY" | grep -q "unauthorized_client" || fail "workload /authorize 未返 unauthorized_client: $BODY"
echo "$BODY" | grep -qi "workload" || fail "错误未说明 workload"
pass "workload /authorize → unauthorized_client"

echo "== 2. C5.5:admin 登记 OIDC 信任绑定绑到 workload client → 201 =="
REG=$(cat <<JSON
{"binding_id":"e2e-b1","tenant_id":"default","platform_issuer":"https://token.actions.githubusercontent.com","jwks_uri":"https://token.actions.githubusercontent.com/.well-known/jwks","subject_pattern":"repo:acme/agent:*","mapped_client_id":"$WL_CLIENT"}
JSON
)
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/admin/workload-trust" -H "$AUTHH" \
  -H "content-type: application/json" -d "$REG")
[ "$ST" = "201" ] || fail "绑 workload client 应 201(got $ST)"; pass "OIDC 信任绑定登记 → 201"

echo "== 3. 无 admin token → 401 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/admin/workload-trust" \
  -H "content-type: application/json" -d "$REG")
[ "$ST" = "401" ] || fail "无 admin token 应 401(got $ST)"; pass "无 admin token → 401"

echo "== 4. 列出租户信任绑定含刚登记的 =="
LIST=$(curl -s -H "$AUTHH" "$BASE_URL/admin/workload-trust/default")
echo "$LIST" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert any(b['mapped_client_id']=='$WL_CLIENT' and b['mechanism']=='oidc' for b in d['bindings']), '列表缺刚登记绑定: '+json.dumps(d)
print('  ✅ 列表含刚登记绑定(total=%d)' % d['total'])
"

echo "== 5. C5.5:DCR 无法铸 workload(workload auth method → 400)=="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/register" \
  -H "content-type: application/json" \
  -d '{"redirect_uris":["https://x/cb"],"token_endpoint_auth_method":"workload_oidc_jwt"}')
[ "$ST" = "400" ] || fail "DCR workload auth method 应 400(got $ST)"; pass "DCR 拒 workload auth method → 400"

echo "== 6. 清理 =="
curl -s -o /dev/null -X DELETE "$BASE_URL/admin/clients/$WL_CLIENT" -H "$AUTHH" || true
pass "清理 workload client"

echo "✅ spec 012 workload client 生命周期 + 信任绑定登记 + C5.6/C5.5 真机 e2e 全绿"

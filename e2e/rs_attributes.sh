#!/usr/bin/env bash
# spec 007 真机 e2e:RS 命名空间用户属性(§6.1,C8.11/C8.12,SelfHosted)。
#
# 验证在真实 AWS(API Gateway→Lambda→KMS+DynamoDB)端到端成立:
# - admin PUT 属性 → RS(aud=namespace)token 读到 + sub 一致 + revision;
# - 跨命名空间隔离(RS-B token 读不到 RS-A 命名空间);
# - 反向隔离:aud=<issuer>/userinfo 的 token 调 /rs/attributes → 403;非 admin 写 → 401;
# - 乐观锁:stale If-Match → 409;体积超限 → 413;非 URI namespace → 400;
# - active-user gate:被禁用户 token 读 → fail-closed(4xx)。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> STACK=AgentAuthDev AWS_PROFILE=default ./e2e/rs_attributes.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
STACK="${STACK:-AgentAuthDev}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"

RS_A="https://mcp.a7.example.com/"
RS_B="https://mcp.b7.example.com/"
APP_A="e2e-attr-app-a"       # 绑 default_resource=RS_A
APP_B="e2e-attr-app-b"       # 绑 default_resource=RS_B
APP_OIDC="e2e-attr-app-oidc" # 无 default_resource → token aud=<issuer>/userinfo
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
EMAIL="attr-e2e-$$@example.com"     # 唯一 email(避免撞已存在用户)
USER_ID="user:${EMAIL}"             # POST /admin/users 派生口径

ddb_put() { aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --item "$1" >/dev/null; }
enc() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

echo "== 0. 取 admin token + seed clients =="
ADMIN=$(STACK="$STACK" REGION="$REGION" PROFILE="$PROFILE" ./e2e/get-admin-token.sh)
[ -n "$ADMIN" ] || { echo "❌ 无 admin token"; exit 1; }
ddb_put "{\"client_id\":{\"S\":\"$APP_A\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"default_resource\":{\"S\":\"$RS_A\"}}"
ddb_put "{\"client_id\":{\"S\":\"$APP_B\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"default_resource\":{\"S\":\"$RS_B\"}}"
ddb_put "{\"client_id\":{\"S\":\"$APP_OIDC\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"

echo "== 1. 创建测试用户($EMAIL)——active-user gate 需其存在 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/users" \
  -H "authorization: Bearer $ADMIN" -H "content-type: application/json" -d "{\"email\":\"$EMAIL\"}")
[ "$ST" = "200" ] || [ "$ST" = "201" ] || { echo "❌ 建用户失败(got $ST)"; exit 1; }

# 签一枚 aud=<resource> 的 access token(authorize+token;login_user=真实 user_id)。
mint() {
  local app="$1"
  local challenge; challenge=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
  local uid_enc; uid_enc=$(enc "$USER_ID")
  local loc; loc=$(curl -s -o /dev/null -w '%{redirect_url}' \
    "$API_URL/authorize?response_type=code&client_id=$app&redirect_uri=$(enc "$REDIRECT")&code_challenge=$challenge&code_challenge_method=S256&scope=openid&state=s&login_user=$uid_enc")
  local code; code=$(echo "$loc" | sed 's/.*code=\([^&]*\).*/\1/')
  local tok; tok=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$code&code_verifier=$VERIFIER&redirect_uri=$(enc "$REDIRECT")&client_id=$app")
  echo "$tok" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"
}

put_attr() { # user_id namespace body if_match auth_bearer  -> http_code
  local uid="$1" ns="$2" body="$3" ifm="$4" auth="$5"
  local hdr=()
  [ -n "$ifm" ] && hdr=(-H "if-match: $ifm")
  # namespace 走 query 参数(URI 含 / 经 path 段会被 API Gateway 误拆导致 404,真机实测)。
  curl -s -o /dev/null -w '%{http_code}' -X PUT \
    "$API_URL/admin/users/$(enc "$uid")/attributes?namespace=$(enc "$ns")" \
    -H "authorization: $auth" -H "content-type: application/json" "${hdr[@]}" -d "$body"
}

echo "== 2. admin 写 RS_A 属性(首写)→ 200 =="
ST=$(put_attr "$USER_ID" "$RS_A" '{"role":"admin","team":"x"}' "" "Bearer $ADMIN")
[ "$ST" = "200" ] || { echo "❌ 首写应 200(got $ST)"; exit 1; }
echo "  ✅ 首写成功"

echo "== 3. RS_A token 读到属性 + sub 一致 + revision =="
AT_A=$(mint "$APP_A"); [ -n "$AT_A" ] || { echo "❌ 无 RS_A token"; exit 1; }
RESP=$(curl -s "$API_URL/rs/attributes" -H "authorization: Bearer $AT_A")
echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['attributes']['role']=='admin', d
assert d['attributes']['team']=='x', d
assert d['revision']==1, d
assert isinstance(d['sub'],str) and d['sub'], d
print('  ✅ 读到属性 role=admin + revision=1 + sub 存在')
"

echo "== 4. 跨命名空间隔离:RS_B token 读 → 空 attributes =="
AT_B=$(mint "$APP_B"); [ -n "$AT_B" ] || { echo "❌ 无 RS_B token"; exit 1; }
RESP=$(curl -s "$API_URL/rs/attributes" -H "authorization: Bearer $AT_B")
echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['attributes']=={}, ('RS_B 命名空间应为空(隔离)',d)
print('  ✅ 跨命名空间隔离:RS_B 读不到 RS_A 属性')
"

echo "== 5. 反向隔离:aud=<issuer>/userinfo 的 token 调 /rs/attributes → 403 =="
AT_O=$(mint "$APP_OIDC"); [ -n "$AT_O" ] || { echo "❌ 无 OIDC token"; exit 1; }
ST=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/rs/attributes" -H "authorization: Bearer $AT_O")
[ "$ST" = "403" ] || { echo "❌ userinfo token 应 403(got $ST)"; exit 1; }
echo "  ✅ userinfo token 不当属性 namespace(403)"

echo "== 6. 非 admin(RS token)写属性 → 401 =="
ST=$(put_attr "$USER_ID" "$RS_A" '{"role":"admin"}' "" "Bearer $AT_A")
[ "$ST" = "401" ] || { echo "❌ 非 admin 写应 401(got $ST)"; exit 1; }
echo "  ✅ 非 admin 写属性被拒(401)"

echo "== 7. 乐观锁:stale If-Match=0 → 409;正确 revision=1 → 200 =="
ST=$(put_attr "$USER_ID" "$RS_A" '{"role":"editor"}' "0" "Bearer $ADMIN")
[ "$ST" = "409" ] || { echo "❌ stale If-Match 应 409(got $ST)"; exit 1; }
ST=$(put_attr "$USER_ID" "$RS_A" '{"role":"editor"}' "1" "Bearer $ADMIN")
[ "$ST" = "200" ] || { echo "❌ 正确 revision 应 200(got $ST)"; exit 1; }
echo "  ✅ 乐观锁:stale 409 / 正确 200"

echo "== 8. 边界:超 4KB → 413;非 URI namespace → 400;值非字符串 → 400;零长 body → 400 =="
# 校验类(400)在 revision 之前:与 If-Match/revision 无关,任意 namespace 都应拒。
ST=$(put_attr "$USER_ID" "not-a-uri" '{"k":"v"}' "" "Bearer $ADMIN")
[ "$ST" = "400" ] || { echo "❌ 非 URI namespace 应 400(got $ST)"; exit 1; }
ST=$(put_attr "$USER_ID" "$RS_B" '{"k":123}' "" "Bearer $ADMIN")
[ "$ST" = "400" ] || { echo "❌ 值非字符串应 400(got $ST)"; exit 1; }
# 超 4KB:用**全新 namespace**(revision 0,无 If-Match 冲突),隔离出体积检查 → 413。
BIG=$(python3 -c "print('{\"blob\":\"'+'x'*5000+'\"}')")
ST=$(put_attr "$USER_ID" "https://mcp.big7.example.com/" "$BIG" "" "Bearer $ADMIN")
[ "$ST" = "413" ] || { echo "❌ 超限应 413(got $ST)"; exit 1; }
ST=$(put_attr "$USER_ID" "$RS_A" '' "" "Bearer $ADMIN")
[ "$ST" = "400" ] || { echo "❌ 零长 body 应 400(got $ST)"; exit 1; }
echo "  ✅ 边界 413/400 全对"

echo "== 9. active-user gate:禁用该用户后 RS token 读 → fail-closed(4xx)=="
curl -s -o /dev/null -X POST "$API_URL/admin/users/$(enc "$USER_ID")/disable" -H "authorization: Bearer $ADMIN"
ST=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/rs/attributes" -H "authorization: Bearer $AT_A")
case "$ST" in 401|403) echo "  ✅ 被禁用户读 fail-closed($ST)";; *) echo "❌ 被禁用户读应 4xx(got $ST)"; exit 1;; esac

echo "== 10. 清理:tombstone 测试用户(级联清属性,GDPR)=="
curl -s -o /dev/null -X DELETE "$API_URL/admin/users/$(enc "$USER_ID")" -H "authorization: Bearer $ADMIN"

echo "✅ spec 007 RS 命名空间用户属性真机 e2e 全绿"

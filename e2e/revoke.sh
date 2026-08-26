#!/usr/bin/env bash
# spec 011 C7.6a 真机 e2e:POST /revoke(RFC 7009)+ P1 discovery 宣告 revocation_endpoint。
#
# 验证(经 CloudFront 统一入口域):
# - discovery 升 P1:/.well-known 宣告 revocation_endpoint + revocation_endpoint_auth_methods_supported。
# - code flow 拿 refresh → /revoke 吊销 → 该 refresh 续期被拒(invalid_grant)。
# - 调用方认证:匿名 revoke → 401(不留匿名可达吊销面)。
# - 幂等:未知 token / 重复吊销 → 200(RFC 7009 §2.2,不泄露存在性)。
#
# 用法:
#   BASE_URL=https://<cloudfront-domain> CLIENTS_TABLE=<clients 表> \
#   AWS_PROFILE=default ./e2e/revoke.sh
set -euo pipefail

BASE_URL="${BASE_URL:?需 BASE_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-revoke-client"
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

echo "== 0. seed public client =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null

echo "== 1. discovery 升 P1:宣告 revocation_endpoint(+auth methods)=="
DISC=$(curl -s "$BASE_URL/.well-known/openid-configuration")
echo "$DISC" | python3 -c "
import sys,json
d=json.load(sys.stdin)
re=d.get('revocation_endpoint')
assert re and re.endswith('/revoke'), 'discovery 未宣告 revocation_endpoint: '+str(re)
assert 'introspection_endpoint' in d, 'P1 应宣告 introspection_endpoint'
assert 'end_session_endpoint' in d, 'P1 应宣告 end_session_endpoint'
ams=d.get('revocation_endpoint_auth_methods_supported')
assert isinstance(ams, list) and ams, 'revocation_endpoint_auth_methods_supported 缺'
print('  ✅ discovery P1:revocation_endpoint=%s auth_methods=%s' % (re, ams))
"

echo "== 2. code flow 拿 refresh_token =="
CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
AUTHZ="$BASE_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&login_user=alice"
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHZ")
CODE=$(echo "$LOC" | sed 's/.*[?&]code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || fail "authorize 未回 code(LOC=$LOC)"
TOK=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
REFRESH=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
[ -n "$REFRESH" ] || fail "token 未回 refresh_token"
pass "拿到 refresh_token"

echo "== 3. 匿名 revoke → 401(不留匿名可达吊销面)=="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/revoke" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$REFRESH")
[ "$ST" = "401" ] || fail "匿名 revoke 应 401(got $ST)"; pass "匿名 revoke → 401"

echo "== 4. 本 client 吊销自己的 refresh → 200 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/revoke" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$REFRESH&client_id=$CLIENT")
[ "$ST" = "200" ] || fail "本 client 吊销应 200(got $ST)"; pass "本 client 吊销 → 200"

echo "== 5. 吊销后该 refresh 续期被拒(invalid_grant)=="
RESP=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH&client_id=$CLIENT")
echo "$RESP" | grep -q "invalid_grant" || fail "吊销后续期应 invalid_grant(got $RESP)"
pass "吊销后 refresh 续期被拒"

echo "== 6. 幂等:未知 token / 重复吊销 → 200(RFC 7009 §2.2)=="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/revoke" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=nonexistent.0&client_id=$CLIENT")
[ "$ST" = "200" ] || fail "未知 token 应 200(got $ST)"; pass "未知 token → 200"
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/revoke" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$REFRESH&client_id=$CLIENT")
[ "$ST" = "200" ] || fail "重复吊销应 200(got $ST)"; pass "重复吊销幂等 → 200"

echo "✅ spec 011 C7.6a /revoke + P1 discovery 真机 e2e 全绿"

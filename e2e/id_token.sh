#!/usr/bin/env bash
# spec 001 C2.6/C2.7/C2.9 真机 e2e:openid code flow 签发 id_token(KMS RSA / RS256)。
#
# 验证(经 CloudFront 统一入口域):
# - JWKS 发布 EC(access) + RSA(id_token)双 key;discovery subject_types=public(与透传 sub 一致)。
# - magic-link 登录 → consent approve → /token 返回 id_token:
#   alg=RS256、typ=JWT(非 at+jwt)、aud=client_id、nonce echo、auth_time 存在、kid 命中 JWKS RSA key。
#
# 用法:BASE_URL=https://<cf域> CLIENTS_TABLE=<clients 表> AWS_PROFILE=default ./e2e/id_token.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

BASE_URL="${BASE_URL:?需 BASE_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-idtoken-client"
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
NONCE="e2e-nonce-$(python3 -c 'import random;print(random.randint(1,1_000_000))')"
JAR="$(mktemp)"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

echo "== 1. JWKS 双 key(EC access + RSA id_token)+ discovery subject_types =="
curl -s "$BASE_URL/jwks.json" | python3 -c "
import sys,json
ks=[k['kty'] for k in json.load(sys.stdin)['keys']]
assert 'EC' in ks and 'RSA' in ks, 'JWKS 应含 EC+RSA: '+str(ks)
print('  ✅ JWKS keys =', ks)
"

echo "== 2. seed client + magic-link 登录 =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
AQ="client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid&state=st&code_challenge=$CH&code_challenge_method=S256&nonce=$NONCE"
EMAIL="idtoken-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
agent_auth_provision_local_user "$BASE_URL" "$EMAIL"
RESP=$(curl -s -c "$JAR" -X POST "$BASE_URL/login/magic-link" -H "content-type: application/json" -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"$AQ\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || fail "无 dev_link"
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')
curl -s -b "$JAR" -c "$JAR" -o /dev/null "$BASE_URL$PQ"
pass "已登录建会话"

echo "== 3. consent approve → code =="
CSRF=$(curl -s -b "$JAR" "$BASE_URL/consent/context?$AQ" | python3 -c "import sys,json;print(json.load(sys.stdin).get('csrf_token',''))")
[ -n "$CSRF" ] || fail "无 csrf_token"
REDIR=$(curl -s -b "$JAR" -X POST "$BASE_URL/consent/decision" -H "content-type: application/json" \
  -d "{\"decision\":\"approve\",\"csrf\":\"$CSRF\",\"authorize_query\":\"$AQ\"}" | python3 -c "import sys,json;print(json.load(sys.stdin).get('redirect',''))")
CODE=$(echo "$REDIR" | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || fail "无 code"

echo "== 4. /token 返回 id_token(RS256/aud=client_id/nonce/auth_time)=="
TOK=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
# 取 JWKS 供 kid 命中校验。
JWKS=$(curl -s "$BASE_URL/jwks.json")
echo "$TOK" | CLIENT="$CLIENT" NONCE="$NONCE" JWKS="$JWKS" python3 -c "
import sys,json,base64,os
d=json.load(sys.stdin)
idt=d.get('id_token'); assert idt, 'token 响应无 id_token: '+json.dumps(d)[:200]
def seg(i): return json.loads(base64.urlsafe_b64decode(idt.split('.')[i]+'=='))
h,c=seg(0),seg(1)
assert h['alg']=='RS256', 'alg 应 RS256: '+h['alg']
assert h.get('typ')=='JWT', 'typ 应 JWT(非 at+jwt): '+str(h.get('typ'))
assert c['aud']==os.environ['CLIENT'], 'aud 应 client_id'
assert c['nonce']==os.environ['NONCE'], 'nonce 应 echo'
assert 'auth_time' in c, 'id_token 应含 auth_time'
# amr(C9.5b:登录方法透传进 id_token;magic-link 登录 → amr=['email'])。
# 此断言若在 acr/amr 全链修复前跑会失败(旧版 SessionRecord/CodeRecord 无 acr/amr 字段,claim 缺失)。
assert c.get('amr')==['email'], 'id_token 应含登录方法 amr=[email](C9.5b 透传链;实得 %s)' % c.get('amr')
# kid 命中 JWKS RSA key。
rsa_kids=[k['kid'] for k in json.loads(os.environ['JWKS'])['keys'] if k['kty']=='RSA']
assert h['kid'] in rsa_kids, 'id_token kid 应命中 JWKS RSA key'
print('  ✅ id_token: alg=RS256 typ=JWT aud=%s nonce✓ auth_time=%s amr=%s kid命中RSA' % (c['aud'], c['auth_time'], c['amr']))
"

echo "== 5. 清理 =="
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$CLIENT\"}}" >/dev/null 2>&1
rm -f "$JAR"
echo "✅ spec 001 C2.6/C2.7/C2.9 id_token(KMS RS256)真机 e2e 全绿"

#!/usr/bin/env bash
# 真机 e2e:验证本轮落地的三项能力在真实 AWS(API Gateway→Lambda→KMS+DynamoDB)可达且行为正确。
#
# 覆盖:
#  A. SPIFFE JWT-SVID(spec 012 §1.4/C5.7):discovery 宣告 spiffe_jwt_svid + admin 登记 SpiffeJwt 绑定
#     (含护栏:整域通配拒 / pattern 非 SPIFFE ID 拒 / 复用 AS JWKS 拒)+ list 回显。
#  B. DPoP AS 侧签发(spec 010 §5.2,委托继承 011 §7.2 的底座):code flow 带 DPoP 头 → access token
#     含 cnf.jkt == RFC 7638 thumbprint of proof.jwk;token_type=DPoP。无 DPoP → bearer。
#  C. token-exchange 端点可达(spec 011):P2 宣告 token-exchange grant;缺参数返结构化错误(非 5xx)。
#
# 用法:API_URL=https://<cf-domain> CLIENTS_TABLE=<clients 表> AWS_PROFILE=default ./e2e/session_capabilities.sh
#
# 依赖:aws cli、curl、python3(+cryptography 造 DPoP proof / 算 jkt)。账号号/资源名不硬编码。
set -euo pipefail

API_URL="${API_URL:?需 API_URL(CloudFront 统一入口 / 自定义域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
HOST="${API_URL#https://}"
CLIENT="e2e-dpop-client"
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

ADMIN_TOKEN="${ADMIN_TOKEN:-$("$(dirname "$0")/get-admin-token.sh")}"
AUTHH="authorization: Bearer $ADMIN_TOKEN"

echo "== A1. discovery 宣告 spiffe_jwt_svid(012 §1.4)+ token-exchange grant(011)=="
DISC=$(curl -s "$API_URL/.well-known/openid-configuration")
echo "$DISC" | python3 -c "
import sys,json
d=json.load(sys.stdin)
m=d.get('token_endpoint_auth_methods_supported',[])
assert 'spiffe_jwt_svid' in m, 'spiffe_jwt_svid 未宣告: '+json.dumps(m)
assert 'spiffe_svid_mtls' not in m, 'spiffe_svid_mtls(X.509-mTLS 未实现)不应宣告'
g=d.get('grant_types_supported',[])
assert 'urn:ietf:params:oauth:grant-type:token-exchange' in g, 'token-exchange grant 未宣告'
print('  ✅ discovery: spiffe_jwt_svid 宣告 / spiffe_svid_mtls 不宣告 / token-exchange grant 宣告')
"

echo "== A2. admin 登记 SpiffeJwt 信任绑定(012 §1.4;mechanism=spiffe_jwt)=="
# 先建一个 workload client 作 mapped 目标(直接写表)。
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item '{"client_id":{"S":"e2e-spiffe-wl"},"redirect_uris":{"L":[]},"token_endpoint_auth_method":{"S":"none"},"client_type":{"S":"workload"}}' >/dev/null
OK=$(cat <<'JSON'
{"binding_id":"e2e-spiffe-b1","tenant_id":"default","mechanism":"spiffe_jwt","trust_domain":"acme.example","jwks_uri":"https://spire.acme.example/bundle","subject_pattern":"spiffe://acme.example/agent/*","mapped_client_id":"e2e-spiffe-wl"}
JSON
)
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/workload-trust" -H "$AUTHH" -H "content-type: application/json" -d "$OK")
[ "$ST" = "201" ] || fail "SpiffeJwt 绑定登记应 201(got $ST)"
pass "SpiffeJwt 绑定登记 → 201"

echo "== A3. SpiffeJwt 护栏:整域通配拒 / pattern 非 SPIFFE ID 拒 / 复用 AS JWKS 拒(全 400)=="
WIDE=$(cat <<'JSON'
{"binding_id":"e2e-spiffe-wide","tenant_id":"default","mechanism":"spiffe_jwt","trust_domain":"acme.example","jwks_uri":"https://spire.acme.example/bundle","subject_pattern":"spiffe://acme.example/*","mapped_client_id":"e2e-spiffe-wl"}
JSON
)
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/workload-trust" -H "$AUTHH" -H "content-type: application/json" -d "$WIDE")
[ "$ST" = "400" ] || fail "整域通配 spiffe://<td>/* 应 400(got $ST)"; pass "整域通配拒 → 400"
NS=$(cat <<'JSON'
{"binding_id":"e2e-spiffe-ns","tenant_id":"default","mechanism":"spiffe_jwt","trust_domain":"acme.example","jwks_uri":"https://spire.acme.example/bundle","subject_pattern":"agent/*","mapped_client_id":"e2e-spiffe-wl"}
JSON
)
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/workload-trust" -H "$AUTHH" -H "content-type: application/json" -d "$NS")
[ "$ST" = "400" ] || fail "pattern 非完整 SPIFFE ID 应 400(got $ST)"; pass "pattern 非 SPIFFE ID 拒 → 400"
REUSE=$(python3 -c "print('{\"binding_id\":\"e2e-spiffe-reuse\",\"tenant_id\":\"default\",\"mechanism\":\"spiffe_jwt\",\"trust_domain\":\"acme.example\",\"jwks_uri\":\"$API_URL/jwks.json\",\"subject_pattern\":\"spiffe://acme.example/agent/*\",\"mapped_client_id\":\"e2e-spiffe-wl\"}')")
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/workload-trust" -H "$AUTHH" -H "content-type: application/json" -d "$REUSE")
[ "$ST" = "400" ] || fail "复用 AS JWKS 应 400(got $ST)"; pass "复用 AS 自身 JWKS 拒 → 400"

echo "== A4. list 回显 SpiffeJwt 绑定(mechanism=spiffe_jwt / trust_anchor=trust_domain)=="
curl -s -H "$AUTHH" "$API_URL/admin/workload-trust/default" | python3 -c "
import sys,json
d=json.load(sys.stdin)
b=[x for x in d['bindings'] if x['mapped_client_id']=='e2e-spiffe-wl' and x['mechanism']=='spiffe_jwt']
assert b, '列表缺 SpiffeJwt 绑定: '+json.dumps(d)
assert b[0]['trust_anchor']=='acme.example', 'trust_anchor 应=trust_domain: '+json.dumps(b[0])
print('  ✅ list 回显 SpiffeJwt(trust_anchor=acme.example,pattern=%s)' % b[0]['subject_pattern'])
"

echo "== B. DPoP AS 侧签发(010 §5.2):code flow 带 DPoP proof → access token 含 cnf.jkt =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
CODE=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&login_user=alice" \
  | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || fail "无 code"
# 造 DPoP proof(ES256,htu=<issuer>/token,htm=POST),换 token 时带 DPoP 头;断言 cnf.jkt==thumbprint。
python3 - "$API_URL" "$CODE" "$VERIFIER" "$REDIRECT" "$CLIENT" <<'PY'
import sys, json, base64, hashlib, time, subprocess
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
api, code, verifier, redirect, client = sys.argv[1:6]
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
sk = ec.generate_private_key(ec.SECP256R1())
nums = sk.public_key().public_numbers()
x = b64u(nums.x.to_bytes(32,'big')); y = b64u(nums.y.to_bytes(32,'big'))
jwk = {"crv":"P-256","kty":"EC","x":x,"y":y}  # RFC 7638 canonical order
jkt = b64u(hashlib.sha256(json.dumps(jwk,separators=(',',':'),sort_keys=True).encode()).digest())
hdr = {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}}
claims = {"htu": api+"/token","htm":"POST","iat":int(time.time()),"jti":b64u(hashlib.sha256(str(time.time()).encode()).digest()[:16])}
si = b64u(json.dumps(hdr,separators=(',',':')).encode())+"."+b64u(json.dumps(claims,separators=(',',':')).encode())
der = sk.sign(si.encode(), ec.ECDSA(hashes.SHA256()))
# DER → JOSE (r||s, 32B each)
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
r,s = decode_dss_signature(der)
sig = b64u(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
proof = si+"."+sig
out = subprocess.run(["curl","-s","-X","POST",api+"/token","-H","content-type: application/x-www-form-urlencoded",
  "-H","DPoP: "+proof,
  "-d",f"grant_type=authorization_code&code={code}&code_verifier={verifier}&redirect_uri={redirect}&client_id={client}"],
  capture_output=True,text=True).stdout
resp = json.loads(out)
assert resp.get("token_type")=="DPoP", "DPoP-bound token 应 token_type=DPoP: "+out
at = resp["access_token"]
payload = json.loads(base64.urlsafe_b64decode(at.split('.')[1]+'=='))
assert payload.get("cnf",{}).get("jkt")==jkt, f"cnf.jkt 应=={jkt}, got {payload.get('cnf')}"
print("  ✅ DPoP code flow → access token cnf.jkt==proof thumbprint + token_type=DPoP")
PY

echo "== B2. 无 DPoP 头 → bearer(不带 cnf)=="
CODE2=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&login_user=alice" \
  | sed 's/.*code=\([^&]*\).*/\1/')
BODY=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE2&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
echo "$BODY" | python3 -c "
import sys,json,base64
r=json.load(sys.stdin); assert r.get('token_type')=='Bearer', '无 DPoP 应 Bearer: '+json.dumps(r)
p=json.loads(base64.urlsafe_b64decode(r['access_token'].split('.')[1]+'=='))
assert 'cnf' not in p, 'bearer token 不应含 cnf'
print('  ✅ 无 DPoP → token_type=Bearer,无 cnf')
"

echo "== C. token-exchange 端点可达(011):缺 subject_token 返结构化 invalid_request(非 5xx)=="
ST=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange")
echo "$ST" | grep -qE "invalid_request|invalid_client|invalid_grant" || fail "token-exchange 缺参应返结构化错误: $ST"
pass "token-exchange 端点可达,缺参返结构化错误"

echo "== 清理 =="
for c in "$CLIENT" e2e-spiffe-wl; do curl -s -o /dev/null -X DELETE "$API_URL/admin/clients/$c" -H "$AUTHH" || true; done
pass "清理"

echo "✅ 本轮能力真机 e2e 全绿:SPIFFE JWT-SVID 宣告+登记护栏(012 §1.4)/ DPoP 签发 cnf.jkt(010 §5.2,011 §7.2 底座)/ token-exchange 端点(011)"

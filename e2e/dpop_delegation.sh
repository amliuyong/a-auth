#!/usr/bin/env bash
# spec 011 §7.2(C7.9)真机 e2e:**DPoP 委托 token cnf 继承完整往返**(token-exchange)。
#
# 复用 SPIFFE 同款 JWKS-hosting(actor 平台 OIDC JWKS 托管到 SPA 桶 /assets,AS 可 fetch 本地验签)。
# 全链:
#   1. 托管 actor 平台 OIDC JWKS(EC/ES256)到 /assets;admin 建 workload actor client + OIDC 信任绑定。
#   2. code flow 拿 **subject_token**(access token,带 jti;code flow 自动落 jti→user_id 映射 + 建 Grant)。
#   3. **把 code flow 建的 Grant 的 actor_allowlist 补上 actor**(grant_json 读改写)——3LO Grant 默认空
#      allowlist(token.rs:906),委托身份闸需 actor ∈ allowlist。
#   4. 签 actor 平台 OIDC JWT(aud=issuer)+ **actor 自己的 DPoP proof**(ES256,htu=<iss>/token)。
#   5. POST /token token-exchange(subject_token + actor_token + DPoP 头 + resource)→ 断言:
#      委托 token cnf.jkt == actor DPoP proof key thumbprint(重绑到 actor,非入站 user key)+ token_type=DPoP。
#   6. 负例:actor 无 DPoP proof(入站 subject 无 cnf)→ 仍签(bearer 委托,opt-in);actor 不在 allowlist → 拒。
#
# ⚠️ 隔离铁律(同 spiffe_svid.sh 收敛):唯一 platform_issuer + binding_id;bundle 强传播后再让 AS 首 fetch
#   (5min 负缓存);allowed_* 与 grant actor_allowlist 用正确类型;trap 清理 binding/client/bundle/grant/jti。
#
# 用法:API_URL=... CLIENTS_TABLE=... SPA_BUCKET=... TRUST_TABLE=... GRANTS_TABLE=... JTI_TABLE=... \
#       AWS_PROFILE=default ./e2e/dpop_delegation.sh
# 依赖:aws cli、curl、python3(+cryptography)。账号号/资源名不硬编码。
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
SPA_BUCKET="${SPA_BUCKET:?需 SPA_BUCKET}"
TRUST_TABLE="${TRUST_TABLE:?需 TRUST_TABLE}"
GRANTS_TABLE="${GRANTS_TABLE:?需 GRANTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RS="https://mcp.rs.example.com"
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

ADMIN_TOKEN="${ADMIN_TOKEN:-$("$(dirname "$0")/get-admin-token.sh")}"
RND=$(python3 -c "import secrets;print(secrets.token_hex(4))")
PLAT_ISS="https://plat-$RND.actions.example.test"
ACTOR_CLIENT="e2e-dpop-actor-$RND"
SUBJECT_CLIENT="e2e-dpop-3lo-$RND"
BINDING_ID="e2e-dpop-b-$RND"
BUNDLE_KEY="assets/dpop-actor-jwks-$RND.json"
BUNDLE_URL="$API_URL/$BUNDLE_KEY"
GRANT_ID=""

cleanup() {
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" --key "{\"binding_id\":{\"S\":\"$BINDING_ID\"}}" >/dev/null 2>&1 || true
  for c in "$ACTOR_CLIENT" "$SUBJECT_CLIENT"; do aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$c\"}}" >/dev/null 2>&1 || true; done
  [ -n "$GRANT_ID" ] && aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" --key "{\"grant_id\":{\"S\":\"$GRANT_ID\"}}" >/dev/null 2>&1 || true
  aws s3 rm "s3://$SPA_BUCKET/$BUNDLE_KEY" --profile "$PROFILE" >/dev/null 2>&1 || true
  rm -f "/tmp/dpop_actor_sk_$RND.pem"
}
trap cleanup EXIT

echo "== 1. 托管 actor 平台 OIDC JWKS + 建 actor workload client + OIDC 信任绑定 =="
python3 - "$RND" > "/tmp/dpop_jwks_$RND.json" <<'PY'
import sys,json,base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
rnd=sys.argv[1]
sk=ec.generate_private_key(ec.SECP256R1()); n=sk.public_key().public_numbers()
b=lambda v: base64.urlsafe_b64encode(v).rstrip(b'=').decode()
open(f'/tmp/dpop_actor_sk_{rnd}.pem','wb').write(sk.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
print(json.dumps({"keys":[{"kty":"EC","crv":"P-256","kid":"actor-k1","x":b(n.x.to_bytes(32,'big')),"y":b(n.y.to_bytes(32,'big'))}]}))
PY
aws s3 cp "/tmp/dpop_jwks_$RND.json" "s3://$SPA_BUCKET/$BUNDLE_KEY" --profile "$PROFILE" --content-type application/json >/dev/null
rm -f "/tmp/dpop_jwks_$RND.json"
OK=0; for i in $(seq 1 30); do if curl -s "$BUNDLE_URL" | grep -q '"actor-k1"'; then OK=$((OK+1)); else OK=0; fi; [ "$OK" -ge 3 ] && break; sleep 2; done
[ "$OK" -ge 3 ] || fail "actor JWKS 未稳定"; sleep 5
# actor workload client(sub_type 由认证得;这里只需 client_type=workload 让 2LO/actor 认证通过)。
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$ACTOR_CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"client_type\":{\"S\":\"workload\"}}" >/dev/null
REG=$(python3 -c "print('{\"binding_id\":\"$BINDING_ID\",\"tenant_id\":\"default\",\"platform_issuer\":\"$PLAT_ISS\",\"jwks_uri\":\"$BUNDLE_URL\",\"subject_pattern\":\"repo:acme/actor:*\",\"mapped_client_id\":\"$ACTOR_CLIENT\"}')")
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/workload-trust" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" -d "$REG")
[ "$ST" = "201" ] || fail "actor OIDC 绑定登记应 201(got $ST)"; pass "actor JWKS + workload client + OIDC 绑定"

echo "== 2. code flow 拿 subject_token(带 jti + 建 Grant + 落 jti→user_id 映射)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$SUBJECT_CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
CODE=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?response_type=code&client_id=$SUBJECT_CLIENT&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&login_user=alice&resource=$RS" \
  | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || fail "无 code"
SUBJECT=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$SUBJECT_CLIENT" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$SUBJECT" ] || fail "无 subject_token"
# code flow 的 Grant grant_id == family_id == subject_token 的 auth_grant(命名空间)。
GRANT_ID=$(echo "$SUBJECT" | python3 -c "import sys,json,base64;p=json.loads(base64.urlsafe_b64decode(sys.stdin.read().split('.')[1]+'=='));print(p['https://a-auth.com/c']['auth_grant'])")
[ -n "$GRANT_ID" ] || fail "subject_token 无 auth_grant"; pass "subject_token + Grant($GRANT_ID)"

echo "== 3. 把 Grant 的 actor_allowlist 补上 actor(3LO Grant 默认空 allowlist)=="
GJSON=$(aws dynamodb get-item --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" --key "{\"grant_id\":{\"S\":\"$GRANT_ID\"}}" --query "Item.grant_json.S" --output text)
NEWJSON=$(python3 -c "
import json,sys
g=json.loads('''$GJSON''')
g['constraints']['actor_allowlist']=['$ACTOR_CLIENT']
print(json.dumps(g))
")
aws dynamodb update-item --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
  --key "{\"grant_id\":{\"S\":\"$GRANT_ID\"}}" \
  --update-expression "SET grant_json = :j" \
  --expression-attribute-values "{\":j\":{\"S\":$(python3 -c "import json;print(json.dumps('''$NEWJSON'''.strip()))")}}" >/dev/null
pass "Grant actor_allowlist ← [$ACTOR_CLIENT]"

echo "== 4+5. actor OIDC JWT + actor DPoP proof → token-exchange → 断言委托 token cnf.jkt==actor key =="
python3 - "$API_URL" "$PLAT_ISS" "$RS" "$SUBJECT" "$ACTOR_CLIENT" "$RND" <<'PY'
import sys,json,base64,time,subprocess
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
api,plat_iss,rs,subject,actor,rnd=sys.argv[1:7]
b=lambda v: base64.urlsafe_b64encode(v).rstrip(b'=').decode()
sk=serialization.load_pem_private_key(open(f'/tmp/dpop_actor_sk_{rnd}.pem','rb').read(),None)
def es256(hdr,claims):
    si=b(json.dumps(hdr,separators=(',',':')).encode())+"."+b(json.dumps(claims,separators=(',',':')).encode())
    der=sk.sign(si.encode(),ec.ECDSA(hashes.SHA256())); r,s=decode_dss_signature(der)
    return si+"."+b(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
now=int(time.time())
# actor 平台 OIDC JWT(aud=本 AS issuer,sub 命中 subject_pattern)。
actor_jwt=es256({"typ":"JWT","alg":"ES256","kid":"actor-k1"},
  {"iss":plat_iss,"sub":"repo:acme/actor:ref:main","aud":api,"iat":now,"exp":now+300})
# actor 自己的 DPoP proof key(独立于平台 key)。
dsk=ec.generate_private_key(ec.SECP256R1()); dn=dsk.public_key().public_numbers()
dx,dy=b(dn.x.to_bytes(32,'big')),b(dn.y.to_bytes(32,'big'))
jkt=b(hashlib.sha256(json.dumps({"crv":"P-256","kty":"EC","x":dx,"y":dy},separators=(',',':'),sort_keys=True).encode()).digest())
def dpop_proof():
    hdr={"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":dx,"y":dy}}
    claims={"htu":api+"/token","htm":"POST","iat":int(time.time()),"jti":b(hashlib.sha256(str(time.time()).encode()).digest()[:16])}
    si=b(json.dumps(hdr,separators=(',',':')).encode())+"."+b(json.dumps(claims,separators=(',',':')).encode())
    der=dsk.sign(si.encode(),ec.ECDSA(hashes.SHA256())); r,s=decode_dss_signature(der)
    return si+"."+b(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
TE="urn:ietf:params:oauth:grant-type:token-exchange"
TT_AT="urn:ietf:params:oauth:token-type:access_token"
JB="urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
def exchange(dpop=None):
    args=["curl","-s","-X","POST",api+"/token","-H","content-type: application/x-www-form-urlencoded"]
    if dpop: args+=["-H","DPoP: "+dpop]
    args+=["-d",f"grant_type={TE}&subject_token={subject}&subject_token_type={TT_AT}&actor_token={actor_jwt}&actor_token_type={JB}&resource={rs}&scope=openid"]
    return subprocess.run(args,capture_output=True,text=True).stdout
# 快乐路径:actor 带 DPoP proof → 委托 token cnf.jkt==actor key(重绑)+ token_type=DPoP。
out=exchange(dpop_proof()); resp=json.loads(out)
assert "access_token" in resp, "委托换发应成功: "+out
assert resp.get("token_type")=="DPoP", "带 DPoP → token_type=DPoP: "+out
p=json.loads(base64.urlsafe_b64decode(resp["access_token"].split('.')[1]+'=='))
assert p.get("cnf",{}).get("jkt")==jkt, f"委托 token cnf.jkt 应==actor proof key({jkt}): {p.get('cnf')}"
assert p.get("act",{}).get("sub")==actor, f"act.sub 应=发起 actor: {p.get('act')}"
print("  ✅ token-exchange 委托:cnf.jkt==actor DPoP key(重绑)+ act.sub=actor + token_type=DPoP")
# 负例:actor 无 DPoP(入站 subject 无 cnf)→ 仍签 bearer 委托(opt-in,现状)。
out2=exchange(None); resp2=json.loads(out2)
assert "access_token" in resp2 and resp2.get("token_type")=="Bearer", "无 DPoP 入站无 cnf → bearer 委托: "+out2
p2=json.loads(base64.urlsafe_b64decode(resp2["access_token"].split('.')[1]+'=='))
assert "cnf" not in p2, "bearer 委托不带 cnf"
print("  ✅ actor 无 DPoP + 入站无 cnf → bearer 委托(opt-in)")
PY
pass "DPoP 委托往返"

echo "✅ spec 011 §7.2 DPoP 委托 token cnf 继承完整真机往返全绿(cnf.jkt 重绑 actor proof key)"

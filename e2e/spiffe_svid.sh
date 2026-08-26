#!/usr/bin/env bash
# spec 012 §1.4(C5.7)真机 e2e:**SPIFFE JWT-SVID 完整 2LO 往返**。
#
# 无真 SPIRE server——把 trust domain 的 trust bundle JWKS **托管到 SPA 桶 /assets/**(CloudFront 可 fetch),
# 令 AS 的 HttpJwksFetcher 按登记的 jwks_uri 拉到公钥本地验签(类比 federation 用真 Cognito JWKS)。
#
# 全链:①造 EC P-256 key(=trust domain 签名 key)+ 发布公钥 JWKS 到 /assets → ②admin 建 workload client
#   (allowed_resources/scopes)+ 登记 SpiffeJwt 绑定(jwks_uri 指向它)→ ③签 JWT-SVID(sub=SPIFFE ID/
#   aud=issuer/kid 匹配 bundle)作 client_assertion → ④POST /token client_credentials → 断言签出 2LO token。
#   负例:aud 非本 AS 拒 / 跨 trust domain 拒 / pattern 不符拒。
#
# ⚠️ 隔离铁律(踩坑收敛):**每次跑用唯一 trust_domain + binding_id + bundle 名**——match_spiffe 按
#   (trust_domain,pattern) 返回**首个匹配** binding,残留同 domain 的旧 binding(尤其指向已删 client)会
#   非确定性命中致 invalid_target;且 AS JWKS fetcher 5min 负缓存,故**发布 bundle → 强传播等待 → 才登记/换发**
#   (AS 对该 url 的首次 fetch 须在对象全球可取之后,否则负缓存毒化 5min)。trap 清理 binding/client/bundle。
#
# 用法:API_URL=https://<cf-domain> CLIENTS_TABLE=<clients 表> SPA_BUCKET=<spa 桶> \
#       TRUST_TABLE=<workload-trust 表> AWS_PROFILE=default ./e2e/spiffe_svid.sh
# 依赖:aws cli、curl、python3(+cryptography)。账号号/资源名不硬编码。
set -euo pipefail

API_URL="${API_URL:?需 API_URL(CloudFront 统一入口 / 自定义域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
SPA_BUCKET="${SPA_BUCKET:?需 SPA_BUCKET(前端 SPA S3 桶,供托管 trust bundle JWKS)}"
TRUST_TABLE="${TRUST_TABLE:?需 TRUST_TABLE(cdk 输出 WorkloadTrustTableName;供 trap 清理残留 binding)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RS="https://mcp.rs.example.com"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

ADMIN_TOKEN="${ADMIN_TOKEN:-$("$(dirname "$0")/get-admin-token.sh")}"

# 唯一后缀(隔离本次跑,避免残留 binding/bundle 冲突)。
RND=$(python3 -c "import secrets;print(secrets.token_hex(4))")
TD="e2e-${RND}.spiffe.test"        # 唯一 trust domain(隔离 match_spiffe)
WL_CLIENT="e2e-spiffe-2lo-$RND"
BINDING_ID="e2e-spiffe-b-$RND"
BUNDLE_KEY="assets/spiffe-bundle-$RND.json"
BUNDLE_URL="$API_URL/$BUNDLE_KEY"

cleanup() {
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$TRUST_TABLE" \
    --key "{\"binding_id\":{\"S\":\"$BINDING_ID\"}}" >/dev/null 2>&1 || true
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
    --key "{\"client_id\":{\"S\":\"$WL_CLIENT\"}}" >/dev/null 2>&1 || true
  aws s3 rm "s3://$SPA_BUCKET/$BUNDLE_KEY" --profile "$PROFILE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== 1. 造 trust domain 签名 key + 发布 trust bundle JWKS 到 /assets(强传播等待)=="
python3 - > /tmp/spiffe_bundle_$RND.json <<'PY'
import sys, json, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
sk = ec.generate_private_key(ec.SECP256R1())
n = sk.public_key().public_numbers()
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
x, y = b64u(n.x.to_bytes(32,'big')), b64u(n.y.to_bytes(32,'big'))
open('/tmp/spiffe_sk.pem','wb').write(sk.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
print(json.dumps({"keys":[{"kty":"EC","crv":"P-256","kid":"svid-k1","x":x,"y":y,"use":"sig","alg":"ES256"}]}))
PY
aws s3 cp "/tmp/spiffe_bundle_$RND.json" "s3://$SPA_BUCKET/$BUNDLE_KEY" --profile "$PROFILE" --content-type application/json >/dev/null
# 强传播:连续 3 次取到 svid-k1 才认为全球可取(AS 首次 fetch 前须稳定,避免 5min 负缓存毒化)。
OK=0
for i in $(seq 1 30); do
  if curl -s "$BUNDLE_URL" | grep -q '"svid-k1"'; then OK=$((OK+1)); else OK=0; fi
  [ "$OK" -ge 3 ] && break; sleep 2
done
[ "$OK" -ge 3 ] || fail "trust bundle JWKS 未稳定可取"
sleep 5  # 余量:让边缘充分一致
pass "trust bundle JWKS 发布 + 强传播:$BUNDLE_URL"

echo "== 2. admin 建 workload client + 登记 SpiffeJwt 绑定(唯一 trust_domain=$TD)=="
# ⚠️ allowed_resources/allowed_scopes 存 **List(L)** 非 String Set(SS)——AS 读用 `ss()`=`.as_l()`
#   (aws.rs:205),写成 SS 会被读空 → invalid_target(踩坑收敛;同 amr Ss-vs-L 教训)。
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$WL_CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"client_type\":{\"S\":\"workload\"},\"allowed_resources\":{\"L\":[{\"S\":\"$RS\"}]},\"allowed_scopes\":{\"L\":[{\"S\":\"kb:read\"}]}}" >/dev/null
REG=$(python3 -c "print('{\"binding_id\":\"$BINDING_ID\",\"tenant_id\":\"default\",\"mechanism\":\"spiffe_jwt\",\"trust_domain\":\"$TD\",\"jwks_uri\":\"$BUNDLE_URL\",\"subject_pattern\":\"spiffe://$TD/agent/*\",\"mapped_client_id\":\"$WL_CLIENT\"}')")
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/admin/workload-trust" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" -d "$REG")
[ "$ST" = "201" ] || fail "SpiffeJwt 绑定登记应 201(got $ST)"
pass "workload client + SpiffeJwt 绑定登记"

echo "== 3+4. 签 JWT-SVID → POST /token → 断言 2LO + 负例 =="
python3 - "$API_URL" "$TD" "$RS" "$WL_CLIENT" <<'PY'
import sys, json, base64, time, subprocess
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
api, td, rs, client = sys.argv[1:5]
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
sk = serialization.load_pem_private_key(open('/tmp/spiffe_sk.pem','rb').read(), None)
def svid(sub, aud):
    hdr = {"typ":"JWT","alg":"ES256","kid":"svid-k1"}; now=int(time.time())
    claims = {"iss":"https://spire."+td,"sub":sub,"aud":aud,"iat":now,"exp":now+300}
    si = b64u(json.dumps(hdr,separators=(',',':')).encode())+"."+b64u(json.dumps(claims,separators=(',',':')).encode())
    der = sk.sign(si.encode(), ec.ECDSA(hashes.SHA256())); r,s = decode_dss_signature(der)
    return si+"."+b64u(r.to_bytes(32,'big')+s.to_bytes(32,'big'))
JB = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
def ex(assertion, resource=rs):
    return subprocess.run(["curl","-s","-X","POST",api+"/token","-H","content-type: application/x-www-form-urlencoded",
      "-d",f"grant_type=client_credentials&client_assertion_type={JB}&client_assertion={assertion}&resource={resource}"],
      capture_output=True,text=True).stdout

resp = json.loads(ex(svid(f"spiffe://{td}/agent/kb", api)))
assert "access_token" in resp, "SPIFFE JWT-SVID 应签出 2LO: "+json.dumps(resp)
assert resp.get("refresh_token") is None, "2LO 不发 refresh"
p = json.loads(base64.urlsafe_b64decode(resp["access_token"].split('.')[1]+'=='))
assert p["sub"]==client, f"2LO sub 应=映射 client_id({client}): {p.get('sub')}"
assert p["aud"]==[rs], f"aud 应=[{rs}]: {p.get('aud')}"
assert p.get("https://a-auth.com/c",{}).get("sub_type")=="agent", "sub_type=agent"
print("  ✅ SPIFFE JWT-SVID 换 2LO:sub=映射 client_id、aud=RS、sub_type=agent、无 refresh")

assert "access_token" not in json.loads(ex(svid(f"spiffe://{td}/agent/kb","https://evil.example"))), "aud 非本 AS 应拒"
print("  ✅ aud 非本 AS → 拒")
assert "access_token" not in json.loads(ex(svid("spiffe://other.example/agent/kb", api))), "跨 trust domain 应拒"
print("  ✅ 跨 trust domain → 拒")
assert "access_token" not in json.loads(ex(svid(f"spiffe://{td}/svc/db", api))), "pattern 不符应拒"
print("  ✅ SPIFFE ID pattern 不符 → 拒")
PY

rm -f "/tmp/spiffe_sk.pem" "/tmp/spiffe_bundle_$RND.json"
echo "✅ spec 012 §1.4 SPIFFE JWT-SVID 完整 2LO 真机往返全绿(信任锚=sub 解 trust domain,aud 硬校验,pattern 匹配)"

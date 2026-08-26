#!/usr/bin/env bash
# P1b 真机 e2e:RS 校验 SDK(TS + Python)验真机 KMS 签发的 access token(拉 live JWKS)。
#
# 验证 spec 010 P1b 两个 SDK 在真实链路成立:AS(KMS ES256)签 aud=RS 的 token →
# SDK 拉 live /jwks.json 验签 + aud 强校验 + sub_type 策略(user 放行、agent 403)。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default ./e2e/rs_sdk_real_token.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RS="https://mcp.kb.example.com"
APP="sdk-e2e-app"
REDIRECT="http://127.0.0.1/cb"
V="0123456789012345678901234567890123456789abc"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== 0. seed app client(default_resource=$RS)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$APP\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"default_resource\":{\"S\":\"$RS\"}}" >/dev/null

echo "== 1. AS 签一枚 aud=$RS 的 access token(KMS ES256)=="
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$V'.encode()).digest()).rstrip(b'=').decode())")
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=$APP&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&state=s&login_user=alice")
CODE=$(echo "$LOC" | sed 's/.*code=\([^&]*\).*/\1/')
AT=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$V&redirect_uri=$REDIRECT&client_id=$APP" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
[ -n "$AT" ] || { echo "❌ 无 access_token"; exit 1; }

echo "== 2. Python SDK 验真机 token(拉 live JWKS)=="
python3 - "$AT" "$API_URL" "$RS" <<'PY'
import sys
sys.path.insert(0, __import__("os").path.join("sdk", "python"))
from agent_auth_rs import RsSdk, RsSdkConfig, RoutePolicy
at, iss, rs = sys.argv[1], sys.argv[2], sys.argv[3]
sdk = RsSdk(RsSdkConfig(resource_id=rs, issuer=iss))
r = sdk.authenticate(f"Bearer {at}", RoutePolicy(require_sub_type="user"))
assert r.ok, (r.error.kind, r.error.detail)
assert r.token.aud == rs and r.token.sub_type == "user"
r2 = sdk.authenticate(f"Bearer {at}", RoutePolicy(require_sub_type="agent"))
assert not r2.ok and r2.status == 403
print("  ✅ Python SDK:user token 放行 + require-agent 403")
PY

echo "== 3. TS SDK 验真机 token(拉 live JWKS)=="
( cd "$ROOT/sdk/ts" && npm run build >/dev/null 2>&1 )
node - "$AT" "$API_URL" "$RS" "$ROOT/sdk/ts/dist/index.js" <<'JS'
const [at, iss, rs, mod] = process.argv.slice(2);
const { RsSdk } = await import(mod);
const sdk = new RsSdk({ resourceId: rs, issuer: iss });
const r = await sdk.authenticate(`Bearer ${at}`, { requireSubType: "user" });
if (!r.ok) { console.error("FAIL", r.error); process.exit(1); }
if (r.token.aud !== rs || r.token.subType !== "user") { console.error("claim 不符"); process.exit(1); }
const r2 = await sdk.authenticate(`Bearer ${at}`, { requireSubType: "agent" });
if (!(r2.ok === false && r2.status === 403)) { console.error("require-agent 应 403"); process.exit(1); }
console.log("  ✅ TS SDK:user token 放行 + require-agent 403");
JS

echo "✅ P1b RS 校验 SDK(TS+Python)验真机 KMS token 全绿"

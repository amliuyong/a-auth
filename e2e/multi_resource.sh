#!/usr/bin/env bash
# 多 resource authorize→token 收窄真机 e2e(spec 006 6.1 / 001 4.2 / C2.5b,P0 缺口#4 关闭)。
#
# P1+ 部署:/authorize 带多个 `resource=` → 接受(303,集合写 code);/token 选其一 → aud=[所选](收窄单值)。
# 修复前:AuthorizeParams Query extractor 遇重复 resource= 报 duplicate-field → 400,多值 HTTP 层不可达。
#
# 用法:  API_URL=https://<host> CLIENTS_TABLE=<cdk ClientsTableName> AWS_PROFILE=default ./e2e/multi_resource.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CID="multi-res-e2e-app"
REDIRECT="http://127.0.0.1/cb"
RA="https://mcp.a.example.com"; RB="https://mcp.b.example.com"
V="0123456789012345678901234567890123456789abc"
pass=0; fail=0

echo "== 0. seed public client =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CID\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
echo "  client $CID 就绪 ✅"
trap 'aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$CID\"}}" >/dev/null 2>&1 || true' EXIT

CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$V'.encode()).digest()).rstrip(b'=').decode())")

echo "== 1. authorize 带 2 resource → 303 接受(P1+ 多 resource)=="
LOC=$(curl -s -o /dev/null -D - "$API_URL/authorize?response_type=code&client_id=$CID&redirect_uri=$REDIRECT&code_challenge=$CH&code_challenge_method=S256&scope=openid&login_user=alice&resource=$RA&resource=$RB" -w '' | grep -i '^location:' | sed 's/[Ll]ocation: //;s/\r//')
CODE=$(echo "$LOC" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
if [ -n "$CODE" ]; then echo "  ✅ 多 resource authorize 接受(拿到 code)"; pass=$((pass+1)); else echo "  ❌ 无 code: $LOC"; fail=$((fail+1)); fi

echo "== 2. token 选 RB → aud=[RB](收窄单值,C2.5b)=="
AUD=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$V&redirect_uri=$REDIRECT&client_id=$CID&resource=$RB" \
  | python3 -c "import sys,json,base64; d=json.load(sys.stdin); at=d.get('access_token',''); p=at.split('.')[1] if at else ''; pad=p+'='*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(pad)).get('aud') if p else 'NO_TOKEN')")
if [ "$AUD" = "['$RB']" ]; then echo "  ✅ aud=[RB](多 resource 收窄单值)"; pass=$((pass+1)); else echo "  ❌ aud=$AUD(期望 ['$RB'])"; fail=$((fail+1)); fi

echo ""
echo "==== 结果:$pass 通过, $fail 失败 ===="
[ "$fail" -eq 0 ] || exit 1

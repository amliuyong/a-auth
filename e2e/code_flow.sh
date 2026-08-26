#!/usr/bin/env bash
# P0 code flow 真机 e2e:discovery → authorize(PKCE)→ token(KMS ES256 签发)→ /jwks.json 独立验签。
#
# 验证 spec 000/001/002/005/006 纯逻辑经 HTTP handler 编排后在真实 AWS(API Gateway→Lambda→KMS+DynamoDB)
# 端到端成立。用 CDK 栈 AgentAuthDev 部署后跑。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default \
#   ./e2e/code_flow.sh
#
# 依赖:aws cli、curl、python3(+PyJWT/cryptography 用于独立验签)。账号号/资源名不硬编码——由环境传入。
set -euo pipefail

API_URL="${API_URL:?需 API_URL(cdk 输出 ApiUrl)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE(cdk 输出 ClientsTableName)}"
PROFILE="${AWS_PROFILE:-default}"
# 资源部署在 us-east-1;显式用 REGION 覆盖,不盲从外部 AWS_REGION(可能指向别的区)。
REGION="${REGION:-us-east-1}"
HOST="${API_URL#https://}"
CLIENT="e2e-client"
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"  # 43 字符,PKCE 合法

echo "== 1. seed 一个 public 客户端(直接写 clients 表;真机无 register 端点时的 e2e 便利)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"

echo "== 2. discovery 断言 issuer 正确 =="
ISS=$(curl -s "$API_URL/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin)['issuer'])")
[ "$ISS" = "$API_URL" ] || { echo "❌ issuer=$ISS != $API_URL"; exit 1; }
echo "  issuer=$ISS ✅"

echo "== 3. authorize(PKCE S256)拿 code =="
CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&state=st123&login_user=alice")
echo "  redirect: $LOC"
echo "$LOC" | grep -q "state=st123" || { echo "❌ state 未 echo"; exit 1; }
CODE=$(echo "$LOC" | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || { echo "❌ 无 code"; exit 1; }

echo "== 4. token 换 KMS ES256 签发的 JWT =="
JWT=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$JWT" ] || { echo "❌ 无 access_token"; exit 1; }

echo "== 5. code 重放应被拒(两阶段 lease finalize 后 AlreadyConsumed)=="
REPLAY=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
[ "$REPLAY" = "400" ] || { echo "❌ code 重放未被拒(got $REPLAY)"; exit 1; }
echo "  重放 → 400 ✅"

echo "== 6. 用 /jwks.json 公钥独立验签(PyJWT/ES256)=="
curl -s "$API_URL/jwks.json" > /tmp/e2e_jwks.json
echo "$JWT" | python3 -c "
import sys,json,jwt as pyjwt
from jwt import algorithms
token=sys.stdin.read().strip()
jwks=json.load(open('/tmp/e2e_jwks.json'))
key=algorithms.ECAlgorithm.from_jwk(json.dumps(jwks['keys'][0]))
claims=pyjwt.decode(token,key=key,algorithms=['ES256'],audience='$API_URL/userinfo',options={'verify_exp':False})
assert claims['iss']=='$API_URL', claims['iss']
# 篡改负例:解码签名、翻转中间一字节、重编码(比翻末字符可靠——末字符只含部分 bit)。
import base64
p=token.split('.')
sig=bytearray(base64.urlsafe_b64decode(p[2]+'='*(-len(p[2])%4)))
sig[10]^=0xFF
bad=p[0]+'.'+p[1]+'.'+base64.urlsafe_b64encode(bytes(sig)).rstrip(b'=').decode()
try:
    pyjwt.decode(bad,key=key,algorithms=['ES256'],audience='$API_URL/userinfo',options={'verify_exp':False}); print('❌ 篡改通过'); sys.exit(1)
except Exception: pass
print('  ✅ KMS 签发 JWT 独立验签通过 + 篡改被拒;sub=',claims['sub'])
"

echo "== 7. refresh_token grant(C3 rotation + 宽限窗 C3.2 + 窗外复用检测 C3.5)=="
# 重走 code flow 拿 refresh_token(前面的 code 已消费)。
CODE2=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?response_type=code&client_id=$CLIENT&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&login_user=alice" \
  | sed 's/.*code=\([^&]*\).*/\1/')
RT=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE2&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
[ -n "$RT" ] || { echo "❌ code flow 未返回 refresh_token"; exit 1; }
# rotation:换新 token。
R1=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CLIENT")
NEW_RT=$(echo "$R1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
[ -n "$NEW_RT" ] && [ "$NEW_RT" != "$RT" ] || { echo "❌ refresh rotation 未换新 refresh"; exit 1; }
NEW_A1=$(echo "$R1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
echo "  rotation 换新 refresh ✅"
# 宽限窗内(≤5s)同指纹复用旧 refresh → 命中缓存,返回**同一组** access/refresh(C3.2:不再签、不吊销)。
GRACE=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CLIENT")
GRACE_A=$(echo "$GRACE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$GRACE_A" ] || { echo "❌ 宽限窗内复用应命中缓存返 200(got: $GRACE)"; exit 1; }
[ "$GRACE_A" = "$NEW_A1" ] || { echo "❌ 宽限窗命中应重放同一 access token"; exit 1; }
echo "  宽限窗内同指纹复用 → 命中缓存重放同一组(C3.2)✅"
# 等宽限窗过期(部署窗 5s;留 7s 余量),窗外复用旧 refresh → 复用检测 → 400 全链吊销(C3.5)。
sleep 7
REUSE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$RT&client_id=$CLIENT")
[ "$REUSE" = "400" ] || { echo "❌ 窗外复用旧 refresh 未被拒(got $REUSE)"; exit 1; }
# 全链吊销:新 refresh 也失效。
REVOKED=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$NEW_RT&client_id=$CLIENT")
[ "$REVOKED" = "400" ] || { echo "❌ 复用检测后新 refresh 未失效(got $REVOKED)"; exit 1; }
echo "  窗外复用检测 → family 全链吊销(C3.5)✅"

echo "✅ P0 code flow + refresh 真机 e2e 全绿"

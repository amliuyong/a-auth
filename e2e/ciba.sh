#!/usr/bin/env bash
# P2 CIBA 真机 e2e(OpenID CIBA,spec 013 C7b.1–C7b.3 + §2b.5):
#   discovery 宣告 backchannel_authentication_endpoint → /bc-authorize(login_hint=email 三选一 + openid)
#   §2b.5 login_hint=email 存在性校验:未注册 email → invalid_request;已注册 → 铸 auth_req_id →
#   轮询 authorization_pending → **真 /bc-approve 批准**(被代表用户登录会话,MED-1 归属校验真机路径)→
#   轮询签出 3LO access token(sub=user:{email}、含 jti,不经 /sessions)→ 重放 invalid_grant(一次性)。
#
# ⚠️ login_hint 契约(用户拍板 2026-07-12):login_hint = 用户面 email → users 表 GSI email-index 解析
# 为内部 user_id(user:{email});未注册直接拒 invalid_request(不静默照发、不造僵尸记录)。被代表用户
# 用户须由 Admin 预置并完成首次改密,之后再用 magic-link 建批准会话。
#
# 用法(须走 CloudFront 统一入口域,/bc-approve+/login 需 host 匹配):
#   API_URL=https://<cf-host> CLIENTS_TABLE=<cdk ClientsTableName> AWS_PROFILE=default ./e2e/ciba.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-ciba-client"
CIBA_GRANT="urn:openid:params:grant-type:ciba"
# 被代表用户 email(magic-link 登录后进 users 表 = 已注册);随机化避冷却/复用。
RAND="$(python3 -c 'import random;print(random.randint(1,1_000_000))')"
ALICE="ciba-alice-${RAND}@example.com"
JAR="$(mktemp)"

echo "== 1. seed public 客户端(CIBA 仅限 public)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"

echo "== 2. discovery 断言 backchannel_authentication_endpoint 已宣告(P2)=="
BAE=$(curl -s "$API_URL/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin).get('backchannel_authentication_endpoint',''))")
[ "$BAE" = "$API_URL/bc-authorize" ] || { echo "❌ backchannel_authentication_endpoint=$BAE"; exit 1; }
echo "  $BAE ✅"

echo "== 3. 缺 openid scope → invalid_scope(CIBA 是 OIDC 流)=="
NO_OIDC=$(curl -s -X POST "$API_URL/bc-authorize" -H "content-type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT&scope=kb:read&login_hint=$ALICE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$NO_OIDC" = "invalid_scope" ] || { echo "❌ 缺 openid 应 invalid_scope(got: $NO_OIDC)"; exit 1; }
echo "  invalid_scope ✅"

echo "== 4. 缺用户标识 → invalid_request(三选一)=="
NO_HINT=$(curl -s -X POST "$API_URL/bc-authorize" -H "content-type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT&scope=openid" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$NO_HINT" = "invalid_request" ] || { echo "❌ 缺用户标识应 invalid_request(got: $NO_HINT)"; exit 1; }
echo "  invalid_request ✅"

echo "== 5. §2b.5 未注册 login_hint(email)→ invalid_request(存在性校验)=="
UNREG=$(curl -s -X POST "$API_URL/bc-authorize" -H "content-type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT&scope=openid&login_hint=$ALICE" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$UNREG" = "invalid_request" ] || { echo "❌ 未注册 email 应 invalid_request(got: $UNREG)"; exit 1; }
echo "  未注册拒 invalid_request ✅"

agent_auth_provision_local_user "$API_URL" "$ALICE"
echo "== 6. 被代表用户 magic-link 登录(已由 Admin 预置 + 拿会话 cookie)=="
RESP=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$ALICE\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || { echo "❌ 无 dev_link(dev 占位未开?): $RESP"; exit 1; }
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')
CB=$(curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' "$API_URL$PQ")
[ "$CB" = "303" ] || { echo "❌ callback 未 303(got $CB)"; exit 1; }
echo "  alice 登录建会话 ✅"

echo "== 7. POST /bc-authorize(已注册 login_hint=email)铸 auth_req_id =="
BA=$(curl -s -X POST "$API_URL/bc-authorize" -H "content-type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT&scope=openid kb:read&login_hint=$ALICE")
AUTH_REQ_ID=$(echo "$BA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('auth_req_id',''))")
INTERVAL=$(echo "$BA" | python3 -c "import sys,json;print(json.load(sys.stdin).get('interval',''))")
[ -n "$AUTH_REQ_ID" ] || { echo "❌ 无 auth_req_id: $BA"; exit 1; }
echo "  auth_req_id=${AUTH_REQ_ID:0:8}… interval=$INTERVAL ✅"

echo "== 8. 未批准轮询 → authorization_pending =="
P1=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=$CIBA_GRANT&auth_req_id=$AUTH_REQ_ID&client_id=$CLIENT")
ERR=$(echo "$P1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$ERR" = "authorization_pending" ] || { echo "❌ 未批准应 authorization_pending(got: $P1)"; exit 1; }
echo "  authorization_pending ✅"

echo "== 9. **真 /bc-approve 批准**(被代表用户 alice 登录会话;MED-1 归属校验真机路径)=="
# login_hint=email 解析后 record.user_id=user:{email} 与 alice 登录会话 user_id 对齐 → 批准成功。
AP=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$API_URL/bc-approve/$AUTH_REQ_ID" \
  -H "content-type: application/x-www-form-urlencoded" -d "approve=true")
[ "$AP" = "204" ] || { echo "❌ 被代表用户批准应 204(got $AP)"; exit 1; }
echo "  /bc-approve 204 ✅(真批准 handler,非直写 DynamoDB)"

echo "== 10. 轮询签出 3LO access token(sub=user:{email}、含 jti)=="
sleep $((INTERVAL + 1))
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=$CIBA_GRANT&auth_req_id=$AUTH_REQ_ID&client_id=$CLIENT")
JWT=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$JWT" ] || { echo "❌ 批准后未签出 token(got: $TOK)"; exit 1; }
echo "$JWT" | ALICE="$ALICE" python3 -c "
import sys,base64,json,os
p=sys.stdin.read().strip().split('.')
c=json.loads(base64.urlsafe_b64decode(p[1]+'='*(-len(p[1])%4)))
want='user:'+os.environ['ALICE'].lower()
assert c['sub']==want, 'sub=%s want=%s' % (c['sub'], want)
assert c.get('jti'), 'no jti'
assert c.get('https://a-auth.com/c',{}).get('sub_type')=='user'
print('  sub=%s sub_type=user jti✓ ✅' % c['sub'])
"

echo "== 11. 一次性:重放 auth_req_id → invalid_grant =="
sleep $((INTERVAL + 1))
REPLAY=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=$CIBA_GRANT&auth_req_id=$AUTH_REQ_ID&client_id=$CLIENT")
RERR=$(echo "$REPLAY" | python3 -c "import sys,json;print(json.load(sys.stdin).get('error',''))")
[ "$RERR" = "invalid_grant" ] || { echo "❌ 已消费 auth_req_id 重放应 invalid_grant(got: $REPLAY)"; exit 1; }
echo "  重放 → invalid_grant ✅"

rm -f "$JAR"
echo "✅ P2 CIBA 真机 e2e 全绿(login_hint=email 存在性校验 + 真 /bc-approve 批准 + 一次性)"

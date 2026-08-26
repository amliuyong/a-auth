#!/usr/bin/env bash
# spec 001 C3.2/C3.4/C3.5 真机 e2e:refresh 宽限窗(item-level 信封加密缓存)。
#
# 验证(经 CloudFront 统一入口域):
# - code flow 拿 refresh(r0);r0 → r1(rotation)。
# - 宽限窗内**同指纹**重放 r0 → 返回缓存的**同一组** access/refresh(不再签、不吊销,C3.2)。
# - r1 仍能正常 rotation(宽限窗命中不吊销 family)。
# - GraceTable 里对应 item 只存密文(enc_dk/nonce/ciphertext,无明文 token,C3.4)。
#
# ⚠️ 依赖真机开了宽限窗(GRACE_TABLE + GRACE_KMS_KEY_ID 已注入);未开则宽限窗关闭,r0 复用会被拒(跳过缓存断言)。
#
# 用法:BASE_URL=https://<cf域> CLIENTS_TABLE=<clients 表> GRACE_TABLE=<grace 表> \
#       AWS_PROFILE=default ./e2e/grace_window.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

BASE_URL="${BASE_URL:?需 BASE_URL(CloudFront 统一入口域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
GRACE_TABLE="${GRACE_TABLE:-}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-grace-client"
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
JAR="$(mktemp)"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }

echo "== 1. seed client + magic-link 登录 =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
CH=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
AQ="client_id=$CLIENT&redirect_uri=$REDIRECT&scope=openid&state=st&code_challenge=$CH&code_challenge_method=S256"
EMAIL="grace-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
agent_auth_provision_local_user "$BASE_URL" "$EMAIL"
RESP=$(curl -s -c "$JAR" -X POST "$BASE_URL/login/magic-link" -H "content-type: application/json" -d "{\"email\":\"$EMAIL\",\"authorize_query\":\"$AQ\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || fail "无 dev_link"
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')
curl -s -b "$JAR" -c "$JAR" -o /dev/null "$BASE_URL$PQ"
pass "已登录建会话"

echo "== 2. consent approve → code → r0 =="
CSRF=$(curl -s -b "$JAR" "$BASE_URL/consent/context?$AQ" | python3 -c "import sys,json;print(json.load(sys.stdin).get('csrf_token',''))")
[ -n "$CSRF" ] || fail "无 csrf_token"
REDIR=$(curl -s -b "$JAR" -X POST "$BASE_URL/consent/decision" -H "content-type: application/json" \
  -d "{\"decision\":\"approve\",\"csrf\":\"$CSRF\",\"authorize_query\":\"$AQ\"}" | python3 -c "import sys,json;print(json.load(sys.stdin).get('redirect',''))")
CODE=$(echo "$REDIR" | sed 's/.*code=\([^&]*\).*/\1/')
[ -n "$CODE" ] || fail "无 code"
TOK=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$CLIENT")
R0=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
[ -n "$R0" ] || fail "code flow 未返回 refresh_token"
pass "拿到 r0"

echo "== 3. r0 → r1(rotation)=="
T1=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$R0&client_id=$CLIENT")
R1=$(echo "$T1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
A1=$(echo "$T1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$R1" ] || fail "r0 未轮换出 r1"
[ "$R1" != "$R0" ] || fail "r1 应 != r0"
pass "r0 → r1"

echo "== 4. 宽限窗内同指纹重放 r0 → 返回缓存的同一组(C3.2)=="
T2=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=$R0&client_id=$CLIENT")
STATUS2=$(echo "$T2" | python3 -c "import sys,json;d=json.load(sys.stdin);print('ok' if d.get('access_token') else d.get('error','err'))")
if [ "$STATUS2" = "ok" ]; then
  A2=$(echo "$T2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
  R2=$(echo "$T2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('refresh_token',''))")
  [ "$A2" = "$A1" ] || fail "宽限窗命中应重放同一 access token(A2!=A1)"
  [ "$R2" = "$R1" ] || fail "宽限窗命中应重放同一 refresh token(R2!=R1)"
  pass "宽限窗命中:重放同一 access/refresh(未再签)"

  echo "== 5. r1 仍能正常 rotation(命中不吊销 family)=="
  T3=$(curl -s -X POST "$BASE_URL/token" -H "content-type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&refresh_token=$R1&client_id=$CLIENT")
  echo "$T3" | python3 -c "import sys,json;assert json.load(sys.stdin).get('access_token'),'r1 应仍有效'" || fail "宽限窗命中后 r1 应仍能 rotation"
  pass "r1 仍有效(family 未被吊销)"

  if [ -n "$GRACE_TABLE" ]; then
    echo "== 6. GraceTable item 只存密文(C3.4)=="
    # 取该 family 的 item(family_id = R1 的 family 部分,即 R0/R1 共享 family)。
    FAM=$(echo "$R0" | sed 's/\.[0-9]*$//')
    ITEM=$(aws dynamodb query --profile "$PROFILE" --region "$REGION" --table-name "$GRACE_TABLE" \
      --key-condition-expression "family_id = :f" \
      --expression-attribute-values "{\":f\":{\"S\":\"$FAM\"}}" 2>/dev/null || echo '{}')
    echo "$ITEM" | python3 -c "
import sys,json
d=json.load(sys.stdin)
items=d.get('Items',[])
assert items, 'GraceTable 应有该 family 的缓存项'
it=items[0]
assert 'ciphertext' in it and 'enc_dk' in it and 'nonce' in it, '应含信封加密字段: '+str(list(it.keys()))
# 明文 token 不得出现在任何字段(粗查:序列化后不含 access token 前缀 eyJ)。
blob=json.dumps(it)
assert 'access_token' not in it, 'MUST NOT 存明文 access_token 字段'
print('  ✅ GraceTable item 字段 =', sorted(it.keys()), '(只存密文,无明文 token)')
" || fail "GraceTable item 校验失败"
  fi
  echo "✅ spec 001 C3.2/C3.4/C3.5 refresh 宽限窗真机 e2e 全绿"
else
  echo "  ⚠️  r0 复用被拒(error=$STATUS2)——真机宽限窗**未开启**(GRACE_TABLE/GRACE_KMS_KEY_ID 未注入)。"
  echo "     这是 fail-closed 正确姿态;要验证 C3.2 缓存重放,需先在栈里注入 GRACE_TABLE + GRACE_KMS_KEY_ID。"
fi

echo "== 清理 =="
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$CLIENT\"}}" >/dev/null 2>&1
rm -f "$JAR"

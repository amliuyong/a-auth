#!/usr/bin/env bash
# spec 006 §7.3(RFC 9126)真机 e2e:PAR /par 打真实 DynamoDB ParTable + 部署 Lambda。
# PAR 仅 P3 可达;dev 栈默认 P2 → 临时把 AuthFn AGENT_AUTH_PHASE=p3(EXIT trap 恢复 p2,不长期改栈)。
#
# 全链:POST /par(存参数)→ request_uri → GET /authorize?request_uri → 签 code(与直连等价);
# + 篡改其余 query 被忽略(redirect_uri=evil 仍回存储值)+ 一次性重放拒 + 恢复 p2 后 /par 404。
#
# 用法:
#   API_URL=https://<cloudfront> FN_NAME=<AuthFn 名> CLIENTS_TABLE=<..> \
#   AWS_PROFILE=default ./e2e/par.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL(CloudFront 域)}"
FN_NAME="${FN_NAME:?需 FN_NAME(AuthFn Lambda 名)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

RAND="$(python3 -c 'import secrets;print(secrets.token_hex(4))')"
CID="par-e2e-$RAND"
REDIR="https://par-e2e.example.com/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
CHAL="$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")"
umask 077
ENV_BAK="$(mktemp)"

cleanup() {
  set +e
  # 恢复 AuthFn env(关回 p2,不长期把栈留在 p3)。
  if [ -s "$ENV_BAK" ]; then
    echo "== [trap] 恢复 AuthFn AGENT_AUTH_PHASE=p2 =="
    "${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME" 2>/dev/null
    for attempt in 1 2 3; do
      if "${AWSQ[@]}" lambda update-function-configuration --function-name "$FN_NAME" \
           --environment "file://$ENV_BAK" >/dev/null; then
        "${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME" 2>/dev/null
        PH=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$FN_NAME" \
          --query 'Environment.Variables.AGENT_AUTH_PHASE' --output text 2>/dev/null)
        [ "$PH" = "p2" ] && { echo "  ✅ 已恢复 phase=p2"; break; }
        echo "  ⚠️ 第 $attempt 次:phase=$PH 未恢复,重试…"
      else echo "  ⚠️ 第 $attempt 次:恢复失败,重试…"; fi
      sleep 3
    done
  fi
  "${AWSQ[@]}" dynamodb delete-item --table-name "$CLIENTS_TABLE" \
    --key "{\"client_id\":{\"S\":\"$CID\"}}" >/dev/null 2>&1
  rm -f "$ENV_BAK"
}
trap cleanup EXIT INT TERM

echo "== 0. seed public client + 临时把 AuthFn 切 phase=p3(PAR 仅 P3 可达)=="
"${AWSQ[@]}" dynamodb put-item --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CID\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIR\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
ENV_NEW="$(mktemp)"
"${AWSQ[@]}" lambda get-function-configuration --function-name "$FN_NAME" \
  --query 'Environment' --output json > "$ENV_BAK"
jq '.Variables += {"AGENT_AUTH_PHASE":"p3"}' "$ENV_BAK" > "$ENV_NEW"
"${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME"
"${AWSQ[@]}" lambda update-function-configuration --function-name "$FN_NAME" \
  --environment "file://$ENV_NEW" >/dev/null
"${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME"
rm -f "$ENV_NEW"
# 轮询到 discovery 宣告 PAR 端点(phase 生效)。
for i in $(seq 1 20); do
  HASPAR=$(curl -s "$API_URL/.well-known/openid-configuration" | python3 -c "import sys,json;print('pushed_authorization_request_endpoint' in json.load(sys.stdin))" 2>/dev/null)
  [ "$HASPAR" = "True" ] && break
  sleep 2
done
echo "  ✅ phase=p3 生效(discovery 宣告 PAR 端点=$HASPAR)"

echo "== 1. POST /par → 201 + request_uri =="
PAR_RESP=$(curl -s -w '\n%{http_code}' -X POST "$API_URL/par" \
  -H "content-type: application/x-www-form-urlencoded" \
  -d "response_type=code&client_id=$CID&redirect_uri=$REDIR&code_challenge=$CHAL&code_challenge_method=S256&scope=openid&state=xyz&login_user=alice")
PAR_CODE=$(echo "$PAR_RESP" | tail -1)
PAR_BODY=$(echo "$PAR_RESP" | sed '$d')
[ "$PAR_CODE" = "201" ] || { echo "❌ /par 未 201(got $PAR_CODE): $PAR_BODY"; exit 1; }
REQUEST_URI=$(echo "$PAR_BODY" | python3 -c "import sys,json;print(json.load(sys.stdin)['request_uri'])")
echo "$REQUEST_URI" | grep -q "^urn:ietf:params:oauth:request_uri:" || { echo "❌ request_uri 非 RFC 9126 URN: $REQUEST_URI"; exit 1; }
echo "  ✅ /par 201;request_uri=$REQUEST_URI"

# request_uri 需 percent-encode 进 authorize query。
ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$REQUEST_URI")

echo "== 2. GET /authorize?request_uri → 303 签 code(与直连等价)=="
LOC=$(curl -s -o /dev/null -D - "$API_URL/authorize?request_uri=$ENC" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
echo "$LOC" | grep -q "^$REDIR" || { echo "❌ authorize?request_uri 未回跳存储 redirect(loc=$LOC)"; exit 1; }
echo "$LOC" | grep -q "code=" || { echo "❌ 回跳无 code(loc=$LOC)"; exit 1; }
echo "$LOC" | grep -q "state=xyz" || { echo "❌ state 未 echo(loc=$LOC)"; exit 1; }
echo "  ✅ authorize?request_uri 303 回跳 + code + state=xyz(用存储参数)"

echo "== 3. 一次性:同 request_uri 二次 → 400(consume 一次性)=="
C2=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/authorize?request_uri=$ENC&_cb=$RAND")
[ "$C2" = "400" ] || { echo "❌ 二次 request_uri 未 400(got $C2)"; exit 1; }
echo "  ✅ 二次 request_uri 被拒(400,一次性)"

echo "== 4. 防篡改:新 request_uri + authorize 附加 redirect_uri=evil → 忽略,仍回存储值 =="
PAR2=$(curl -s -X POST "$API_URL/par" -H "content-type: application/x-www-form-urlencoded" \
  -d "response_type=code&client_id=$CID&redirect_uri=$REDIR&code_challenge=$CHAL&code_challenge_method=S256&scope=openid&login_user=alice" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['request_uri'])")
ENC2=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$PAR2")
LOC2=$(curl -s -o /dev/null -D - "$API_URL/authorize?request_uri=$ENC2&redirect_uri=https%3A%2F%2Fevil.com%2Fcb&scope=evil" | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
echo "$LOC2" | grep -q "^$REDIR" || { echo "❌ 篡改 redirect_uri 未被忽略(loc=$LOC2)"; exit 1; }
echo "$LOC2" | grep -q "evil.com" && { echo "❌ 回跳到了篡改的 evil.com(loc=$LOC2)"; exit 1; }
echo "  ✅ 附加 redirect_uri=evil 被忽略,仍回存储的 $REDIR(RFC 9126 §4)"

echo "== 5. 恢复 p2 后 /par → 404(阶段门控)=="
# 触发 trap 前先手动恢复验证 404(trap 会再恢复一次,幂等)。
"${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME"
"${AWSQ[@]}" lambda update-function-configuration --function-name "$FN_NAME" --environment "file://$ENV_BAK" >/dev/null
"${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME"
sleep 3
P404=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/par" \
  -H "content-type: application/x-www-form-urlencoded" \
  -d "response_type=code&client_id=$CID&redirect_uri=$REDIR&code_challenge=$CHAL&code_challenge_method=S256&scope=openid")
[ "$P404" = "404" ] || { echo "❌ p2 下 /par 未 404(got $P404)"; exit 1; }
> "$ENV_BAK"  # 已恢复,trap 见空跳过
echo "  ✅ 恢复 p2 后 /par=404(阶段门控 C1.2)"

echo "✅ spec 006 §7.3 PAR 真机 e2e 全绿(P3 /par 201→authorize?request_uri 签 code / 一次性 / 篡改忽略 / p2 门控 404)"
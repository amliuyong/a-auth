#!/usr/bin/env bash
# 真机 e2e:redirect `prefix` 模式 + C4.6 confidential-only 门控(spec 002 §5.2)。
#
# 验证 authorize handler 在真实 AWS(API GW→Lambda→DynamoDB)上按 client 的 redirect_mode 分流:
#   - confidential + redirect_mode=prefix:入站前缀下**单层** callback → 303 回跳签 code(放行);
#   - public       + redirect_mode=prefix:授权请求 → 400(C4.6:prefix 仅授 confidential;
#     共享 host 上攻击者可自建同前缀 callback,confidential secret 是补充防线);
#   - confidential + prefix:通配**越段**(多层)callback → 400(通配只匹配单层,不越段)。
#
# 用法(走 CloudFront 统一入口域,与其它 e2e 一致;issuer host 经 X-Forwarded-Host 透传):
#   API_URL=https://<cloudfront 域> \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default \
#   ./e2e/redirect_prefix_gate.sh
#
# 依赖:aws cli、curl、python3。账号号/资源名不硬编码——由环境传入。
set -euo pipefail

API_URL="${API_URL:?需 API_URL(cdk 输出 ApiUrl)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE(cdk 输出 ClientsTableName)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
VERIFIER="0123456789012345678901234567890123456789abc"  # 43 字符,PKCE 合法
CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")

CONF_CLIENT="e2e-prefix-conf"
PUB_CLIENT="e2e-prefix-pub"
# 注册的 prefix redirect:host 精确 + https + path 前缀以 `/*` 结尾(单层通配)。
PREFIX_REG="https://prefix.example.com/identities/oauth2/callback/*"
# 入站单层 callback(prefix 下补一层段)——应放行。
CB_OK="https://prefix.example.com/identities/oauth2/callback/abc123"
# 入站越段 callback(多补一层)——应拒(通配只匹配单层)。
CB_MULTI="https://prefix.example.com/identities/oauth2/callback/a/b"

pct() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

echo "== 1. seed confidential(client_secret_basic)+ prefix client =="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CONF_CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$PREFIX_REG\"}]},\"token_endpoint_auth_method\":{\"S\":\"client_secret_basic\"},\"client_secret\":{\"S\":\"conf-secret-xyz\"},\"redirect_mode\":{\"S\":\"prefix\"}}" >/dev/null

echo "== 2. seed public(none)+ prefix client(应被门控拒)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$PUB_CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$PREFIX_REG\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"redirect_mode\":{\"S\":\"prefix\"}}" >/dev/null

base="response_type=code&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&state=st&login_user=alice"

echo "== 3. confidential + prefix,单层 callback → 期望 303 回跳带 code =="
CODE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/authorize?$base&client_id=$CONF_CLIENT&redirect_uri=$(pct "$CB_OK")")
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?$base&client_id=$CONF_CLIENT&redirect_uri=$(pct "$CB_OK")")
echo "  http=$CODE_HTTP loc=$LOC"
[ "$CODE_HTTP" = "303" ] || { echo "❌ confidential+prefix 单层未放行(got $CODE_HTTP,期望 303)"; exit 1; }
echo "$LOC" | grep -q "^$CB_OK?" || { echo "❌ 回跳未落在注册前缀下的入站 URI"; exit 1; }
echo "$LOC" | grep -q "code=" || { echo "❌ 回跳未带 code"; exit 1; }
echo "  confidential+prefix 单层 → 303 + code ✅"

echo "== 4. public + prefix → 期望 400(C4.6 门控:prefix 仅授 confidential)=="
PUB_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/authorize?$base&client_id=$PUB_CLIENT&redirect_uri=$(pct "$CB_OK")")
[ "$PUB_HTTP" = "400" ] || { echo "❌ public+prefix 未被拒(got $PUB_HTTP,期望 400)"; exit 1; }
echo "  public+prefix → 400 ✅(C4.6)"

echo "== 5. confidential + prefix,越段(多层)callback → 期望 400(通配不越段)=="
MULTI_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
  "$API_URL/authorize?$base&client_id=$CONF_CLIENT&redirect_uri=$(pct "$CB_MULTI")")
[ "$MULTI_HTTP" = "400" ] || { echo "❌ prefix 越段未被拒(got $MULTI_HTTP,期望 400)"; exit 1; }
echo "  confidential+prefix 越段 → 400 ✅"

echo "== 6. 清理 seed client =="
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --key "{\"client_id\":{\"S\":\"$CONF_CLIENT\"}}" >/dev/null
aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --key "{\"client_id\":{\"S\":\"$PUB_CLIENT\"}}" >/dev/null

echo ""
echo "✅ redirect prefix 门控真机 e2e 全绿(confidential 单层放行 / public 拒 / 越段拒 — C4.4b + C4.6)"

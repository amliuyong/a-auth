#!/usr/bin/env bash
# P1a 真机 e2e:MCP 集成 AS 侧(spec 010)—— PRM 生成 + /introspect(aud 隔离 + 回带命名空间)。
#
# 验证 spec 010 P1a 在真实 AWS(API Gateway→Lambda→KMS+DynamoDB)端到端成立:
# - GET /rs/{resource_id}/prm 为已注册 RS 生成 PRM(resource/authorization_servers 匹配);未注册→404。
# - POST /introspect:授权 RS 查自己 aud 的 token→active+回带命名空间;RS-B 查 RS-A token→active:false;
#   未认证/无 introspect 权限→401。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   CLIENTS_TABLE=<clients 表名> AWS_PROFILE=default ./e2e/mcp_introspect.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
RS_A="https://mcp.kb.example.com"
RS_B="https://mcp.mail.example.com"
APP="e2e-mcp-app"            # 绑 default_resource=RS_A,用来签 aud=RS_A 的 token
REDIRECT="http://127.0.0.1/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
SEC_A="e2e-introspect-secret-a"
SEC_B="e2e-introspect-secret-b"

ddb_put() { aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --item "$1"; }

echo "== 0. seed:token-minting client(default_resource=RS_A)+ RS-A/RS-B introspect 凭证 =="
ddb_put "{\"client_id\":{\"S\":\"$APP\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"default_resource\":{\"S\":\"$RS_A\"}}"
ddb_put "{\"client_id\":{\"S\":\"rs-a-introspect\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"client_secret_basic\"},\"client_secret\":{\"S\":\"$SEC_A\"},\"introspect_enabled\":{\"BOOL\":true},\"resource_ids\":{\"L\":[{\"S\":\"$RS_A\"}]}}"
ddb_put "{\"client_id\":{\"S\":\"rs-b-introspect\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"client_secret_basic\"},\"client_secret\":{\"S\":\"$SEC_B\"},\"introspect_enabled\":{\"BOOL\":true},\"resource_ids\":{\"L\":[{\"S\":\"$RS_B\"}]}}"

echo "== 1. PRM 生成:认证的 RS-A 取回自己的 PRM → 200 + 字段匹配(resource 走 query)=="
RS_A_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$RS_A',safe=''))")
PRM=$(curl -s -u "rs-a-introspect:$SEC_A" "$API_URL/rs/prm?resource=$RS_A_ENC&client_id=rs-a-introspect")
echo "$PRM" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['resource']=='$RS_A', d
assert d['authorization_servers']==['$API_URL'], d
assert 'bearer_methods_supported' in d, d
print('  ✅ PRM resource/authorization_servers 匹配')
"

echo "== 2. PRM 未认证 → 401;RS-A 请求非自己的 RS_B → 401(防枚举)=="
ST=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/rs/prm?resource=$RS_A_ENC")
[ "$ST" = "401" ] || { echo "❌ 未认证取 PRM 应 401(got $ST)"; exit 1; }
RS_B_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$RS_B',safe=''))")
ST=$(curl -s -o /dev/null -w '%{http_code}' -u "rs-a-introspect:$SEC_A" "$API_URL/rs/prm?resource=$RS_B_ENC&client_id=rs-a-introspect")
[ "$ST" = "401" ] || { echo "❌ 非本 caller 资源应 401(got $ST)"; exit 1; }
echo "  ✅ 未认证/非本 caller 资源 → 401"

echo "== 3. 签一枚 aud=RS_A 的 access token(authorize+token)=="
CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$API_URL/authorize?response_type=code&client_id=$APP&redirect_uri=$REDIRECT&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&state=st1&login_user=alice")
CODE=$(echo "$LOC" | sed 's/.*code=\([^&]*\).*/\1/')
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=$REDIRECT&client_id=$APP")
AT=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
[ -n "$AT" ] || { echo "❌ 无 access_token"; exit 1; }

echo "== 4. RS-A 查自己 aud 的 token → active:true + 回带命名空间 =="
RESP=$(curl -s -X POST "$API_URL/introspect" -u "rs-a-introspect:$SEC_A" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$AT&client_id=rs-a-introspect")
echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['active'] is True, d
assert d['aud']==['$RS_A'], d
ns=d['https://a-auth.com/c']
assert ns['sub_type']=='user', ns
assert 'auth_grant' in ns, ns
assert 'act' not in d, '非委托 token 不应有 act'
print('  ✅ active + 回带命名空间 sub_type/auth_grant')
"

echo "== 5. RS-B 凭证查 aud=RS_A 的 token → active:false(aud 隔离,不泄露)=="
RESP=$(curl -s -X POST "$API_URL/introspect" -u "rs-b-introspect:$SEC_B" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$AT&client_id=rs-b-introspect")
echo "$RESP" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d['active'] is False, d
assert 'sub' not in d and 'aud' not in d, 'inactive 响应不得泄露其它字段'
print('  ✅ aud 隔离:RS-B 查 RS-A token → active:false 且不泄露')
"

echo "== 6. 错 secret / 未知调用方 → 401 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/introspect" -u "rs-a-introspect:WRONG" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$AT&client_id=rs-a-introspect")
[ "$ST" = "401" ] || { echo "❌ 错 secret 应 401(got $ST)"; exit 1; }
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/introspect" -u "nobody:x" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$AT&client_id=nobody")
[ "$ST" = "401" ] || { echo "❌ 未知调用方应 401(got $ST)"; exit 1; }
echo "  ✅ 认证失败 → 401"

echo "== 7. 无 introspect 权限的普通 client → 401 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/introspect" \
  -H "content-type: application/x-www-form-urlencoded" -d "token=$AT&client_id=$APP")
[ "$ST" = "401" ] || { echo "❌ 无 introspect 权限应 401(got $ST)"; exit 1; }
echo "  ✅ 无 introspect 权限 client → 401"

echo "✅ P1a MCP 集成(PRM 生成 + /introspect)真机 e2e 全绿"

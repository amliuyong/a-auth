#!/usr/bin/env bash
# spec 003 §1.4 真机 e2e:Admin 置备用户 → magic-link 登录复用 email→user_id 映射。
#
# 验证「user by email」访问模式在真机(API Gateway→Lambda→DynamoDB UsersTable)端到端成立:
#   1. POST /login/magic-link(email 含大写)→ dev_link → GET callback 建会话;
#   2. UsersTable get-item pk=user_id(user:{归一 email})→ 断言记录存在(user_id/email/created_at);
#      email 字段 == trim+lowercase 归一值(大写输入命中同一条,与 GSI key 一致);
#   3. GSI email-index query email=归一值 → 断言反查回同一 user_id(by-email 访问模式);
#   4. 幂等:直接再 get-item → created_at 不变(用户目录持久、后续登录复用不覆盖 created_at)。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   USERS_TABLE=<UsersTableName> AWS_PROFILE=default ./e2e/users_directory.sh
#
# 依赖:curl、python3、aws cli。dev 栈须开 AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER(magic-link dev 回显链接)。
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
USERS_TABLE="${USERS_TABLE:?需 USERS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
# email 故意含大写 + 前后不影响的本地部分,验证 trim+lowercase 归一命中同一条。
RAND="$(python3 -c 'import random;print(random.randint(1,1_000_000))')"
EMAIL_INPUT="E2E-User-${RAND}@Example.COM"
EMAIL_NORM="$(printf '%s' "$EMAIL_INPUT" | tr '[:upper:]' '[:lower:]')"
USER_ID="user:${EMAIL_NORM}"
JAR="$(mktemp)"

agent_auth_provision_local_user "$API_URL" "$EMAIL_INPUT"
echo "== 1. 已置备用户 POST /login/magic-link(大写 email=$EMAIL_INPUT)=="
RESP=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL_INPUT\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK" ] || { echo "❌ 无 dev_link(dev 占位未开?)"; exit 1; }
PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')

echo "== 2. GET callback(带 nonce cookie → 建会话并复用 users 表记录)=="
CODE_HTTP=$(curl -s -b "$JAR" -c "$JAR" -o /dev/null -w '%{http_code}' "$API_URL$PQ")
[ "$CODE_HTTP" = "303" ] || { echo "❌ callback 未 303(got $CODE_HTTP)"; exit 1; }

echo "== 3. UsersTable get-item pk=$USER_ID(归一 email 落库)=="
ITEM=$(aws dynamodb get-item --profile "$PROFILE" --region "$REGION" --table-name "$USERS_TABLE" \
  --key "{\"user_id\":{\"S\":\"$USER_ID\"}}")
echo "$ITEM" | E_UID="$USER_ID" EMAIL_NORM="$EMAIL_NORM" python3 -c "
import sys,json,os
d=json.load(sys.stdin).get('Item')
assert d, 'users 表无该 user 记录(§1.4 未落库)'
assert d['user_id']['S']==os.environ['E_UID'], 'user_id 不符'
assert d['email']['S']==os.environ['EMAIL_NORM'], 'email 未归一为小写(大写输入应 trim+lowercase)'
int(d['created_at']['N'])  # created_at 是数字时间戳
print('  ✅ users 记录存在;email 归一小写;created_at=%s' % d['created_at']['N'])
"
CREATED_AT=$(echo "$ITEM" | python3 -c "import sys,json;print(json.load(sys.stdin)['Item']['created_at']['N'])")

echo "== 4. GSI email-index query email=$EMAIL_NORM → 反查回同一 user_id(by-email 访问模式)=="
QRES=$(aws dynamodb query --profile "$PROFILE" --region "$REGION" --table-name "$USERS_TABLE" \
  --index-name email-index \
  --key-condition-expression "email = :e" \
  --expression-attribute-values "{\":e\":{\"S\":\"$EMAIL_NORM\"}}")
echo "$QRES" | E_UID="$USER_ID" python3 -c "
import sys,json,os
d=json.load(sys.stdin)
items=d.get('Items',[])
assert len(items)==1, 'GSI email-index 应恰好反查 1 条,得 %d' % len(items)
assert items[0]['user_id']['S']==os.environ['E_UID'], 'GSI 反查 user_id 不符'
print('  ✅ GSI email-index 反查回同一 user_id')
"

echo "== 5. 幂等:等冷却窗后**二次登录同 email** → 复用同 user_id + created_at 不覆盖 =="
# per-email 冷却 60s(C9.1);等过窗再触发第二次 magic-link,验证后续登录复用而非新建/覆盖。
sleep 62
JAR2="$(mktemp)"
RESP2=$(curl -s -c "$JAR2" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" \
  -d "{\"email\":\"$EMAIL_INPUT\"}")
LINK2=$(echo "$RESP2" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
[ -n "$LINK2" ] || { echo "❌ 二次登录无 dev_link"; exit 1; }
PQ2=$(echo "$LINK2" | sed 's|.*/login/callback|/login/callback|')
CODE_HTTP2=$(curl -s -b "$JAR2" -c "$JAR2" -o /dev/null -w '%{http_code}' "$API_URL$PQ2")
[ "$CODE_HTTP2" = "303" ] || { echo "❌ 二次 callback 未 303(got $CODE_HTTP2)"; exit 1; }
CREATED_AT2=$(aws dynamodb get-item --profile "$PROFILE" --region "$REGION" --table-name "$USERS_TABLE" \
  --key "{\"user_id\":{\"S\":\"$USER_ID\"}}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['Item']['created_at']['N'])")
[ "$CREATED_AT" = "$CREATED_AT2" ] || { echo "❌ 二次登录覆盖了 created_at($CREATED_AT→$CREATED_AT2)"; exit 1; }
# 再确认仍只 1 条(GSI 未产生重复记录)。
QCNT=$(aws dynamodb query --profile "$PROFILE" --region "$REGION" --table-name "$USERS_TABLE" \
  --index-name email-index --key-condition-expression "email = :e" \
  --expression-attribute-values "{\":e\":{\"S\":\"$EMAIL_NORM\"}}" \
  | python3 -c "import sys,json;print(len(json.load(sys.stdin).get('Items',[])))")
[ "$QCNT" = "1" ] || { echo "❌ 二次登录产生了重复记录(count=$QCNT)"; exit 1; }
echo "  ✅ 二次登录复用同 user_id;created_at 稳定($CREATED_AT);无重复记录"

rm -f "$JAR" "$JAR2"
echo "✅ spec 003 §1.4 用户目录 users 表真机 e2e 全绿(email→user_id 幂等映射 + GSI 反查 + 归一)"

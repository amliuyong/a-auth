#!/usr/bin/env bash
# P0.5 真机 e2e:账户恢复(C9.3 硬 gate)—— 一次性恢复码。
#
# 验证恢复流在真机(API Gateway→Lambda→DynamoDB)端到端成立:
# Admin 置备用户 + 首次改密建会话 → POST /recovery/generate(show-once 生成 10 码)→
# 密码重新认证 → POST /recovery/verify 用一个码 → 验码消费(C9.3)→ 建新会话登入 +
# 引导绑新因子 → 吊销恢复前会话(delete_by_user)。
# 再验一次性(同码重放拒)+ 限流锁定(连续错码 → 429)。
#
# 用法:
#   API_URL=https://<id>.execute-api.us-east-1.amazonaws.com \
#   AWS_PROFILE=default ./e2e/recovery.sh
#
# 依赖:curl、python3、AWS CLI。
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL}"
STACK="${STACK:-AgentAuthDev}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
EMAIL="e2e-recover-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
EMAIL2=""
JAR="$(mktemp)"          # 登录会话 cookie jar(旧会话)
JAR2="$(mktemp)"         # 恢复后新会话 cookie jar
JAR3=""
OPERATION_ID="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
E2E_PASSWORD="${AGENT_AUTH_E2E_PASSWORD:-$(python3 -c 'import secrets; print("Active-" + secrets.token_urlsafe(24))')}"
export AGENT_AUTH_E2E_PASSWORD="$E2E_PASSWORD"

stack_output() {
  aws cloudformation describe-stacks --stack-name "$STACK" \
    --profile "$PROFILE" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" \
    --output text
}

RECOVERY_TABLE="${RECOVERY_TABLE:-$(stack_output RecoveryTableName)}"
if [ -z "$RECOVERY_TABLE" ] || [ "$RECOVERY_TABLE" = "None" ]; then
  echo "❌ $STACK 缺 RecoveryTableName 输出" >&2
  exit 1
fi

cleanup() {
  local status=$?
  local values keys physical_key key_json
  trap - EXIT INT TERM
  set +e

  if [ -n "${ADMIN_TOKEN:-}" ]; then
    for email in "$EMAIL" "$EMAIL2"; do
      [ -n "$email" ] || continue
      curl -sS -o /dev/null -X DELETE "$API_URL/admin/users/user:$email" \
        -H "authorization: Bearer $ADMIN_TOKEN" || true
    done
  fi

  values="$(EMAIL="$EMAIL" EMAIL2="$EMAIL2" python3 -c '
import json, os
user1 = "user:" + os.environ["EMAIL"]
user2 = "user:" + (os.environ["EMAIL2"] or os.environ["EMAIL"])
print(json.dumps({
    ":kind": {"S": "recovery_success_result"},
    ":user1": {"S": user1},
    ":user2": {"S": user2},
}))
')"
  keys="$(aws dynamodb scan --profile "$PROFILE" --region "$REGION" \
    --table-name "$RECOVERY_TABLE" --consistent-read \
    --projection-expression "user_lookup" \
    --filter-expression "#kind = :kind AND user_id IN (:user1, :user2)" \
    --expression-attribute-names '{"#kind":"kind"}' \
    --expression-attribute-values "$values" \
    --query 'Items[].user_lookup.S' --output text 2>/dev/null)" || {
      echo "❌ 无法扫描并清理 recovery success-result" >&2
      [ "$status" -ne 0 ] || status=1
      keys=""
    }
  for physical_key in $keys; do
    key_json="$(PHYSICAL_KEY="$physical_key" python3 -c \
      'import json,os; print(json.dumps({"user_lookup":{"S":os.environ["PHYSICAL_KEY"]}}))')"
    aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" \
      --table-name "$RECOVERY_TABLE" --key "$key_json" >/dev/null 2>&1 || {
        echo "❌ 无法删除 recovery success-result" >&2
        [ "$status" -ne 0 ] || status=1
      }
  done

  rm -f "$JAR" "$JAR2" "$JAR3"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

password_login_session() {
  local email="$1" jar="$2" body status
  body="$(EMAIL="$email" PASSWORD="$E2E_PASSWORD" python3 -c \
    'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"password":os.environ["PASSWORD"]}))')"
  status="$(curl -s -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' \
    -X POST "$API_URL/login/password" -H "content-type: application/json" -d "$body")"
  [ "$status" = "200" ] || {
    echo "❌ 密码重新认证失败(email=$email,status=$status)" >&2
    return 1
  }
}

magic_link_session() {
  local email="$1" jar="$2" body response messages link="" status
  body="$(EMAIL="$email" python3 -c \
    'import json,os; print(json.dumps({"email":os.environ["EMAIL"],"authorize_query":""}))')"
  response="$(curl -fsS -b "$jar" -c "$jar" -X POST "$API_URL/login/magic-link" \
    -H "content-type: application/json" -d "$body")"
  RESPONSE="$response" python3 -c '
import json, os
assert json.loads(os.environ["RESPONSE"]).get("sent") is True
'

  # The deployed environments do not expose dev_link. Read the tenant-scoped
  # outbox and allow for DynamoDB scan propagation before consuming the link.
  for _ in $(seq 1 10); do
    if messages="$(curl -fsS "$API_URL/admin/messages" \
      -H "authorization: Bearer $ADMIN_TOKEN")"; then
      link="$(MESSAGES="$messages" EMAIL="$email" python3 -c '
import json, os
messages = json.loads(os.environ["MESSAGES"]).get("messages", [])
print(next((
    message.get("body", "")
    for message in messages
    if message.get("kind") == "magic_link"
    and message.get("recipient") == os.environ["EMAIL"]
), ""))
')"
    fi
    [ -n "$link" ] && break
    sleep 1
  done
  [ -n "$link" ] || {
    echo "❌ 未在 Admin 消息 outbox 找到 magic-link(email=$email)" >&2
    return 1
  }

  status="$(curl -sS -b "$jar" -c "$jar" -o /dev/null -w '%{http_code}' "$link")"
  [ "$status" = "303" ] || {
    echo "❌ magic-link callback 失败(email=$email,status=$status)" >&2
    return 1
  }
}

echo "== 1. Admin 置备用户 + 首次改密建会话 =="
agent_auth_provision_local_user "$API_URL" "$EMAIL" "$JAR"

echo "== 2. POST /recovery/generate(已登录 → show-once 10 码)=="
GEN=$(curl -s -b "$JAR" -X POST "$API_URL/recovery/generate")
readarray -t CODES < <(echo "$GEN" | python3 -c "
import sys,json
d=json.load(sys.stdin)
cs=d.get('recovery_codes',[])
assert len(cs)==10, f'期望 10 码,得 {len(cs)}'
assert all(c.startswith('v1.') for c in cs), '码应带 v1. 前缀'
print('\n'.join(cs))
")
[ "${#CODES[@]}" = "10" ] || { echo "❌ 未生成 10 码"; exit 1; }
echo "  ✅ 生成 ${#CODES[@]} 个恢复码(show-once)"

echo "== 2b. 生成推进 credential authority 后密码重新认证 =="
password_login_session "$EMAIL" "$JAR"

echo "== 3. 未登录不能生成(401)=="
UNAUTH=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/generate")
[ "$UNAUTH" = "401" ] || { echo "❌ 未登录生成未拒(got $UNAUTH)"; exit 1; }

echo "== 3b. GET /recovery/status:已登录用户查自己 → configured=true/remaining=10 =="
STATUS=$(curl -s -b "$JAR" "$API_URL/recovery/status")
echo "$STATUS" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d.get('configured') is True, f'生成后应 configured=true,得 {d}'
assert d.get('remaining')==10, f'剩余应 10,得 {d.get(\"remaining\")}'
print('  ✅ status: configured=true, remaining=10')
"
# 未登录查 status 也 401(与 generate 同鉴权面,不留匿名可达面)。
SUNAUTH=$(curl -s -o /dev/null -w '%{http_code}' "$API_URL/recovery/status")
[ "$SUNAUTH" = "401" ] || { echo "❌ 未登录查 status 未拒(got $SUNAUTH)"; exit 1; }

echo "== 4. 恢复前会话此刻有效(探针:recovery/status 200)=="
BEFORE=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$API_URL/recovery/status")
[ "$BEFORE" = "200" ] || { echo "❌ 恢复前旧会话应有效(got $BEFORE)"; exit 1; }

echo "== 5. POST /recovery/verify 用一个码 → 建新会话登入 + next=bind_new_factor =="
RECOVER=$(curl -s -c "$JAR2" -X POST "$API_URL/recovery/verify" -H "content-type: application/json" \
  -d "{\"code\":\"${CODES[0]}\",\"operation_id\":\"$OPERATION_ID\"}")
echo "$RECOVER" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d.get('recovered') is True, '应 recovered=true'
assert d.get('next')=='bind_new_factor', 'next 应 bind_new_factor'
print('  ✅ 恢复成功,建会话登入,引导绑新因子')
"
grep -q "__Host-agent_auth_session" "$JAR2" || { echo "❌ 恢复未设新会话 cookie"; exit 1; }

echo "== 6. 响应丢失:同 operation + 同码重试 → 200(同一权威结果)=="
REPLAY=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/verify" -H "content-type: application/json" \
  -d "{\"code\":\"${CODES[0]}\",\"operation_id\":\"$OPERATION_ID\"}")
[ "$REPLAY" = "200" ] || { echo "❌ 同 operation 重试未找回结果(got $REPLAY)"; exit 1; }

echo "== 6b. 一次性:不同 operation 不能重放已消费码 → 400 =="
OTHER_OPERATION_ID="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
REPLAY_OTHER=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/verify" -H "content-type: application/json" \
  -d "{\"code\":\"${CODES[0]}\",\"operation_id\":\"$OTHER_OPERATION_ID\"}")
[ "$REPLAY_OTHER" = "400" ] || { echo "❌ 不同 operation 重放未拒(got $REPLAY_OTHER)"; exit 1; }

echo "== 7. 恢复吊销旧会话:旧 cookie 探针 → 401(delete_by_user)=="
AFTER=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' "$API_URL/recovery/status")
[ "$AFTER" = "401" ] || { echo "❌ 恢复后旧会话未吊销(got $AFTER)"; exit 1; }

echo "== 7b. 消费一码后 status.remaining 递减(用恢复建的新会话查)=="
# 消费了 CODES[0](step 5)→ 剩 9。用恢复后的新会话 JAR2 查 status(旧会话已吊销)。
STATUS2=$(curl -s -b "$JAR2" "$API_URL/recovery/status")
echo "$STATUS2" | python3 -c "
import sys,json
d=json.load(sys.stdin)
assert d.get('remaining')==9, f'消费一码后剩余应 9,得 {d.get(\"remaining\")}'
assert d.get('configured') is True, '仍有剩余 → 仍 configured'
print('  ✅ status: remaining 9(消费一码后递减)')
"

echo "== 8. 限流:连续错码(同 user_lookup 前缀,秘密段错)→ 最终 429 =="
# 从真实码取 v1.{lookup}. 前缀,拼一个秘密段错误的同 user 码。
PREFIX=$(echo "${CODES[1]}" | cut -d. -f1-2)
WRONG="$PREFIX.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
SAW_LOCK=0
for _ in $(seq 1 7); do
  WRONG_OPERATION_ID="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/verify" -H "content-type: application/json" \
    -d "{\"code\":\"$WRONG\",\"operation_id\":\"$WRONG_OPERATION_ID\"}")
  if [ "$ST" = "429" ]; then SAW_LOCK=1; break; fi
  [ "$ST" = "400" ] || { echo "❌ 错码应 400/429(got $ST)"; exit 1; }
done
[ "$SAW_LOCK" = "1" ] || { echo "❌ 连续错码未触发锁定(429)"; exit 1; }

echo "== 9. 锁定期内正确码也被拒(429,防绕过限流)=="
LOCKED=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/verify" -H "content-type: application/json" \
  -d "{\"code\":\"${CODES[2]}\",\"operation_id\":\"$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')\"}")
[ "$LOCKED" = "429" ] || { echo "❌ 锁定期内正确码未 429(got $LOCKED)"; exit 1; }

echo "== 10. 生成限流(C9.1 防滥刷 + 缓解 CSRF 覆盖旧码):新用户连续生成 → 最终 429 =="
# 用全新用户(全新 user_id → 全新桶)避免污染前面步骤。桶容量 5,连刷应触顶 429。
EMAIL2="e2e-genflood-$(python3 -c 'import random;print(random.randint(1,1_000_000))')@example.com"
JAR3="$(mktemp)"
agent_auth_provision_local_user "$API_URL" "$EMAIL2" "$JAR3"
SAW_GEN_LIMIT=0
for attempt in $(seq 1 6); do
  GST=$(curl -s -b "$JAR3" -o /dev/null -w '%{http_code}' -X POST "$API_URL/recovery/generate")
  if [ "$GST" = "429" ]; then SAW_GEN_LIMIT=1; break; fi
  [ "$GST" = "200" ] || { echo "❌ 生成应 200/429(got $GST)"; exit 1; }
  # Regenerate advances credential authority and clears the old session.
  # The initial password change plus four password logins exactly consume that
  # login bucket; after generation five, use the independent magic-link path.
  if [ "$attempt" -lt 5 ]; then
    password_login_session "$EMAIL2" "$JAR3"
  elif [ "$attempt" = "5" ]; then
    magic_link_session "$EMAIL2" "$JAR3"
  fi
done
[ "$SAW_GEN_LIMIT" = "1" ] || { echo "❌ 连续生成未触发限流(429)"; exit 1; }
echo "  ✅ 生成限流触顶 429(per-user 桶)"

echo "✅ P0.5 账户恢复(一次性恢复码)真机 e2e 全绿"

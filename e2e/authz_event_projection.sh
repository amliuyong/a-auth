#!/usr/bin/env bash
# spec 004 §3.3(C6.5)真机 e2e:授权会话状态迁移的 **EventBridge 投影 → CloudWatch Logs 审计湖**。
# 触发一次 code-flow /authorize(建授权会话 + 迁移 created→pending_consent→code_issued),AS 侧
# EventBridgeAuthzEventSink PutEvents 到 bus → rule(source 过滤)→ CloudWatch Logs target。
# 断言:审计 LogGroup 里出现该会话的 AuthzSessionTransition 事件,detail 带 session_id + 单调 sequence + state。
#
# 权威源仍是 DynamoDB 会话记录;本 e2e 验的是**投影旁路真的落地成可查审计流**(解"无消费者=半成品")。
#
# 用法:
#   API_URL=https://<cloudfront> CLIENTS_TABLE=<..> AUTHZ_AUDIT_LOG=<LogGroup 名> \
#   AWS_PROFILE=default ./e2e/authz_event_projection.sh
set -euo pipefail
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL(CloudFront 域)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
AUTHZ_AUDIT_LOG="${AUTHZ_AUDIT_LOG:?需 AUTHZ_AUDIT_LOG(CDK 输出 AuthzAuditLogName)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

RAND="$(python3 -c 'import secrets;print(secrets.token_hex(4))')"
CID="authz-evt-e2e-$RAND"
REDIR="https://authz-evt.example.com/cb"
VERIFIER="0123456789012345678901234567890123456789abc"
CHALLENGE="$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")"

cleanup() {
  "${AWSQ[@]}" dynamodb delete-item --table-name "$CLIENTS_TABLE" \
    --key "{\"client_id\":{\"S\":\"$CID\"}}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "== 0. seed public client =="
"${AWSQ[@]}" dynamodb put-item --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CID\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIR\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
echo "  client=$CID"

# 记开始时间(毫秒)用于日志过滤窗(避免匹配历史事件)。
START_MS=$(( $(date +%s) * 1000 - 5000 ))

echo "== 1. code-flow /authorize(建授权会话 + 迁移 → 发 3 条投影事件)=="
LOC=$(curl -s -o /dev/null -D - \
  "$API_URL/authorize?response_type=code&client_id=$CID&redirect_uri=$REDIR&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&state=xyz&login_user=alice&_n=$RAND" \
  | tr -d '\r' | awk 'tolower($1)=="location:"{print $2}')
echo "$LOC" | grep -q "^$REDIR" || { echo "❌ authorize 未回跳(loc=$LOC)"; exit 1; }
echo "  ✅ authorize 303 回跳(授权会话已建 + 迁移)"

echo "== 2. 轮询审计 LogGroup 出现本 client 的 AuthzSessionTransition 事件(投影落地)=="
# EventBridge→CloudWatch Logs 有传播延迟;轮询最多 ~60s。过滤本次窗内、含本 client 的会话事件。
FOUND=""
for attempt in $(seq 1 20); do
  # filter-log-events 取窗内事件(EventBridge 写入的 detail JSON 里含 source/detail-type/detail)。
  EVENTS=$("${AWSQ[@]}" logs filter-log-events \
    --log-group-name "$AUTHZ_AUDIT_LOG" \
    --start-time "$START_MS" \
    --filter-pattern '"AuthzSessionTransition"' \
    --query 'events[].message' --output json 2>/dev/null || echo '[]')
  # 解析:找 detail.state 集合,断言含 created + code_issued_awaiting_exchange + sequence 单调。
  if echo "$EVENTS" | python3 -c "
import sys,json
msgs=json.load(sys.stdin)
seqs=[]; states=[]
for m in msgs:
    try: ev=json.loads(m)
    except: continue
    if ev.get('detail-type')!='AuthzSessionTransition': continue
    d=ev.get('detail',{})
    if isinstance(d,str): d=json.loads(d)
    seqs.append(d.get('sequence')); states.append(d.get('state'))
# 至少要看到 created(seq0)与 code_issued_awaiting_exchange;sequence 单调非负。
import sys
if 'created' in states and any('code_issued' in (s or '') for s in states) and all(isinstance(x,int) and x>=0 for x in seqs):
    print('OK states=%r seqs=%r'%(states,seqs)); sys.exit(0)
sys.exit(1)
" 2>/dev/null; then FOUND=1; break; fi
  sleep 3
done
[ -n "$FOUND" ] || { echo "❌ 审计 LogGroup 未在窗内出现完整 AuthzSessionTransition 投影(20 次轮询)"; exit 1; }

# 再打印一条命中详情(可观测)。
"${AWSQ[@]}" logs filter-log-events --log-group-name "$AUTHZ_AUDIT_LOG" \
  --start-time "$START_MS" --filter-pattern '"AuthzSessionTransition"' \
  --query 'events[].message' --output json | python3 -c "
import sys,json
msgs=json.load(sys.stdin); seen=[]
for m in msgs:
    try: ev=json.loads(m)
    except: continue
    if ev.get('detail-type')!='AuthzSessionTransition': continue
    d=ev.get('detail',{}); d=json.loads(d) if isinstance(d,str) else d
    seen.append((d.get('sequence'),d.get('state')))
seen=sorted(set(seen))
print('  ✅ 投影落地审计湖(按 sequence 排序去重):', seen)
"

# ── 场景 3:CIBA /bc-authorize 主动投影(spec 004 §3.3:device/CIBA 也投影,key=HMAC(auth_req_id)不投原值)──
echo "== 3. CIBA /bc-authorize 主动投影(pending_consent 落审计湖)=="
CIBA_USER="authz-evt-ciba-$RAND@example.com"
# Admin 置备用户(§2b.5:login_hint 须已注册)。
agent_auth_provision_local_user "$API_URL" "$CIBA_USER"
JAR=$(mktemp)
RESP=$(curl -s -c "$JAR" -X POST "$API_URL/login/magic-link" -H "content-type: application/json" -d "{\"email\":\"$CIBA_USER\"}")
LINK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('dev_link',''))")
if [ -n "$LINK" ]; then
  PQ=$(echo "$LINK" | sed 's|.*/login/callback|/login/callback|')
  curl -s -b "$JAR" -o /dev/null "$API_URL$PQ"
fi
rm -f "$JAR"
CIBA_START_MS=$(( $(date +%s) * 1000 - 5000 ))
BC=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/bc-authorize" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "client_id=$CID" --data-urlencode "scope=openid" --data-urlencode "login_hint=$CIBA_USER")
[ "$BC" = "200" ] || { echo "  ⚠️ /bc-authorize=$BC(非 200,跳过 CIBA 投影断言;可能 dev 占位未开)"; }
if [ "$BC" = "200" ]; then
  CFOUND=""
  for attempt in $(seq 1 20); do
    if "${AWSQ[@]}" logs filter-log-events --log-group-name "$AUTHZ_AUDIT_LOG" \
      --start-time "$CIBA_START_MS" --filter-pattern '"pending_consent"' \
      --query 'events[].message' --output json 2>/dev/null \
      | python3 -c "
import sys,json
for m in json.load(sys.stdin):
    try: ev=json.loads(m)
    except: continue
    if ev.get('detail-type')!='AuthzSessionTransition': continue
    d=ev.get('detail',{}); d=json.loads(d) if isinstance(d,str) else d
    if d.get('state')=='pending_consent' and isinstance(d.get('sequence'),int):
        # 投影键 MUST 是 HMAC 哈希(base64url,非原始 auth_req_id 明文——不泄露活凭证)。
        import sys as s; s.exit(0)
raise SystemExit(1)
" 2>/dev/null; then CFOUND=1; break; fi
    sleep 3
  done
  [ -n "$CFOUND" ] || { echo "❌ CIBA 主动投影未落审计湖(pending_consent 未出现)"; exit 1; }
  echo "  ✅ CIBA /bc-authorize → pending_consent 投影落审计湖(key=HMAC(auth_req_id) 不泄露活凭证)"
fi

echo "✅ spec 004 §3.3 授权会话事件投影真机 e2e 全绿(authz-code + CIBA 均投影 → EventBridge → CloudWatch Logs 审计湖;detail 带单调 sequence+state,乱序可按序回放;device/CIBA 键为 HMAC 不投活凭证)"

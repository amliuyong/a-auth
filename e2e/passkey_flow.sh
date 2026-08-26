#!/usr/bin/env bash
# spec 003 §3(C9.4)真机 e2e:WebAuthn passkey 登录仪式打到真实 DynamoDB(PasskeyTable + GSI user_id-index
# + PasskeyChallengeTable)。**无需真/虚拟 authenticator**:脚本内用 P-256(cryptography)+ 自带极简 CBOR
# 编码器扮 authenticator——造 fmt=none attestation(注册)+ 签 assertion(认证),类比进程内 passkey_e2e。
#
# 为何要真机(进程内 passkey_e2e 已全绿):验 **Dynamo 适配器** 路径——put_new 条件写唯一 / list_by_user
# GSI 反查(begin 的 allowCredentials/excludeCredentials)/ signCount CAS(UpdateItem 条件)/ challenge
# 条件删一次性。这是内存适配器**测不到**的一类(如 amr 曾 Ss-vs-L 只被真机 e2e 抓到)。
#
# 脚本临时启用 passkey → 跑仪式 → **EXIT trap 全量恢复原 env**。
# 原部署的开关状态不作假设，恢复后按完整 Environment JSON 相等断言。
#
# 全链:开功能 → Admin 置备本地用户 + 首次改密建会话 → register/begin(challenge 绑 user_id)→ 造 attestation →
#   register/finish 存凭证 → 断言 PasskeyTable 落库 + GSI 反查命中 → authenticate/begin(login_hint)→
#   allowCredentials 含刚注册 → 造 assertion(signCount++)→ authenticate/finish 登入(amr=webauthn)→
#   断言 signCount CAS 已回写(0→1)→ challenge 重放 → 400。
#
# 用法:
#   API_URL=https://<cloudfront 域> \
#   FN_NAME=<AuthFn 名> \
#   CLIENTS_TABLE=<ClientsTable 名> USERS_TABLE=<UsersTable 名> \
#   PASSKEY_TABLE=<PasskeyTable 名> PASSKEY_CHALLENGE_TABLE=<PasskeyChallengeTable 名> \
#   AWS_PROFILE=default ./e2e/passkey_flow.sh
#
# 依赖:curl、python3(cryptography)、aws cli、jq。仅可用于隔离 dev 栈。
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/lib/local_user.sh"

API_URL="${API_URL:?需 API_URL(CloudFront 域,非裸 API-GW,否则 bad-host)}"
FN_NAME="${FN_NAME:?需 FN_NAME(AuthFn Lambda 名)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
USERS_TABLE="${USERS_TABLE:?需 USERS_TABLE}"
PASSKEY_TABLE="${PASSKEY_TABLE:?需 PASSKEY_TABLE}"
PASSKEY_CHALLENGE_TABLE="${PASSKEY_CHALLENGE_TABLE:?需 PASSKEY_CHALLENGE_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"

AWSQ=(aws --profile "$PROFILE" --region "$REGION")
# issuer host = API_URL 去 scheme(rp_id 逐租户 = issuer host;origin = https://<rp_id>)。
RP_ID="$(printf '%s' "$API_URL" | sed -E 's#^https?://##; s#/.*$##')"
ORIGIN="https://$RP_ID"
RAND="$(python3 -c 'import secrets;print(secrets.token_hex(4))')"
EMAIL="pk-e2e-${RAND}@example.com"
USER_ID="user:${EMAIL}"
umask 077
JAR="$(mktemp)"
KEYFILE="$(mktemp)"                  # authenticator 私钥 PEM(临时;不进 repo)
ENV_BAK="$(mktemp)"                  # 原 Lambda env 全量 {"Variables":{...}}(含 SERVER_SECRET 明文;600;trap 后删)
ENV_NEW="$(mktemp)"                  # 加开关后的 env(同上)
ENV_CURRENT="$(mktemp)"              # 恢复后 env,仅用于与 ENV_BAK 全量比对
AF_JAR="$(mktemp)"                   # authenticate/finish 的 session cookie jar(含活会话;trap 清理,评审 Kiro L3)
AF_BODY_FILE="$(mktemp)"             # authenticate/finish 响应体(mktemp 非固定名,防共享主机碰撞/符号链接,L3)
CRED_ID=""
STEP_UP_CLIENT="pk-stepup-$RAND"
STEP_UP_REDIRECT="https://probe.example.com/passkey-step-up"
# ⚠️ 安全:Lambda env 仍含 SERVER_SECRET 明文(Admin credential 仅含 ARN)。**只经 file:// 传参**
#   (不进 argv、CLI 报错不回显)、
#   只经 600 tempfile 中转(不打印、不入 repo),trap 结束即删。

cleanup() {
  local status=$? cleanup_failed=0
  trap - EXIT INT TERM
  set +e
  "${AWSQ[@]}" dynamodb delete-item --table-name "$CLIENTS_TABLE" \
    --key "{\"client_id\":{\"S\":\"$STEP_UP_CLIENT\"}}" >/dev/null 2>&1 || true
  if agent_auth_admin_token; then
    USER_DELETE_STATUS=$(curl -s -o /dev/null -w '%{http_code}' --path-as-is \
      -X DELETE "$API_URL/admin/users/$USER_ID" \
      -H "authorization: Bearer $ADMIN_TOKEN")
  else
    USER_DELETE_STATUS="admin-token-error"
  fi
  case "$USER_DELETE_STATUS" in
    200)
      if "${AWSQ[@]}" dynamodb delete-item --table-name "$USERS_TABLE" \
        --key "{\"user_id\":{\"S\":\"$USER_ID\"}}" >/dev/null; then
        echo "  ✅ e2e 用户全级联后已删除测试 tombstone"
      else
        echo "❌ e2e 用户 tombstone 清理失败(user_id=$USER_ID);保留记录供人工恢复" >&2
        cleanup_failed=4
      fi
      ;;
    404) ;;
    *)
      echo "❌ e2e 用户清理失败(status=$USER_DELETE_STATUS,user_id=$USER_ID);保留记录供人工恢复" >&2
      cleanup_failed=4
      ;;
  esac
  # F10(评审 codex#1/Kiro H1):无论成败都恢复完整原 env;**恢复失败 MUST 醒目告警 + 保留备份 + 非零退出**。
  # 绝不假设原 passkey 状态，也不静默吞错后删掉唯一恢复物。
  if [ -s "$ENV_BAK" ]; then
    echo "== [trap] 全量恢复 Lambda 原 env(F10)=="
    RESTORED=""
    for attempt in 1 2 3; do
      "${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME" 2>/dev/null
      # 恢复 update **不吞 stderr**——失败要能看到原因(评审 Kiro L5:此处是恢复关键路径)。
      if "${AWSQ[@]}" lambda update-function-configuration --function-name "$FN_NAME" \
           --environment "file://$ENV_BAK" >/dev/null; then
        "${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME" 2>/dev/null
        if "${AWSQ[@]}" lambda get-function-configuration --function-name "$FN_NAME" \
             --query 'Environment' --output json > "$ENV_CURRENT" &&
           jq -e --slurpfile original "$ENV_BAK" '. == $original[0]' \
             "$ENV_CURRENT" >/dev/null; then
          RESTORED=1
          echo "  ✅ Lambda Environment 与运行前备份全量一致"
          break
        fi
        echo "  ⚠️ 第 $attempt 次:update 成功但 env 全量比对不一致,重试…"
      else
        echo "  ⚠️ 第 $attempt 次:update-function-configuration 失败,重试…"
      fi
      sleep 3
    done
    if [ -z "$RESTORED" ]; then
      echo "❌❌ 严重:Lambda 原 env 恢复失败(F10:测试开关可能仍对公网可达)。" >&2
      echo "    原始 env 备份**保留**在:$ENV_BAK —— 请立即手动执行:" >&2
      echo "    aws lambda update-function-configuration --function-name $FN_NAME --environment file://$ENV_BAK --profile $PROFILE --region $REGION" >&2
      rm -f "$JAR" "$KEYFILE" "$ENV_NEW" "$ENV_CURRENT" "$AF_JAR" "$AF_BODY_FILE"  # 只删非恢复物;ENV_BAK 保留
      exit 3
    fi
  fi
  rm -f "$JAR" "$KEYFILE" "$ENV_BAK" "$ENV_NEW" "$ENV_CURRENT" "$AF_JAR" "$AF_BODY_FILE"
  [ "$cleanup_failed" -eq 0 ] || exit "$cleanup_failed"
  exit "$status"
}
# INT/TERM 先转为非零退出，再由 EXIT trap 做一次恢复；SIGKILL 无法捕获,属固有(评审 Kiro L4)。
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== 0. 临时开启 passkey;跑完 trap 全量恢复 =="
echo "  ⚠️ 注意(评审 Kiro M1):测试期间 passkey 端点对公网可达——**仅隔离 dev 栈可跑**,勿对共享/生产栈用。"
# 读全量现有 env(update-function-configuration 是**整体替换**,须回灌全部)。取整个 Environment 结构
# ({"Variables":{...}}),经 file:// 传参——secret 不进 argv、只在 600 tempfile 中转。
"${AWSQ[@]}" lambda get-function-configuration --function-name "$FN_NAME" \
  --query 'Environment' --output json > "$ENV_BAK"
jq '.Variables += {"AGENT_AUTH_PASSKEY_ENABLED":"1"}' "$ENV_BAK" > "$ENV_NEW"
"${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME"
# 开启 update 也带全量 env(含 secret):吞 stderr 防 ValidationException 回显 env 细节(评审 Kiro L5)。
"${AWSQ[@]}" lambda update-function-configuration --function-name "$FN_NAME" \
  --environment "file://$ENV_NEW" >/dev/null 2>&1
"${AWSQ[@]}" lambda wait function-updated --function-name "$FN_NAME"
# 轮询直到 register/begin 不再 404(冷启动 + 新配置生效)。
for _ in $(seq 1 20); do
  C=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/passkey/register/begin")
  [ "$C" != "404" ] && break
  sleep 2
done
echo "  passkey 已开(register/begin 未登录=$C,期望 401)"

agent_auth_provision_local_user "$API_URL" "$EMAIL" "$JAR"
echo "== 1. 已置备本地用户并首次改密登录(email=$EMAIL)=="
grep -q "__Host-agent_auth_session" "$JAR" || {
  echo "❌ 首次改密未建立 session cookie"
  exit 1
}
echo "  ✅ 已登录(session cookie 落 jar)"

echo "== 2. register/begin(会话鉴权 → challenge 绑 user_id)=="
RB=$(curl -s -b "$JAR" -X POST "$API_URL/passkey/register/begin")
REG_CHALLENGE=$(echo "$RB" | jq -r '.challenge')
RESP_RPID=$(echo "$RB" | jq -r '.rp_id')
RESP_UID=$(echo "$RB" | jq -r '.user_id')
if [ -z "$REG_CHALLENGE" ] || [ "$REG_CHALLENGE" = "null" ]; then
  echo "❌ register/begin 无 challenge: $RB"
  exit 1
fi
[ "$RESP_RPID" = "$RP_ID" ] || { echo "❌ rp_id 不符:期望 $RP_ID 得 $RESP_RPID"; exit 1; }
[ "$RESP_UID" = "$USER_ID" ] || echo "  ⚠️ user_id=$RESP_UID(与推断 $USER_ID 不同,继续以服务端为准)"
[ "$(echo "$RB" | jq -r '.user_verification')" = "required" ] || { echo "❌ UV 非 required"; exit 1; }
echo "  ✅ challenge 下发;rp_id=$RESP_RPID;UV=required"

echo "== 3. 造 fmt=none attestation(P-256 + CBOR)+ register/finish 存凭证 =="
# python 扮 authenticator:生成 P-256 key(存 KEYFILE 供认证复用)、造 clientDataJSON + attestationObject。
REG_OUT=$(RP_ID="$RP_ID" ORIGIN="$ORIGIN" CHALLENGE="$REG_CHALLENGE" KEYFILE="$KEYFILE" python3 - <<'PY'
import os, json, base64, hashlib, secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

# --- 极简 CBOR 编码器(仅需:小整数/字节串/文本串/map)---
def cbor_uint(major, n):
    if n < 24: return bytes([major | n])
    if n < 256: return bytes([major | 24, n])
    if n < 65536: return bytes([major | 25]) + n.to_bytes(2, 'big')
    raise ValueError('len too big')
def enc(v):
    if isinstance(v, bool):  # 必须在 int 前(bool 是 int 子类)
        raise ValueError('bool unsupported')
    if isinstance(v, int):
        if v >= 0: return cbor_uint(0x00, v)
        return cbor_uint(0x20, -1 - v)          # 负整数 major 1
    if isinstance(v, bytes): return cbor_uint(0x40, len(v)) + v
    if isinstance(v, str):
        b = v.encode(); return cbor_uint(0x60, len(b)) + b
    if isinstance(v, dict):
        out = cbor_uint(0xa0, len(v))
        for k, val in v.items(): out += enc(k) + enc(val)
        return out
    raise ValueError('unsupported %r' % type(v))

rp_id = os.environ['RP_ID']; origin = os.environ['ORIGIN']; challenge = os.environ['CHALLENGE']

key = ec.generate_private_key(ec.SECP256R1())
with open(os.environ['KEYFILE'], 'wb') as f:
    f.write(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
nums = key.public_key().public_numbers()
x = nums.x.to_bytes(32, 'big'); y = nums.y.to_bytes(32, 'big')

# COSE_Key: 1=kty(2 EC2) 3=alg(-7 ES256) -1=crv(1 P-256) -2=x -3=y
cose = enc({1: 2, 3: -7, -1: 1, -2: x, -3: y})

cred_id = secrets.token_bytes(20)
rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
flags = bytes([0x45])       # UP|UV|AT
sign_count = (0).to_bytes(4, 'big')
aaguid = bytes(16)
cred_id_len = len(cred_id).to_bytes(2, 'big')
auth_data = rp_id_hash + flags + sign_count + aaguid + cred_id_len + cred_id + cose

att_obj = enc({"fmt": "none", "attStmt": {}, "authData": auth_data})
cdj = json.dumps({"type": "webauthn.create", "challenge": challenge, "origin": origin},
                 separators=(',', ':')).encode()

print(json.dumps({
    "client_data_json": b64u(cdj),
    "attestation_object": b64u(att_obj),
    "credential_id": b64u(cred_id),
}))
PY
)
CRED_ID=$(echo "$REG_OUT" | jq -r '.credential_id')
RF=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$API_URL/passkey/register/finish" \
  -H "content-type: application/json" \
  -d "$(echo "$REG_OUT" | jq -c --arg c "$REG_CHALLENGE" '{challenge:$c, client_data_json, attestation_object}')")
[ "$RF" = "200" ] || { echo "❌ register/finish 未 200(got $RF)"; exit 1; }
echo "  ✅ register/finish 200;credential_id=$CRED_ID"

echo "== 4. 断言 PasskeyTable 落库(pk=credential_id,--consistent-read)+ 归属 user_id =="
# --consistent-read:写后立即强一致读主表,免最终一致读到旧值致假失败(评审 Kiro M2)。
ITEM=$("${AWSQ[@]}" dynamodb get-item --table-name "$PASSKEY_TABLE" --consistent-read \
  --key "{\"credential_id\":{\"S\":\"$CRED_ID\"}}")
echo "$ITEM" | CRED="$CRED_ID" python3 -c "
import sys,json,os
d=json.load(sys.stdin).get('Item')
assert d, 'PasskeyTable 无该凭证(put_new 未落库)'
assert d['credential_id']['S']==os.environ['CRED'], 'credential_id 不符'
assert d.get('user_id',{}).get('S'), '缺 user_id 归属'
print('  ✅ PasskeyTable 落库;user_id=%s' % d['user_id']['S'])
"

echo "== 4b. credentialId 唯一(put_new attribute_not_exists)拒覆盖:同 credential_id 二次注册 → 400 =="
# 内存适配器测不到的 Dynamo 专有原子拒绝路径(评审 Kiro M4)。用新 challenge(begin 再取)但复用同 credential_id,
# 造合法 attestation 走到 put_new → 应 ConditionalCheckFailed → 400 "credential already exists"。
RB2=$(curl -s -b "$JAR" -X POST "$API_URL/passkey/register/begin")
DUP_CHALLENGE=$(echo "$RB2" | jq -r '.challenge')
DUP_OUT=$(RP_ID="$RP_ID" ORIGIN="$ORIGIN" CHALLENGE="$DUP_CHALLENGE" KEYFILE="$KEYFILE" CRED_ID_B64="$CRED_ID" python3 - <<'PY'
import os, json, base64, hashlib
from cryptography.hazmat.primitives import serialization
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def cbor_uint(m,n):
    if n<24: return bytes([m|n])
    if n<256: return bytes([m|24,n])
    if n<65536: return bytes([m|25])+n.to_bytes(2,'big')
    raise ValueError('len')
def enc(v):
    if isinstance(v,bool): raise ValueError('bool')
    if isinstance(v,int): return cbor_uint(0x00,v) if v>=0 else cbor_uint(0x20,-1-v)
    if isinstance(v,bytes): return cbor_uint(0x40,len(v))+v
    if isinstance(v,str): b=v.encode(); return cbor_uint(0x60,len(b))+b
    if isinstance(v,dict):
        o=cbor_uint(0xa0,len(v))
        for k,val in v.items(): o+=enc(k)+enc(val)
        return o
    raise ValueError('type')
rp_id=os.environ['RP_ID']; origin=os.environ['ORIGIN']; challenge=os.environ['CHALLENGE']
with open(os.environ['KEYFILE'],'rb') as f: key=serialization.load_pem_private_key(f.read(),password=None)
n=key.public_key().public_numbers(); x=n.x.to_bytes(32,'big'); y=n.y.to_bytes(32,'big')
cose=enc({1:2,3:-7,-1:1,-2:x,-3:y})
# 复用同一 credential_id(base64url decode 回字节)——触发 put_new 唯一性拒绝。
cred_id=base64.urlsafe_b64decode(os.environ['CRED_ID_B64']+'='*(-len(os.environ['CRED_ID_B64'])%4))
ad=hashlib.sha256(rp_id.encode()).digest()+bytes([0x45])+(0).to_bytes(4,'big')+bytes(16)+len(cred_id).to_bytes(2,'big')+cred_id+cose
att=enc({"fmt":"none","attStmt":{},"authData":ad})
cdj=json.dumps({"type":"webauthn.create","challenge":challenge,"origin":origin},separators=(',',':')).encode()
print(json.dumps({"client_data_json":b64u(cdj),"attestation_object":b64u(att)}))
PY
)
DUP_RF=$(curl -s -b "$JAR" -o /dev/null -w '%{http_code}' -X POST "$API_URL/passkey/register/finish" \
  -H "content-type: application/json" \
  -d "$(echo "$DUP_OUT" | jq -c --arg c "$DUP_CHALLENGE" '{challenge:$c, client_data_json, attestation_object}')")
[ "$DUP_RF" = "400" ] || { echo "❌ 同 credential_id 二次注册未 400(got $DUP_RF;put_new 唯一性拒绝断链)"; exit 1; }
echo "  ✅ credentialId 唯一拒覆盖(400,attribute_not_exists 条件写)"

echo "== 5. GSI user_id-index 反查命中(list_by_user 路径,begin 的 allow/excludeCredentials 靠它)=="
# GSI 恒最终一致(无法 consistent-read);retry-with-backoff 等传播,免假失败(评审 Kiro M2)。
GSI_OK=""
for attempt in 1 2 3 4 5; do
  Q=$("${AWSQ[@]}" dynamodb query --table-name "$PASSKEY_TABLE" --index-name user_id-index \
    --key-condition-expression "user_id = :u" \
    --expression-attribute-values "{\":u\":{\"S\":\"$RESP_UID\"}}")
  if echo "$Q" | CRED="$CRED_ID" python3 -c "
import sys,json,os
items=json.load(sys.stdin).get('Items',[])
sys.exit(0 if any(i['credential_id']['S']==os.environ['CRED'] for i in items) else 1)
"; then GSI_OK=1; CNT=$(echo "$Q" | jq '.Items|length'); break; fi
  sleep $((attempt))
done
[ -n "$GSI_OK" ] || { echo "❌ GSI user_id-index 未反查到刚注册凭证(5 次重试后仍无)"; exit 1; }
echo "  ✅ GSI user_id-index 反查命中($CNT 条)"

echo "== 6. authenticate/begin(login_hint)→ allowCredentials 含刚注册 =="
AB=$(curl -s "$API_URL/passkey/authenticate/begin?login_hint=$EMAIL")
AUTH_CHALLENGE=$(echo "$AB" | jq -r '.challenge')
if [ -z "$AUTH_CHALLENGE" ] || [ "$AUTH_CHALLENGE" = "null" ]; then
  echo "❌ authenticate/begin 无 challenge: $AB"
  exit 1
fi
echo "$AB" | CRED="$CRED_ID" python3 -c "
import sys,json,os
d=json.load(sys.stdin)
allow=d.get('allow_credentials',[])
assert os.environ['CRED'] in allow, 'allowCredentials 未含刚注册凭证(GSI 反查断链): %r' % allow
print('  ✅ allowCredentials 含刚注册凭证')
"

# 造 assertion 的辅助:给定 challenge + signCount → 输出 {client_data_json, authenticator_data, signature}。
# SIGN_COUNT 经 env 参数化(step 7 用 1 正常递增;step 8b 用 1 造不递增触发 CAS 回退拒绝)。
mk_assertion() {  # $1=challenge $2=sign_count
  RP_ID="$RP_ID" ORIGIN="$ORIGIN" CHALLENGE="$1" SIGN_COUNT="$2" KEYFILE="$KEYFILE" python3 - <<'PY'
import os, json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
rp_id = os.environ['RP_ID']; origin = os.environ['ORIGIN']; challenge = os.environ['CHALLENGE']
with open(os.environ['KEYFILE'], 'rb') as f:
    key = serialization.load_pem_private_key(f.read(), password=None)
rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
flags = bytes([0x05])                                # UP|UV(无 AT)
sign_count = int(os.environ['SIGN_COUNT']).to_bytes(4, 'big')
auth_data = rp_id_hash + flags + sign_count
cdj = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin},
                 separators=(',', ':')).encode()
sig = key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))  # DER ES256
print(json.dumps({"client_data_json": b64u(cdj), "authenticator_data": b64u(auth_data),
                  "signature": b64u(sig)}))
PY
}

echo "== 7. 造 assertion(signCount 0→1)+ authenticate/finish 登入(amr=webauthn)=="
AUTH_OUT=$(mk_assertion "$AUTH_CHALLENGE" 1)
AF_BODY=$(echo "$AUTH_OUT" | jq -c --arg c "$AUTH_CHALLENGE" --arg id "$CRED_ID" \
  '{challenge:$c, credential_id:$id, client_data_json, authenticator_data, signature}')
AF=$(curl -s -c "$AF_JAR" -o "$AF_BODY_FILE" -w '%{http_code}' -X POST "$API_URL/passkey/authenticate/finish" \
  -H "content-type: application/json" -d "$AF_BODY")
[ "$AF" = "200" ] || { echo "❌ authenticate/finish 未 200(got $AF):$(cat "$AF_BODY_FILE")"; exit 1; }
grep -q "__Host-agent_auth_session" "$AF_JAR" || { echo "❌ 未建 passkey 会话 cookie"; exit 1; }
grep -q '"authenticated":true' "$AF_BODY_FILE" || { echo "❌ 响应非 authenticated:true"; exit 1; }
echo "  ✅ authenticate/finish 200;建 passkey 会话(amr=webauthn)"

echo "== 8. 断言 signCount CAS 已回写(0→1;真机 UpdateItem 条件,--consistent-read)=="
# 断言两处一致回写:顶层 sign_count(N,CAS 条件依据)与 cred_json 内嵌值(from_item 真相源)。
# --consistent-read 免最终一致读到回写前旧值致假失败(评审 Kiro M2)。
"${AWSQ[@]}" dynamodb get-item --table-name "$PASSKEY_TABLE" --consistent-read \
  --key "{\"credential_id\":{\"S\":\"$CRED_ID\"}}" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)['Item']
top=int(d['sign_count']['N'])
emb=json.loads(d['cred_json']['S'])['sign_count']
assert top==1, 'top-level sign_count 未回写为 1(got %s;CAS 断链)'%top
assert emb==1, 'cred_json 内嵌 sign_count 未回写为 1(got %s;json 与顶层不一致)'%emb
print('  ✅ signCount CAS 回写 0→1(顶层 N 与 cred_json 一致)')
"

echo "== 8b. signCount CAS **回退拒绝**路径:新 challenge + 不递增 signCount(仍 1)→ 400 =="
# 用**新有效 challenge**(过 challenge 一次性闸)+ signCount 不严格递增(仍 1,当前库内已 1)→ 验签会过、
# challenge 会过,但 verify_assertion 的 counter 递增闸拒(CounterNotIncreasing)→ 400。这覆盖内存适配器
# 也测不到、且被 step 9 challenge 一次性顺序遮蔽的"克隆/回退检测"分支(评审 Kiro M3;codex#3)。
AB2=$(curl -s "$API_URL/passkey/authenticate/begin?login_hint=$EMAIL")
CAS_CHALLENGE=$(echo "$AB2" | jq -r '.challenge')
CAS_OUT=$(mk_assertion "$CAS_CHALLENGE" 1)   # signCount 仍 1(不 > 库内 1)→ 应拒
CAS_BODY=$(echo "$CAS_OUT" | jq -c --arg c "$CAS_CHALLENGE" --arg id "$CRED_ID" \
  '{challenge:$c, credential_id:$id, client_data_json, authenticator_data, signature}')
CAS_RE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/passkey/authenticate/finish" \
  -H "content-type: application/json" -d "$CAS_BODY")
[ "$CAS_RE" = "400" ] || { echo "❌ 不递增 signCount 未 400(got $CAS_RE;counter 回退/克隆检测断链)"; exit 1; }
# 且确认库内 signCount 仍 1(拒绝路径**没有**误写)。
"${AWSQ[@]}" dynamodb get-item --table-name "$PASSKEY_TABLE" --consistent-read \
  --key "{\"credential_id\":{\"S\":\"$CRED_ID\"}}" \
  | python3 -c "
import sys,json
top=int(json.load(sys.stdin)['Item']['sign_count']['N'])
assert top==1, '拒绝路径误写 signCount(应仍 1,got %s)'%top
print('  ✅ 不递增 signCount 被拒(400);库内 signCount 仍 1(无误写)')
"

echo "== 9. challenge 重放:同 step7 challenge 二次 authenticate/finish → 400 且**错因是 challenge 失效** =="
# 复用 step7 的 AF_BODY(其 challenge 首次已被 consume 删除)。仅断 400 不够——400 也可能来自 signCount 等
# 其它闸,会掩盖"challenge 一次性其实失效"(评审 codex#3)。故断响应体错因含 "challenge",隔离一次性 consume。
RE_BODY_FILE="$(mktemp)"
RE=$(curl -s -o "$RE_BODY_FILE" -w '%{http_code}' -X POST "$API_URL/passkey/authenticate/finish" \
  -H "content-type: application/json" -d "$AF_BODY")
[ "$RE" = "400" ] || { echo "❌ challenge 重放未 400(got $RE;一次性 consume 断链)"; rm -f "$RE_BODY_FILE"; exit 1; }
grep -qi "challenge" "$RE_BODY_FILE" || {
  echo "❌ 重放 400 但错因非 challenge($(cat "$RE_BODY_FILE"));无法确认是一次性 consume 生效(可能被其它闸掩盖)";
  rm -f "$RE_BODY_FILE"; exit 1; }
rm -f "$RE_BODY_FILE"
echo "  ✅ challenge 重放被拒(400,错因=challenge 失效,一次性 consume 隔离确认)"

echo "== 10. passkey session satisfies canonical strong and high-risk RAR step-up =="
"${AWSQ[@]}" dynamodb put-item --table-name "$CLIENTS_TABLE" --item \
  "{\"client_id\":{\"S\":\"$STEP_UP_CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$STEP_UP_REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}"
STEP_VERIFIER="0123456789012345678901234567890123456789abc"
STEP_CHALLENGE="$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$STEP_VERIFIER'.encode()).digest()).rstrip(b'=').decode())")"

assert_consent_redirect() {
  local state="$1" acr="$2" rar="${3:-}" headers body status location
  headers="$(mktemp)"
  body="$(mktemp)"
  local -a args=(
    -sS -b "$AF_JAR" -D "$headers" -o "$body" -w '%{http_code}' -G
    "$API_URL/authorize"
    --data-urlencode "response_type=code"
    --data-urlencode "client_id=$STEP_UP_CLIENT"
    --data-urlencode "redirect_uri=$STEP_UP_REDIRECT"
    --data-urlencode "code_challenge=$STEP_CHALLENGE"
    --data-urlencode "code_challenge_method=S256"
    --data-urlencode "scope=openid"
    --data-urlencode "state=$state"
    --data-urlencode "acr_values=$acr"
  )
  if [ -n "$rar" ]; then
    args+=(--data-urlencode "authorization_details=$rar")
  fi
  status="$(curl "${args[@]}")"
  location="$(awk 'BEGIN{IGNORECASE=1} /^location:/{sub(/\r$/,""); print substr($0,11)}' "$headers" | tail -1)"
  rm -f "$headers" "$body"
  if [ "$status" != "303" ] || ! printf '%s' "$location" | grep -q '/consent?'; then
    echo "❌ passkey strong step-up 未进入 consent(status=$status,location=$location)"
    exit 1
  fi
  if printf '%s' "$location" | grep -q '/login?'; then
    echo "❌ passkey strong step-up 错误回落登录"
    exit 1
  fi
  return 0
}

assert_consent_redirect \
  "passkey-explicit-strong" \
  "urn:agent-auth:assurance:strong"
echo "  ✅ canonical strong acr_values 由 passkey 会话满足"

assert_consent_redirect \
  "passkey-high-risk-rar" \
  "urn:agent-auth:assurance:baseline" \
  '[{"type":"agent_auth_rar_v1","actions":["transfer"]}]'
echo "  ✅ high-risk transfer RAR 将 baseline 请求提升为 strong，passkey 会话满足"

echo "✅ spec 003 §3 passkey 仪式真机 e2e 全绿"
echo "   覆盖:put_new 落库 + **唯一性拒绝(4b)** / GSI 反查(重试稳态)/ signCount CAS 回写(8)+ **回退拒绝(8b)** /"
echo "   challenge 一次性(错因隔离,9)/ canonical strong + high-risk RAR step-up(10);"
echo "   secret 只经 file://、F10 原 env 全量恢复带断言+重试+保留备份。"

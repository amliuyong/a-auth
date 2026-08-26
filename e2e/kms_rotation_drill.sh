#!/usr/bin/env bash
# KMS 签名 key 两相优雅轮换(C10.11b)+ 紧急吊销(C10.12)**演练/预检脚本**(spec 005 §8)。
#
# 真机三相轮换须**创建多把 KMS CMK + 改 IAM + 分阶段部署 + 等 max-age/TTL 重叠期**——**不可**一键安全自动跑完
# (会真改现网签名行为、创建计费 CMK、须人工掌控相位时长)。故本脚本三段,默认**只读预检 + 打印运维命令、不执行**:
#   A. 只读预检:身份 / signing key 的 KeySpec 同质(EC=ECC_NIST_P256、RSA=RSA_*)/ 当前 JWKS EC+RSA key 数 +
#      Cache-Control max-age / AuthFn 的 SIGNING_KEY_IDS_PUBLISHED 现状。
#   B. 无停机基线验证:取一枚**活跃 key 签的真 access token**(走 code flow),用**当前 /jwks.json** 公钥独立验签
#      通过——坐实"签名 key ∈ 已发布 JWKS"(轮换无停机的基本前提;单 key 现状下即活跃 key 在 JWKS)。
#   C. 打印**三相轮换 + 紧急吊销的精确运维命令**(创建 CMK / 加 IAM / 改 env 分阶段部署 / 等相位 / CloudFront
#      invalidate)——**不执行**,须运维按 max-age/TTL 掌控相位时长手动照做(会改现网签名,不进自动化)。
#
# 用法(默认只读预检 + 打印命令,不改现网):
#   API_URL=https://<apigw> CLIENTS_TABLE=<..> AUTH_FN=<AuthFn 名> \
#   [EC_KEY_ID=<..> RSA_KEY_ID=<..>] [CLOUDFRONT_DIST_ID=<..>] AWS_PROFILE=default REGION=us-east-1 \
#   ./e2e/kms_rotation_drill.sh
#
# **真机轮换演练(EXECUTE=1,仅 dev 栈!)**:默认实跑 publish-ahead→切签名并保留旧 key,
#   全程改 dev 栈 Lambda 的 signing env(仅用于瞬时演练;生产相位必须由 CDK 配置持久化;**全程可逆**:
#   trap 恢复原始 env + schedule-delete 新 CMK + 移除临时 IAM inline policy + 删演练 client)。每相验证无停机
#   (旧 key 签的 token 在重叠期仍验签通过;切签名后新 key 签的 token 也验签通过)。graceful retire
#   只有 RETIRE_AFTER_WAIT=1 且等待 ≥86400 秒才执行,覆盖 SSF immutable SET 的绝对 freshness 窗口。
#   独立事故演练用 EMERGENCY_REVOKE=1:切签名后立即把 published 收成仅新 key、等待 CloudFront
#   /jwks.json invalidation 完成并断言旧 token 失败,不经过 graceful retire 等待。
#   **MUST 只对 dev 栈跑**——
#   会真改签名 key + 创建计费 CMK(7 天 pending 删除窗)。用法:
#   EXECUTE=1 AUTH_FN=<..> SSF_FN=<SsfDeliveryFn 名> CLOUDFRONT_DIST_ID=<..> \
#     API_URL=.. CLIENTS_TABLE=.. AWS_PROFILE=default ./e2e/kms_rotation_drill.sh
#
# 依赖:aws cli、python3(+PyJWT/cryptography 独立验签)、curl、jq。默认**只读**;EXECUTE=1 才改现网 key/env(可逆)。
set -euo pipefail

API_URL="${API_URL:?需 API_URL(CloudFront/apigw 域,如 https://xxx.execute-api...)}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE(栈输出 ClientsTableName;B 段 seed client 用)}"
AUTH_FN="${AUTH_FN:-}"                 # 主 AuthFn 名(可选;给了则查 signing env + KeySpec)
SSF_FN="${SSF_FN:-}"                   # SSF DeliveryFn 名(轮换时必须与 AuthFn 同相位)
EC_KEY_ID="${EC_KEY_ID:-}"            # 活跃 EC signing key id(可选;给了则查 KeySpec)
RSA_KEY_ID="${RSA_KEY_ID:-}"          # 活跃 RSA signing key id(可选)
CLOUDFRONT_DIST_ID="${CLOUDFRONT_DIST_ID:-<cloudfront-dist-id>}"
EXECUTE="${EXECUTE:-0}"                 # 1 = 真机执行三相演练(仅 dev 栈!默认 0 = 只读)
RETIRE_AFTER_WAIT="${RETIRE_AFTER_WAIT:-0}" # 1 = 切签名后等待完整窗口并 retire
RETIRE_WAIT_SECS="${RETIRE_WAIT_SECS:-86400}" # 至少覆盖 SSF 原 SET iat 后 24 小时
EMERGENCY_REVOKE="${EMERGENCY_REVOKE:-0}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")
HERE="$(cd "$(dirname "$0")" && pwd)"
HOST="${API_URL#https://}"; HOST="${HOST%%/*}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"
ROTATION_OPERATION_ID="kms_rotation_$(date +%s)_$$"
ROTATION_PHASE=""
ROTATION_STARTED=0
OLD_KID=""
NEW_KID=""

echo "=============================================================="
echo " KMS 签名 key 轮换 / 紧急吊销 演练(默认只读预检 + 打印命令,不执行)"
echo "=============================================================="

# ── A. 只读预检 ───────────────────────────────────────────────
echo ""
echo "== A. 只读预检 =="
echo "-- A0 身份 --"
"${AWSQ[@]}" sts get-caller-identity --query 'Arn' --output text

# KeySpec 同质校验(spec 005 §8 评审 H1:轮换发布集须全 P-256 EC / 全 RSA,防 alg 混淆)。
check_keyspec() {  # $1=key_id $2=expect-substr(ECC_NIST_P256 | RSA) $3=label
  local ks
  ks=$("${AWSQ[@]}" kms describe-key --key-id "$1" --query 'KeyMetadata.KeySpec' --output text 2>&1) || {
    echo "   ⚠ $3 DescribeKey 失败(无权限或 key 不存在):$ks"; return; }
  if echo "$ks" | grep -q "$2"; then
    echo "   ✅ $3 KeySpec=$ks(符合 $2;KmsSigner 构造期同质校验通过)"
  else
    echo "   ❌ $3 KeySpec=$ks 不符 $2 —— 发布集混入会致 alg 混淆(C10.15a),KmsSigner 会 fail-closed 拒启动"
  fi
}
echo "-- A1 signing key KeySpec 同质 --"
[ -n "$EC_KEY_ID" ] && check_keyspec "$EC_KEY_ID" "ECC_NIST_P256" "活跃 EC" || echo "   (未传 EC_KEY_ID,跳过 EC KeySpec 检查)"
[ -n "$RSA_KEY_ID" ] && check_keyspec "$RSA_KEY_ID" "RSA" "活跃 RSA" || echo "   (未传 RSA_KEY_ID,跳过 RSA KeySpec 检查)"

echo "-- A2 当前 /jwks.json:EC + RSA key 数 + kid + Cache-Control --"
JWKS=$(curl -s "$API_URL/jwks.json" -H "host: $HOST")
echo "$JWKS" | python3 -c "
import sys,json
d=json.load(sys.stdin); keys=d.get('keys',[])
ec=[k for k in keys if k.get('kty')=='EC']; rsa=[k for k in keys if k.get('kty')=='RSA']
print('   EC 已发布:%d 把 kids=%s'%(len(ec),[k.get('kid','')[:12] for k in ec]))
print('   RSA 已发布:%d 把 kids=%s'%(len(rsa),[k.get('kid','')[:12] for k in rsa]))
print('   (轮换重叠期这里应见新旧两把;单 key 现状 = 各 1 把)')
"
MAXAGE=$(curl -s -D - "$API_URL/jwks.json" -H "host: $HOST" -o /dev/null | grep -i "cache-control" | grep -oE "max-age=[0-9]+" | head -1)
echo "   Cache-Control: ${MAXAGE:-(缺!)} —— publish-ahead 须等 ≥ 2×此值(或 publish-ahead 时也 CloudFront invalidate,评审 H2)"

if [ -n "$AUTH_FN" ]; then
  echo "-- A3 AuthFn signing env(轮换靠改这些 env 分阶段部署)--"
  "${AWSQ[@]}" lambda get-function-configuration --function-name "$AUTH_FN" \
    --query 'Environment.Variables.[SIGNING_KEY_ID,SIGNING_KEY_IDS_PUBLISHED,RSA_SIGNING_KEY_ID,RSA_SIGNING_KEY_IDS_PUBLISHED]' \
    --output json 2>&1 | python3 -c "
import sys,json
v=json.load(sys.stdin)
labels=['SIGNING_KEY_ID(活跃 EC)','SIGNING_KEY_IDS_PUBLISHED(EC 发布集)','RSA_SIGNING_KEY_ID(活跃 RSA)','RSA_SIGNING_KEY_IDS_PUBLISHED(RSA 发布集)']
for l,x in zip(labels,v): print('   %s = %s'%(l, x if x is not None else '(未配 → 退化单 key,字节等价现状)'))
"
fi
if [ -n "$SSF_FN" ]; then
  echo "-- A4 SsfDeliveryFn signing env(必须与 AuthFn 的 EC 相位一致)--"
  "${AWSQ[@]}" lambda get-function-configuration --function-name "$SSF_FN" \
    --query 'Environment.Variables.[SIGNING_KEY_ID,SIGNING_KEY_IDS_PUBLISHED]' \
    --output json 2>&1 | python3 -c "
import sys,json
v=json.load(sys.stdin)
labels=['SIGNING_KEY_ID(活跃 EC)','SIGNING_KEY_IDS_PUBLISHED(EC 发布集)']
for l,x in zip(labels,v): print('   %s = %s'%(l, x if x is not None else '(未配 → 退化单 key)'))
"
fi

# ── B. 无停机基线验证 ─────────────────────────────────────────
echo ""
echo "== B. 无停机基线验证:活跃 key 签的 token 用当前 JWKS 验签通过 =="
echo "   委托 e2e/code_flow.sh(走 code flow 拿活跃 key 签的 access token → 用 /jwks.json 公钥独立验签)。"
echo "   这坐实'签名 key ∈ 已发布 JWKS'——轮换无停机的基本不变量(切签名后新 key 也须在 JWKS,同理)。"
if API_URL="$API_URL" CLIENTS_TABLE="$CLIENTS_TABLE" AWS_PROFILE="$PROFILE" REGION="$REGION" \
     bash "$HERE/code_flow.sh" >/tmp/kms_drill_cf.log 2>&1; then
  echo "   ✅ 活跃 key 签的 access token 用当前 JWKS 独立验签通过(无停机前提成立)"
  grep -E "独立验签通过|全绿" /tmp/kms_drill_cf.log | tail -2 | sed 's/^/     /'
else
  echo "   ❌ code_flow 基线验签失败——轮换前置不成立,须先排查(见 /tmp/kms_drill_cf.log)"
  tail -5 /tmp/kms_drill_cf.log | sed 's/^/     /'
  rm -f /tmp/kms_drill_cf.log; exit 1
fi
rm -f /tmp/kms_drill_cf.log

# ── C. 打印运维命令(不执行)───────────────────────────────────
echo ""
echo "== C. 三相轮换 + 紧急吊销运维命令(**不执行**;运维按 max-age/TTL 掌控相位,手动照做)=="
AWSC="aws --profile $PROFILE --region $REGION"  # 命令前缀(纯字符串,heredoc 里可直接粘贴)
cat <<EOF
   前提:A1 KeySpec 同质 ✅、A2 当前 JWKS 正常、B 基线验签通过。轮换全程 KmsSigner 构造期会校验
   active∈published / KeySpec 同质 / GetPublicKey(active 硬失败、非active permanent失败/transient重试/绝不skip)。

   ── 优雅轮换(C10.11b,三相,每相一次部署)──
   0) 置备新 EC signing CMK(ECC_NIST_P256),记录旧/新 key ARN:
        NEW=\$($AWSC kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY --query KeyMetadata.KeyId --output text)
        # Dev 用 DEV_EC_SIGNING_KEY_ARN / DEV_EC_SIGNING_KEY_ARNS_PUBLISHED;
        # SaaS 用 SAAS_EC_SIGNING_KEY_ARN / SAAS_EC_SIGNING_KEY_ARNS_PUBLISHED。
        # CDK 自动让 AuthFn 与 SsfDeliveryFn 同相位:Sign 仅 active,GetPublicKey 覆盖 published。

	   1) publish-ahead(仍用旧 key 签,新 key 进 JWKS):部署时设
        <STACK>_EC_SIGNING_KEY_ARN=<旧 ARN>
        <STACK>_EC_SIGNING_KEY_ARNS_PUBLISHED=<旧 ARN>,<新 ARN>
        npx cdk deploy <stack> --profile $PROFILE
      **等 ≥ 2×max-age(${MAXAGE:-max-age=300})**(CDN+朴素RS缓存叠加,评审 H2);或此刻也 invalidate:
        $AWSC cloudfront create-invalidation --distribution-id $CLOUDFRONT_DIST_ID --paths '/jwks.json'
	      验:A2 应见 EC 2 把 kid。
	      使用受鉴权的 POST /admin/ssf/signing-key-rotations 记录 phase=publish_ahead、
	      old_kid/new_kid、result 和 operation_id；服务端从 admin 凭证绑定操作者并拒绝 key ARN。

   2) 切签名(新旧都可验,改用新 key 签):
        <STACK>_EC_SIGNING_KEY_ARN=<新 ARN>
        <STACK>_EC_SIGNING_KEY_ARNS_PUBLISHED=<旧 ARN>,<新 ARN>
        npx cdk deploy <stack> --profile $PROFILE
	      验:B 基线 code_flow 仍验签通过(新 key 签的 token ∈ JWKS)。
	      同样记录 phase=activate 的 canonical security event。

   3) retire(从最后一个旧 key 签名时刻起,同时满足 OAuth token expiry 和
      SSF SET iat+86400 秒,再加时钟偏移余量;不能只等 access/ID token TTL):
        <STACK>_EC_SIGNING_KEY_ARN=<新 ARN>
        <STACK>_EC_SIGNING_KEY_ARNS_PUBLISHED=<新 ARN>
        npx cdk deploy <stack> --profile $PROFILE
	      验:A2 应只剩新 EC kid;旧 key 签的存量 token 已全过期。
	      同样记录 phase=retire 的 canonical security event。

   ── 紧急吊销(C10.12,重叠期=0,事故)──
   * 从 PUBLISHED 移除泄露 ARN(若它是活跃,同时把 SIGNING_KEY_ID 切到未泄露的新 key)重部署:
        SIGNING_KEY_ID=\$NEW  SIGNING_KEY_IDS_PUBLISHED=\$NEW        (cdk deploy)
   * **MUST** CloudFront invalidate /jwks.json(否则新取 RS 仍从 CDN 拿含泄露 key 的旧 JWKS 整个 TTL):
        $AWSC cloudfront create-invalidation --distribution-id $CLOUDFRONT_DIST_ID --paths '/jwks.json'
   * 诚实限界:AS 内部校验随 rollout 秒级收敛;**离线缓存 JWKS 的 RS 上界 = JWKS max-age + 时钟偏移**
     (非泄露 token 剩余 TTL;unknown-kid 重取不触发,因 kid 仍在缓存 JWKS)。更低 max-age 是唯一收紧杠杆。
   * RSA id_token 轮换/吊销同构(RSA_SIGNING_KEY_ID + RSA_SIGNING_KEY_IDS_PUBLISHED)。
EOF

if [ "$EXECUTE" != "1" ]; then
  echo ""
  echo "🎉 KMS 轮换演练完成(A 预检 + B 无停机基线验签通过;C 运维命令已打印,未执行)。"
  echo "   真机三相轮换 / 紧急吊销请照 C 段手动执行,或 EXECUTE=1(仅 dev 栈)自动跑可逆演练。"
  exit 0
fi

# ── D. 真机三相无停机演练(EXECUTE=1,仅 dev 栈;全程可逆)─────────────────
echo ""
echo "=============================================================="
echo " D. 真机三相无停机演练(EXECUTE=1)—— 改 dev 栈 signing env,全程可逆"
echo "=============================================================="
[ -n "$AUTH_FN" ] || { echo "❌ EXECUTE=1 须给 AUTH_FN(主 Lambda 名)"; exit 1; }
[ -n "$SSF_FN" ] || { echo "❌ EXECUTE=1 须给 SSF_FN(SSF Delivery Lambda 名)"; exit 1; }
if [ "$EMERGENCY_REVOKE" = "1" ] && [ "$RETIRE_AFTER_WAIT" = "1" ]; then
  echo "❌ EMERGENCY_REVOKE=1 and RETIRE_AFTER_WAIT=1 are mutually exclusive"
  exit 1
fi
if [ "$EMERGENCY_REVOKE" = "1" ] && [ "$CLOUDFRONT_DIST_ID" = "<cloudfront-dist-id>" ]; then
  echo "❌ EMERGENCY_REVOKE=1 须给 CLOUDFRONT_DIST_ID"
  exit 1
fi
if [ -z "$ADMIN_TOKEN" ]; then
  ADMIN_TOKEN=$(STACK=AgentAuthDev REGION="$REGION" PROFILE="$PROFILE" \
    "$HERE/get-admin-token.sh")
fi
[ -n "$ADMIN_TOKEN" ] || { echo "❌ EXECUTE=1 须可取得 Dev ADMIN_TOKEN"; exit 1; }
ROLE_ARN=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$AUTH_FN" --query 'Role' --output text)
ROLE_NAME="${ROLE_ARN##*/}"
SSF_ROLE_ARN=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$SSF_FN" --query 'Role' --output text)
SSF_ROLE_NAME="${SSF_ROLE_ARN##*/}"
ACCOUNT=$("${AWSQ[@]}" sts get-caller-identity --query Account --output text)
# 记录原始 signing env(结束恢复)。null → 空串。
ORIG_EC=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$AUTH_FN" --query 'Environment.Variables.SIGNING_KEY_ID' --output text)
ORIG_EC_PUB=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$AUTH_FN" --query 'Environment.Variables.SIGNING_KEY_IDS_PUBLISHED' --output text 2>/dev/null)
[ "$ORIG_EC_PUB" = "None" ] && ORIG_EC_PUB=""
ORIG_SSF_EC=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$SSF_FN" --query 'Environment.Variables.SIGNING_KEY_ID' --output text)
ORIG_SSF_EC_PUB=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$SSF_FN" --query 'Environment.Variables.SIGNING_KEY_IDS_PUBLISHED' --output text 2>/dev/null)
[ "$ORIG_SSF_EC_PUB" = "None" ] && ORIG_SSF_EC_PUB=""
echo "   Auth 原始:SIGNING_KEY_ID=$ORIG_EC  PUBLISHED='${ORIG_EC_PUB:-（未配=退化单key）}'"
echo "   SSF  原始:SIGNING_KEY_ID=$ORIG_SSF_EC  PUBLISHED='${ORIG_SSF_EC_PUB:-（未配=退化单key）}'"
[ "$ORIG_EC" = "$ORIG_SSF_EC" ] ||
  { echo "❌ Auth/SSF active EC key 已漂移,轮换前须先收敛"; exit 1; }
NEW_KEY=""; AUTH_POLICY_ADDED=""; SSF_POLICY_ADDED=""

# 改主 Lambda 的 EC signing env(SIGNING_KEY_ID / SIGNING_KEY_IDS_PUBLISHED)并等 update 收敛。
# 用 **JSON**(`--environment file://`)而非 shorthand `Variables={K=V,..}`:published CSV 值含逗号,
# shorthand 以逗号分隔键值对会解析炸(实测)。JSON 也避免 secret 值回显到终端。
set_function_signing_env() {  # $1=function $2=active $3=published-csv(可空)
  local envjson; envjson=$(mktemp)
  build_env_json "$1" "$2" "$3" >"$envjson"
  "${AWSQ[@]}" lambda update-function-configuration --function-name "$1" \
    --environment "file://$envjson" >/dev/null
  "${AWSQ[@]}" lambda wait function-updated --function-name "$1"
  rm -f "$envjson"
}
set_signing_env() {  # $1=active $2=published-csv
  set_function_signing_env "$AUTH_FN" "$1" "$2"
  set_function_signing_env "$SSF_FN" "$1" "$2"
}
# 构造完整 env 变更集:只覆盖 SIGNING_KEY_ID / SIGNING_KEY_IDS_PUBLISHED,其余 env **原样保留**
# (update-function-configuration 的 Environment 全替换,须回读合并;漏则 fail-closed 缺表拒启动)。
# 输出 `{"Variables":{...}}` JSON(update-function-configuration --environment 接受的结构)。
build_env_json() {  # $1=function $2=active $3=pub → 回读全 env、覆盖两键、输出 JSON
  "${AWSQ[@]}" lambda get-function-configuration --function-name "$1" \
    --query 'Environment.Variables' --output json | python3 -c "
import sys,json
env=json.load(sys.stdin)
env['SIGNING_KEY_ID']='$2'
if '$3': env['SIGNING_KEY_IDS_PUBLISHED']='$3'
else: env.pop('SIGNING_KEY_IDS_PUBLISHED', None)
print(json.dumps({'Variables':env}))
"
}

# 取一枚活跃 key 现签的 access token(走 code flow;返回 token 串)。
mint_token() {
  local cf_log; cf_log=$(mktemp)
  API_URL="$API_URL" CLIENTS_TABLE="$CLIENTS_TABLE" AWS_PROFILE="$PROFILE" REGION="$REGION" \
    bash "$HERE/code_flow.sh" >"$cf_log" 2>&1 || { echo "MINT_FAIL"; cat "$cf_log" >&2; rm -f "$cf_log"; return; }
  rm -f "$cf_log"
  # code_flow 内部已独立验签;此处再单独 mint 一枚裸 token 供跨相验签(直接 authorize+token)。
  local verifier challenge loc code
  verifier="0123456789012345678901234567890123456789abc"
  challenge=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$verifier'.encode()).digest()).rstrip(b'=').decode())")
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$API_URL/authorize?response_type=code&client_id=e2e-client&redirect_uri=http://127.0.0.1/cb&code_challenge=$challenge&code_challenge_method=S256&scope=openid&login_user=alice")
  code="${loc##*code=}"
  code="${code%%&*}"
  curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$code&code_verifier=$verifier&redirect_uri=http://127.0.0.1/cb&client_id=e2e-client" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"
}

# 用当前 /jwks.json 独立验签一枚 token(EC/ES256);成功打印 kid,失败非零退出。
verify_token() {  # $1=token $2=label
  local jwks; jwks=$(curl -s "$API_URL/jwks.json" -H "host: $HOST")
  echo "$1" | python3 -c "
import sys,json,jwt as pyjwt
from jwt import algorithms
tok=sys.stdin.read().strip()
jwks=json.loads('''$jwks''')
hdr=pyjwt.get_unverified_header(tok); kid=hdr['kid']
ks=[k for k in jwks['keys'] if k.get('kid')==kid and k.get('kty')=='EC']
assert ks, ('$2: 签名 kid %s 不在当前 JWKS(停机!)'%kid[:12], [k.get('kid','')[:12] for k in jwks['keys']])
key=algorithms.ECAlgorithm.from_jwk(json.dumps(ks[0]))
c=pyjwt.decode(tok,key=key,algorithms=['ES256'],audience='$API_URL/userinfo',options={'verify_exp':False})
print('   ✅ $2:kid=%s ∈ JWTS,验签通过(无停机)'%kid[:12])
"
}

token_kid() {
  echo "$1" | python3 -c "
import sys,jwt
print(jwt.get_unverified_header(sys.stdin.read().strip())['kid'])
"
}

kms_ec_kid() {
  "${AWSQ[@]}" kms get-public-key --key-id "$1" --query PublicKey --output text |
    python3 -c "
import base64,hashlib,json,sys
from cryptography.hazmat.primitives.serialization import load_der_public_key

der=base64.b64decode(sys.stdin.read().strip())
numbers=load_der_public_key(der).public_numbers()
b64=lambda value: base64.urlsafe_b64encode(value).rstrip(b'=').decode()
jwk={
  'crv':'P-256',
  'kty':'EC',
  'x':b64(numbers.x.to_bytes(32,'big')),
  'y':b64(numbers.y.to_bytes(32,'big')),
}
canonical=json.dumps(jwk,sort_keys=True,separators=(',',':')).encode()
print(b64(hashlib.sha256(canonical).digest()))
"
}

audit_rotation() { # $1=phase $2=old-kid $3=new-kid $4=result
  local phase="$1" old_kid="$2" new_kid="$3" result="$4"
  local header payload response status
  header=$(mktemp)
  response=$(mktemp)
  printf 'authorization: Bearer %s\ncontent-type: application/json\n' "$ADMIN_TOKEN" >"$header"
  chmod 0600 "$header"
  payload=$(python3 - "$phase" "$old_kid" "$new_kid" "$result" \
    "$ROTATION_OPERATION_ID" <<'PY'
import json,sys
phase,old_kid,new_kid,result,operation_id=sys.argv[1:]
print(json.dumps({
    "phase": phase,
    "old_kid": old_kid,
    "new_kid": new_kid,
    "result": result,
    "operation_id": operation_id,
}, separators=(",", ":")))
PY
)
  status=$(curl -sS --proto '=https' --connect-timeout 5 --max-time 20 \
    -o "$response" -w '%{http_code}' -X POST -H "@$header" -d "$payload" \
    "$API_URL/admin/ssf/signing-key-rotations") || status=000
  rm -f "$header"
  if [ "$status" != "201" ]; then
    echo "   ❌ 轮换 canonical audit 失败 phase=$phase HTTP $status: $(<"$response")" >&2
    rm -f "$response"
    return 1
  fi
  python3 - "$phase" "$old_kid" "$new_kid" "$result" "$response" <<'PY'
import json,sys
phase,old_kid,new_kid,result,response=sys.argv[1:]
with open(response, encoding="utf-8") as handle:
    event=json.load(handle)
assert event["action"] == f"key.signing.rotate.{phase}"
assert event["outcome"] == result
assert event["subject"]["id"] == new_kid
assert event["correlation"]["credential_id"] == old_kid
assert "arn:aws:kms" not in json.dumps(event)
print(f"   ✅ canonical audit phase={phase} event_id={event['event_id']}")
PY
  rm -f "$response"
}

run_emergency_revoke() {
  echo ""
  echo "== D.E 紧急吊销(重叠期=0:立即 published=new-only + CloudFront invalidate)=="
  ROTATION_PHASE="emergency_revoke"
  set_signing_env "$NEW_KEY" "$NEW_KEY"
  sleep 3

  local invalidation
  invalidation=$("${AWSQ[@]}" cloudfront create-invalidation \
    --distribution-id "$CLOUDFRONT_DIST_ID" --paths '/jwks.json' \
    --query 'Invalidation.Id' --output text)
  "${AWSQ[@]}" cloudfront wait invalidation-completed \
    --distribution-id "$CLOUDFRONT_DIST_ID" --id "$invalidation"
  echo "   ✅ CloudFront /jwks.json invalidation 已完成:$invalidation"

  local emergency_token
  emergency_token=$(mint_token)
  if [ "$emergency_token" = "MINT_FAIL" ] || [ -z "$emergency_token" ]; then
    echo "❌ 紧急吊销后 mint 失败"
    exit 1
  fi
  verify_token "$emergency_token" "紧急吊销:新 key 签的 token"
  curl -s "$API_URL/jwks.json" -H "host: $HOST" | python3 -c "
import json,sys
expected='$NEW_KID'
ec=[key for key in json.load(sys.stdin)['keys'] if key.get('kty') == 'EC']
assert len(ec) == 1, f'紧急吊销后 JWKS EC key 应==1,实得{len(ec)}'
assert ec[0].get('kid') == expected, '紧急吊销后 JWKS 未只保留新 EC key'
print(f'   ✅ 紧急吊销后 JWKS 仅剩新 EC kid={expected[:12]}')
"
  if verify_token "$TOK_OLD" "紧急吊销后旧 token(应失败)" 2>/dev/null; then
    echo "   ❌ 紧急吊销后旧 key token 仍验签通过"
    exit 1
  fi
  echo "   ✅ 未等待 graceful 窗口,旧 key token 已无法用当前 JWKS 验签"
  audit_rotation emergency_revoke "$OLD_KID" "$NEW_KID" success
}

# 清理:恢复原 env + schedule-delete 新 key + 移除临时 IAM + 删演练 client。幂等。
cleanup_drill() {
  local original_status=$?
  trap - EXIT
  echo ""
  echo "== D.cleanup 恢复现网(可逆)=="
  local restored=0
  set_function_signing_env "$AUTH_FN" "$ORIG_EC" "$ORIG_EC_PUB" 2>/dev/null || restored=1
  set_function_signing_env "$SSF_FN" "$ORIG_SSF_EC" "$ORIG_SSF_EC_PUB" 2>/dev/null || restored=1
  [ "$restored" = "0" ] && echo "   ✅ Auth/SSF signing env 已分别恢复原始值" ||
    echo "   ⚠ 恢复 env 失败,请手动核对 $AUTH_FN 与 $SSF_FN"
  if [ "$ROTATION_STARTED" = "1" ] && [ -n "$OLD_KID" ] && [ -n "$NEW_KID" ]; then
    if [ "$original_status" != "0" ] && [ -n "$ROTATION_PHASE" ]; then
      audit_rotation "$ROTATION_PHASE" "$OLD_KID" "$NEW_KID" failure ||
        echo "   ⚠ 轮换失败事件未能写入 canonical ledger"
    fi
    if [ "$restored" = "0" ]; then
      audit_rotation rollback "$NEW_KID" "$OLD_KID" success ||
        echo "   ⚠ rollback 事件未能写入 canonical ledger"
    fi
  fi
  if [ -n "$NEW_KEY" ]; then
    "${AWSQ[@]}" kms schedule-key-deletion --key-id "$NEW_KEY" --pending-window-in-days 7 >/dev/null 2>&1 \
      && echo "   ✅ 演练 CMK $NEW_KEY 已排期删除(7 天窗,可 cancel-key-deletion 撤销)" \
      || echo "   ⚠ schedule-key-deletion 失败,请手动删 $NEW_KEY"
  fi
  if [ -n "$AUTH_POLICY_ADDED" ]; then
    "${AWSQ[@]}" iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$AUTH_POLICY_ADDED" 2>/dev/null \
      && echo "   ✅ Auth 临时 IAM policy 已移除" || echo "   ⚠ 移除 Auth 临时 IAM 失败:$AUTH_POLICY_ADDED"
  fi
  if [ -n "$SSF_POLICY_ADDED" ]; then
    "${AWSQ[@]}" iam delete-role-policy --role-name "$SSF_ROLE_NAME" --policy-name "$SSF_POLICY_ADDED" 2>/dev/null \
      && echo "   ✅ SSF 临时 IAM policy 已移除" || echo "   ⚠ 移除 SSF 临时 IAM 失败:$SSF_POLICY_ADDED"
  fi
  # 最终无停机确认:恢复后再 mint+verify 一次(现网回到原始 key,仍应验签通过)。
  local t; t=$(mint_token)
  if [ -n "$t" ] && [ "$t" != "MINT_FAIL" ]; then verify_token "$t" "cleanup 后原始 key" || true; fi
  exit "$original_status"
}
trap cleanup_drill EXIT

echo ""
echo "== D.0 置备新 EC signing CMK(ECC_NIST_P256)+ 临时授 Lambda role kms:Sign/GetPublicKey =="
NEW_KEY=$("${AWSQ[@]}" kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --description "agent-auth EC rotation drill (transient, schedule-deleted)" \
  --query 'KeyMetadata.KeyId' --output text)
NEW_ARN="arn:aws:kms:$REGION:$ACCOUNT:key/$NEW_KEY"
NEW_KID=$(kms_ec_kid "$NEW_KEY")
echo "   新 CMK=$NEW_KEY"
echo "   新 kid=$NEW_KID"
AUTH_POLICY_ADDED="kms-rotation-drill-$NEW_KEY"
SSF_POLICY_ADDED="kms-rotation-drill-$NEW_KEY"
"${AWSQ[@]}" iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$AUTH_POLICY_ADDED" \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Sign\",\"kms:GetPublicKey\"],\"Resource\":\"$NEW_ARN\"}]}"
"${AWSQ[@]}" iam put-role-policy --role-name "$SSF_ROLE_NAME" --policy-name "$SSF_POLICY_ADDED" \
  --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"kms:Sign\",\"kms:GetPublicKey\"],\"Resource\":\"$NEW_ARN\"}]}"
echo "   ✅ Auth/SSF 临时 IAM inline policy 已加(仅本 CMK,不放宽到 *)"
sleep 8  # IAM 传播

TOK_BEFORE=$(mint_token)
if [ "$TOK_BEFORE" = "MINT_FAIL" ] || [ -z "$TOK_BEFORE" ]; then
  echo "❌ 轮换前 mint 失败"
  exit 1
fi
OLD_KID=$(token_kid "$TOK_BEFORE")

echo ""
echo "== D.1 publish-ahead(旧 key 签,新 key 进 JWKS)=="
ROTATION_PHASE="publish_ahead"
ROTATION_STARTED=1
set_signing_env "$ORIG_EC" "${ORIG_EC:+$ORIG_EC,}$NEW_KEY"
sleep 3
TOK_OLD=$(mint_token)
if [ "$TOK_OLD" = "MINT_FAIL" ] || [ -z "$TOK_OLD" ]; then
  echo "❌ publish-ahead 后 mint 失败"
  exit 1
fi
curl -s "$API_URL/jwks.json" -H "host: $HOST" | python3 -c "
import sys,json
ec=[k for k in json.load(sys.stdin)['keys'] if k.get('kty')=='EC']
assert len(ec)>=2, ('publish-ahead 后 JWTS EC key 应≥2(新旧并存),实得%d'%len(ec))
print('   ✅ JWTS 现有 EC key %d 把(新旧并存):%s'%(len(ec),[k['kid'][:12] for k in ec]))
"
verify_token "$TOK_OLD" "publish-ahead:旧 key 签的 token"
OLD_KID=$(token_kid "$TOK_OLD")
audit_rotation publish_ahead "$OLD_KID" "$NEW_KID" success

echo ""
echo "== D.2 切签名(改用新 key 签;新旧都在 JWKS)=="
ROTATION_PHASE="activate"
set_signing_env "$NEW_KEY" "${ORIG_EC:+$ORIG_EC,}$NEW_KEY"
sleep 3
TOK_NEW=$(mint_token)
if [ "$TOK_NEW" = "MINT_FAIL" ] || [ -z "$TOK_NEW" ]; then
  echo "❌ 切签名后 mint 失败"
  exit 1
fi
verify_token "$TOK_NEW" "切签名:新 key 签的 token"
# 关键无停机断言:切签名瞬间,**旧 key 签的存量 token 仍验签通过**(旧 key 仍在 JWTS)。
verify_token "$TOK_OLD" "切签名后:旧 key 签的存量 token(仍在重叠期)"
# 且新 token 的 kid 确实变了(真的切了签名 key)。
python3 -c "
import jwt
ko=jwt.get_unverified_header('$TOK_OLD')['kid']; kn=jwt.get_unverified_header('$TOK_NEW')['kid']
assert ko!=kn, ('切签名后 kid 应变,旧=%s 新=%s'%(ko[:12],kn[:12]))
print('   ✅ 签名 kid 已切换:%s → %s(真切了 key)'%(ko[:12],kn[:12]))
"
audit_rotation activate "$OLD_KID" "$NEW_KID" success

echo ""
if [ "$EMERGENCY_REVOKE" = "1" ]; then
  run_emergency_revoke
  exit 0
fi
if [ "$RETIRE_AFTER_WAIT" != "1" ]; then
  echo "== D.3 graceful retire 已跳过(默认安全行为)=="
  echo "   旧 key 继续 published,避免破坏 24 小时内可重试/redrive 的 immutable SSF SET。"
  echo "   完整长时演练须显式 RETIRE_AFTER_WAIT=1 RETIRE_WAIT_SECS>=86400。"
  exit 0
fi
case "$RETIRE_WAIT_SECS" in
  ''|*[!0-9]*) echo "❌ RETIRE_WAIT_SECS 必须是整数秒"; exit 1 ;;
esac
[ "$RETIRE_WAIT_SECS" -ge 86400 ] ||
  { echo "❌ graceful retire 必须等待至少 86400 秒(SSF freshness window)"; exit 1; }
echo "== D.3 等待 $RETIRE_WAIT_SECS 秒后 retire(移除旧 key;仅新 key 在 JWTS)=="
sleep "$RETIRE_WAIT_SECS"
ROTATION_PHASE="retire"
set_signing_env "$NEW_KEY" "$NEW_KEY"
sleep 3
TOK_R=$(mint_token)
if [ "$TOK_R" = "MINT_FAIL" ] || [ -z "$TOK_R" ]; then
  echo "❌ retire 后 mint 失败"
  exit 1
fi
verify_token "$TOK_R" "retire:新 key 签的 token"
curl -s "$API_URL/jwks.json" -H "host: $HOST" | python3 -c "
import sys,json
ec=[k for k in json.load(sys.stdin)['keys'] if k.get('kty')=='EC']
assert len(ec)==1, ('retire 后 JWTS EC key 应==1,实得%d'%len(ec))
print('   ✅ retire 后 JWTS 仅剩新 EC key 1 把:%s'%[k['kid'][:12] for k in ec])
"
# retire 后:旧 key 签的存量 token 现在验签**应失败**(旧 key 已移出 JWTS)——坐实"等 ≥ TTL 后才 retire"的必要性。
if verify_token "$TOK_OLD" "retire 后旧 token(应失败)" 2>/dev/null; then
  echo "   ❌ retire 后旧 key 签的 token 仍验签通过——旧 key 未真正移出 JWTS"; exit 1
else
  echo "   ✅ retire 后旧 key 签的存量 token 验签失败(已等 OAuth expiry + SSF 24h window)"
fi
audit_rotation retire "$OLD_KID" "$NEW_KID" success

echo ""
echo "🎉 KMS 三相无停机优雅轮换真机演练全绿(D 段长时实跑,trap 将恢复现网):"
echo "   publish-ahead(新旧并存)→ 切签名(旧存量仍验签)→ retire(等待完整窗口后旧 key 退出)。"
echo "   全程每相 mint+verify 无停机(签名 kid 恒 ∈ 当时 JWTS)。清理见下方 D.cleanup。"

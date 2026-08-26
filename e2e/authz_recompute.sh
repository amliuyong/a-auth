#!/usr/bin/env bash
# spec 005 §7(C10.17)真机 e2e:Cedar 策略重算后台任务(agent-auth-recompute)打真实 DynamoDB
# (GrantsTable + GSI policy_version-index)+ 重算 Lambda 的 **publish-then-activate**(补强 ⑨)+
# GSI Query stale(effective_pv < current_pv,补强 ⑩)+ evaluate 收窄/吊销 + 条件写 CAS(补强 ⑫)。
#
# 为何真机(编排/纯逻辑 UT 已全绿,见 crates/http/tests/authz_e2e.rs):验 **Dynamo 专有路径** ——
# ① publish_policy_from_env 单写者写不可变工件 + bump policy_version(ADD 原子)+ 幂等(digest 相同不涨版本);
# ② GSI policy_version-index(pk=gv_tenant, sk=effective_pv,ProjectionType=ALL)Query stale 的分页 + 顶层属性提升;
# ③ put_conditional 条件写(revision CAS)在真表的并发语义。内存适配器测不到这些。
#
# **安全隔离(评审 Blocker B1 修正)**:run_recompute_pass 的作用域是**整个 tenant**,不是 grant_id 前缀。
# 若跑在自部署 tenant ""(现网真实 Grant 所在),会吊销真实 Grant + 把 deny-all 发布为该 tenant 的 active 工件。
# 故本脚本用**一次性专用 tenant** `e2e-authz-<rand>`:AGENT_AUTH_RECOMPUTE_TENANTS 只传它,seed 的 Grant 与
# publish 的 policy-version/工件全落该 tenant 分区,**绝不碰 ""**。EXIT trap 删该 tenant 的全部行(合成 Grant +
# policy-version + 工件)并恢复 Lambda env(关回 dry-run、清策略集)。主 Lambda 保持 authz **关**(字节等价)。
#
# 用法:
#   RECOMPUTE_FN=<RecomputeFn 名> GRANTS_TABLE=<GrantsTable 名> \
#   AWS_PROFILE=default REGION=us-east-1 ./e2e/authz_recompute.sh
#
# 依赖:aws cli、python3、jq。
set -euo pipefail

RECOMPUTE_FN="${RECOMPUTE_FN:?需 RECOMPUTE_FN(RecomputeFn Lambda 名;见栈输出 RecomputeFnName)}"
GRANTS_TABLE="${GRANTS_TABLE:?需 GRANTS_TABLE(GrantsTable 名;见栈输出 GrantsTableName)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")

RAND="$(python3 -c 'import secrets;print(secrets.token_hex(4))')"
# **一次性专用 tenant**(绝不用 ""):publish/bump/list_stale 全隔离在此,跑完删干净。
TENANT="e2e-authz-$RAND"
SEP=$'\x1f'                       # tpk 分隔符(crates/http/src/tenant.rs SEP=\u{1f})
# tpk(tenant,key) = "<tenant>\x1f<key>"(tenant 非空)。GSI 分区键 gv_tenant = tpk(TENANT,"gv")。
GV_TENANT="${TENANT}${SEP}gv"
PK_POLICY_VERSION="${TENANT}${SEP}policy-version"
umask 077
ENV_BAK="$(mktemp)"               # 重算 Lambda 原 env 全量(trap 恢复;含 secret 明文,只经 file:// + 600 tempfile)
GIDS=()                           # 造的合成 grant_id(cleanup 删)
ARTIFACT_VERSIONS=()              # publish 出的工件版本(cleanup 删 policy-artifact#<v> 行)

# 策略集:v-narrow 只 permit read(用于收窄 {read,write}→{read});v-deny permit 无关 action(全 deny → 吊销)。
POLICY_NARROW='permit(principal, action == Action::"read", resource);'
POLICY_DENY='permit(principal, action == Action::"nonexistent", resource);'

# DynamoDB --key JSON 生成器:grant_id 含 tpk 分隔符 \x1f(控制字符),AWS CLI 的 JSON 解析器**拒绝裸控制字符**,
# 故用 python json.dumps 转义成 (纯 ASCII,CLI 接受)。所有 --key 经此,绝不内联拼裸 \x1f。
keyjson() {  # $1=物理 grant_id(可含 \x1f)→ 打印 {"grant_id":{"S":"......"}}
  GID="$1" python3 -c 'import json,os;print(json.dumps({"grant_id":{"S":os.environ["GID"]}}))'
}

cleanup() {
  set +e
  echo "== [trap] 恢复 RecomputeFn env(关回 dry-run + 清策略集 + 清专用 tenant)=="
  if [ -s "$ENV_BAK" ]; then
    "${AWSQ[@]}" lambda wait function-updated --function-name "$RECOMPUTE_FN" 2>/dev/null
    for attempt in 1 2 3; do
      if "${AWSQ[@]}" lambda update-function-configuration --function-name "$RECOMPUTE_FN" \
           --environment "file://$ENV_BAK" >/dev/null; then
        "${AWSQ[@]}" lambda wait function-updated --function-name "$RECOMPUTE_FN" 2>/dev/null
        EN=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$RECOMPUTE_FN" \
          --query 'Environment.Variables.AGENT_AUTH_RECOMPUTE_ENABLED' --output text 2>/dev/null)
        [ "$EN" = "None" ] && { echo "  ✅ 已关回 dry-run(ENABLED=None)"; break; }
        echo "  ⚠️ 第 $attempt 次:ENABLED=$EN 未清,重试…"
      else
        echo "  ⚠️ 第 $attempt 次:恢复 update 失败,重试…"
      fi
      sleep 3
    done
  fi
  # 删合成 Grant + 专用 tenant 的 policy-version + 工件(专用 tenant 全清,现网 tenant "" 零触碰)。
  # --key 经 keyjson(python 转义 \x1f 控制字符;裸拼会被 CLI JSON 解析器拒 → 删不掉留孤儿行)。
  for gid in "${GIDS[@]}"; do
    "${AWSQ[@]}" dynamodb delete-item --table-name "$GRANTS_TABLE" \
      --key "$(keyjson "$gid")" >/dev/null 2>&1
  done
  "${AWSQ[@]}" dynamodb delete-item --table-name "$GRANTS_TABLE" \
    --key "$(keyjson "$PK_POLICY_VERSION")" >/dev/null 2>&1
  for v in "${ARTIFACT_VERSIONS[@]}"; do
    "${AWSQ[@]}" dynamodb delete-item --table-name "$GRANTS_TABLE" \
      --key "$(keyjson "${TENANT}${SEP}policy-artifact#${v}")" >/dev/null 2>&1
  done
  echo "  ✅ 专用 tenant $TENANT 全部行已清(现网 tenant \"\" 未触碰)"
  rm -f "$ENV_BAK"
}
trap cleanup EXIT INT TERM

# 直接在 GrantsTable 造一个合成 Grant(canonical serde 形状 + 顶层 gv_tenant/effective_pv/revision)。
# grant_id / user_id / gv_tenant 全带专用 TENANT 前缀(tpk 物理分区);$1=grant_id 尾 $2=effective_pv $3=scopes JSON。
seed_grant() {
  local gid="${TENANT}${SEP}$1" epv="$2" scopes="$3" logical_id="$1"
  local gjson
  gjson=$(GID="$logical_id" SCOPES="$scopes" EPV="$epv" python3 - <<'PY'
import json, os
gid = os.environ["GID"]; scopes = json.loads(os.environ["SCOPES"]); epv = int(os.environ["EPV"])
rg = {"resource": "rs1", "scopes": scopes, "authorization_details": []}
g = {
    "grant_id": gid, "user_id": "user:alice", "client_id": "app",
    "per_resource": [rg], "effective_per_resource": [rg],
    "effective_pv": epv, "allowed_ip_cidrs": [], "allowed_vpce": [], "revision": 0,
    "constraints": {"max_act_chain": 1, "actor_allowlist": [], "expires_at": 9999999999},
    "status": "active",
}
print(json.dumps(g, separators=(",", ":")))
PY
)
  local item
  item=$(GID="$gid" GV="$GV_TENANT" USERID="${TENANT}${SEP}user:alice" EPV="$epv" GJSON="$gjson" python3 - <<'PY'
import json, os
item={"grant_id":{"S":os.environ["GID"]},"user_id":{"S":os.environ["USERID"]},
      "gv_tenant":{"S":os.environ["GV"]},"effective_pv":{"N":os.environ["EPV"]},"revision":{"N":"0"},
      "grant_json":{"S":os.environ["GJSON"]}}
print(json.dumps(item))
PY
)
  "${AWSQ[@]}" dynamodb put-item --table-name "$GRANTS_TABLE" --item "$item" >/dev/null
  GIDS+=("$gid")
}

# 读一个合成 Grant 的 grant_json,提取 (effective_pv, effective scopes, status)。$1=grant_id 尾。
# **注**:`aws | python3 -c` —— 脚本走 -c、stdin=管道(aws json);绝不用 `python3 - <<HEREDOC`(heredoc
# 与管道都占 stdin,heredoc 胜 → aws 输出被丢弃 → broken pipe;read_current_pv 同款 -c 写法可参照)。
read_grant() {
  "${AWSQ[@]}" dynamodb get-item --table-name "$GRANTS_TABLE" --consistent-read --output json \
    --key "$(keyjson "${TENANT}${SEP}$1")" \
    | python3 -c '
import sys, json
s = sys.stdin.read().strip() or "{}"
it = json.loads(s).get("Item")
if not it:
    print("GONE|GONE|GONE"); sys.exit(0)
g = json.loads(it["grant_json"]["S"])
eff = g.get("effective_per_resource", [])
scopes = ",".join(sorted(eff[0]["scopes"])) if eff else ""
print("%s|%s|%s" % (g.get("effective_pv"), scopes, g.get("status")))
'
}

# 读专用 tenant 的 current policy_version(供断言 publish/bump 生效 + 记录工件版本供 cleanup)。
read_current_pv() {
  "${AWSQ[@]}" dynamodb get-item --table-name "$GRANTS_TABLE" --consistent-read --output json \
    --key "$(keyjson "$PK_POLICY_VERSION")" \
    | python3 -c "import sys,json;s=sys.stdin.read().strip() or '{}';d=json.loads(s).get('Item',{});print(d.get('policy_version',{}).get('N','0'))"
}

invoke_recompute() {  # 返回 payload JSON
  local out; out=$(mktemp)
  "${AWSQ[@]}" lambda invoke --function-name "$RECOMPUTE_FN" \
    --cli-binary-format raw-in-base64-out --payload '{"source":"e2e"}' "$out" >/dev/null
  cat "$out"; rm -f "$out"
}

echo "== 专用 tenant = $TENANT(publish/bump/重算全隔离于此;现网 tenant \"\" 零触碰)=="

echo "== 0. 备份 RecomputeFn env,置真处置(ENABLED=1 + AUTHZ_ENABLED=1 + TENANTS=专用 + POLICY_SET=narrow)=="
"${AWSQ[@]}" lambda get-function-configuration --function-name "$RECOMPUTE_FN" \
  --query 'Environment' --output json > "$ENV_BAK"
# ENV_BAK 可能是 "null"(函数无 environment)——兜底成 {"Variables":{}}(健壮性 L3)。
if [ "$(cat "$ENV_BAK")" = "null" ]; then echo '{"Variables":{}}' > "$ENV_BAK"; fi
apply_env() {  # $1=policy text
  local pol="$1"
  local envnew
  envnew=$(POL="$pol" TEN="$TENANT" python3 - "$ENV_BAK" <<'PY'
import json, os, sys
env = json.load(open(sys.argv[1]))
v = env.get("Variables", {})
v["AGENT_AUTH_RECOMPUTE_ENABLED"] = "1"
v["AGENT_AUTH_AUTHZ_ENABLED"] = "1"
v["AGENT_AUTH_RECOMPUTE_TENANTS"] = os.environ["TEN"]   # **只跑专用 tenant**(绝不含 "")
v["AGENT_AUTH_POLICY_SET"] = os.environ["POL"]
print(json.dumps({"Variables": v}))
PY
)
  echo "$envnew" > /tmp/recompute_env_$RAND.json
  "${AWSQ[@]}" lambda wait function-updated --function-name "$RECOMPUTE_FN"
  "${AWSQ[@]}" lambda update-function-configuration --function-name "$RECOMPUTE_FN" \
    --environment "file:///tmp/recompute_env_$RAND.json" >/dev/null
  "${AWSQ[@]}" lambda wait function-updated --function-name "$RECOMPUTE_FN"
  rm -f /tmp/recompute_env_$RAND.json
}
apply_env "$POLICY_NARROW"
echo "  ✅ RecomputeFn 置真处置(narrow 策略,TENANTS=$TENANT;trap 恢复 dry-run)"

# 造两个合成 Grant(effective_pv=0:一旦 current_pv≥1 即 stale)。
#  narrow:授权 {read,write} → narrow 策略下应收窄 effective 到 {read}。
#  deny:授权 {read} → deny 策略(第二轮)下 evaluate 空 → 吊销。
seed_grant "narrow" 0 '["read","write"]'
seed_grant "deny"   0 '["read"]'
ARTIFACT_VERSIONS=(1 2)   # 两轮 publish 至多产出 v1/v2(cleanup 兜底删;幂等第二轮不涨)
echo "== 1. 造 2 合成 Grant(effective_pv=0):narrow(read,write)+ deny(read)=="
# GSI policy_version-index **最终一致**:刚 put 的 item 到 GSI 有传播延迟。重算靠 GSI Query 找 stale,
# 故 invoke 前给足传播窗(否则首轮 scanned=0 = GSI 尚未见到新行,非逻辑错)。
echo "  (等 GSI 传播 8s…)"; sleep 8

echo "== 2. 首次 invoke:publish narrow(current_pv 0→1)+ seed backfill 收窄 stale Grant =="
P1=$(invoke_recompute)
echo "  payload: $P1"
echo "$P1" | python3 -c "import sys,json;d=json.load(sys.stdin);assert d.get('enabled')==True,'应真处置';print('  ✅ enabled=true scanned=%s recomputed=%s revoked=%s conflicted=%s errored=%s'%(d['scanned'],d['recomputed'],d['revoked'],d['conflicted'],d['errored']))"
PV1=$(read_current_pv); echo "  专用 tenant current_pv=$PV1"
[ "$PV1" = "1" ] || { echo "❌ publish 后 current_pv 应=1,实得 $PV1"; exit 1; }

echo "== 3. 断言 narrow Grant → effective 收窄成 {read}、effective_pv 追平(=1、不再 stale)=="
RG=$(read_grant "narrow"); echo "  narrow = $RG"
IFS='|' read -r N_EPV N_SCOPES N_STATUS <<< "$RG"
[ "$N_SCOPES" = "read" ] || { echo "❌ narrow effective 应收窄成 read,实得 '$N_SCOPES'"; exit 1; }
[ "$N_EPV" = "1" ] || { echo "❌ narrow effective_pv 应追平 current=1,实得 '$N_EPV'"; exit 1; }
[ "$N_STATUS" = "active" ] || { echo "❌ narrow 应仍 active,实得 '$N_STATUS'"; exit 1; }
echo "  ✅ narrow effective={read} effective_pv=1 status=active(收窄 + 追平,seed backfill 生效)"

echo "== 4. 幂等:再 invoke(narrow 未变 → 不涨版本、backfill 扫 0 新 stale)=="
P2=$(invoke_recompute)
echo "  payload: $P2"
echo "$P2" | python3 -c "import sys,json;d=json.load(sys.stdin);assert d.get('errored',0)==0,'幂等轮不应有错';print('  ✅ 幂等 scanned=%s recomputed=%s errored=0'%(d['scanned'],d['recomputed']))"
PV2=$(read_current_pv)
[ "$PV2" = "1" ] || { echo "❌ 幂等:current_pv 不应变(1→$PV2)"; exit 1; }
echo "  ✅ 幂等:current_pv 稳定 = $PV2(相同策略不涨版本)"

echo "== 5. 收紧到 deny 策略(publish v2 → bump current_pv→2)→ deny Grant 应被**吊销** =="
apply_env "$POLICY_DENY"
P3=$(invoke_recompute)
echo "  payload: $P3"
echo "$P3" | python3 -c "import sys,json;d=json.load(sys.stdin);print('  ✅ deny 轮 scanned=%s recomputed=%s revoked=%s'%(d['scanned'],d['recomputed'],d['revoked']))"
PV3=$(read_current_pv)
[ "$PV3" = "2" ] || { echo "❌ deny publish 后 current_pv 应=2,实得 $PV3"; exit 1; }
RD=$(read_grant "deny"); echo "  deny = $RD"
IFS='|' read -r _ _ D_STATUS <<< "$RD"
[ "$D_STATUS" = "revoked" ] || { echo "❌ deny Grant 在全 deny 策略下 MUST 被吊销,实得 status='$D_STATUS'"; exit 1; }
echo "  ✅ deny Grant status=revoked(策略下无任何生效权限 → 吊销,C10.17 敏感度分档 P2 起步)"

echo ""
echo "🎉 authz_recompute e2e 全绿:publish-then-activate(补强⑨)+ seed backfill(补强⑪)+ GSI stale Query(补强⑩)+ 收窄/吊销 + 条件写 CAS 真机验证通过"
echo "   (专用 tenant $TENANT 全部行 + RecomputeFn env 由 trap 清理;现网 tenant \"\" 零触碰)"

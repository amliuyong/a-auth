#!/usr/bin/env bash
# Cedar/AVP 授权引擎(C10.17)**启用演练**脚本(spec 005 §7 / spec 006 §3.4;DEPLOYMENT §3 顺序沉淀)。
#
# 目的:把"开 authz"这一有顺序、易踩雷的运维动作变成**一键可跑、默认只演练不真开、带完整安全预检**的流程。
# 真机审计教训:dev 栈 66 Active Grant 里 56 无可评估单元(开 authz+backfill 若语义错会误吊销);已由补强 ⑯
# 修复(无可评估单元恒保留),但启用前仍须**看清哪些 Grant 会被策略收窄/吊销**。
#
# 三阶段(默认全跑,只读 + 隔离,零现网副作用):
#   A. 只读预检:身份 / GSI policy_version-index=ACTIVE / 主 AuthFn authz 现状 / **按形状分类现网 Grant**
#      (有可评估单元=会被策略管;无可评估单元=恒保留)——这是 dry-run 无法给的预览(dry-run 只报 scanned)。
#   B. 隔离租户机制演练:委托给 e2e/authz_recompute.sh(专用一次性 tenant 跑 publish→bump→backfill→吊销,
#      trap 全清,现网 tenant "" 零触碰)——验证引擎机制在真机可用,不碰现网数据。
#   C. 打印**真启用命令**(cdk deploy authzEnabled + invoke RecomputeFn + 验证 + 回滚)——**不执行**,
#      须运维审阅现网 Grant 分类后手动照做(真开会改现网签发行为,不进自动化)。
#
# 用法:
#   RECOMPUTE_FN=<RecomputeFn 名> GRANTS_TABLE=<GrantsTable 名> AUTH_FN=<AuthFn 名> \
#   [POLICY_FILE=<path/to/policy.cedar>] AWS_PROFILE=default REGION=us-east-1 ./e2e/authz_enable_drill.sh
#
# 依赖:aws cli、python3、jq、bash。**只读 + 隔离**;不改现网 Grant、不改主 AuthFn env。
set -euo pipefail

RECOMPUTE_FN="${RECOMPUTE_FN:?需 RECOMPUTE_FN(RecomputeFn Lambda 名;栈输出 RecomputeFnName)}"
GRANTS_TABLE="${GRANTS_TABLE:?需 GRANTS_TABLE(栈输出 GrantsTableName)}"
AUTH_FN="${AUTH_FN:-}"   # 主 AuthFn 名(可选;给了则查 authz 现状)
POLICY_FILE="${POLICY_FILE:-}"   # 拟启用的 Cedar 策略文件(可选;给了则 C 段命令引用它)
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
AWSQ=(aws --profile "$PROFILE" --region "$REGION")
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "=============================================================="
echo " Cedar/AVP 授权引擎 启用演练(默认只读 + 隔离,不真开)"
echo "=============================================================="

# ── A. 只读预检 ───────────────────────────────────────────────
echo ""
echo "== A. 只读预检 =="

echo "-- A0 身份 --"
"${AWSQ[@]}" sts get-caller-identity --query 'Arn' --output text

echo "-- A1 GSI policy_version-index 状态(须 ACTIVE 才能安全开 authz)--"
GSI_ST=$("${AWSQ[@]}" dynamodb describe-table --table-name "$GRANTS_TABLE" \
  --query "Table.GlobalSecondaryIndexes[?IndexName=='policy_version-index'].IndexStatus | [0]" --output text 2>&1)
echo "   policy_version-index = $GSI_ST"
if [ "$GSI_ST" != "ACTIVE" ]; then
  echo "   ⚠ GSI 未 ACTIVE(或不存在)。先 cdk deploy 建 GSI 并等 ACTIVE 再启用 authz(DEPLOYMENT §3 步骤 1)。"
else
  echo "   ✅ GSI ACTIVE(重算 list_stale 可用)"
fi

if [ -n "$AUTH_FN" ]; then
  echo "-- A2 主 AuthFn authz 现状(演练前应为关=字节等价)--"
  AZ=$("${AWSQ[@]}" lambda get-function-configuration --function-name "$AUTH_FN" \
    --query 'Environment.Variables.AGENT_AUTH_AUTHZ_ENABLED' --output text 2>&1)
  echo "   AGENT_AUTH_AUTHZ_ENABLED = $AZ  ($([ "$AZ" = "None" ] && echo '关=字节等价现网' || echo '已开!'))"
fi

echo "-- A3 现网 Grant 按形状分类(启用影响预览;dry-run 给不了这个)--"
# 有可评估单元 = ∃ resource 有 ≥1 scope 或 ≥1 RAR(会被策略收窄/吊销);
# 无可评估单元 = resource-less 或全是空 scope+无 RAR(补强 ⑯:恒保留、不受策略约束)。
# 只扫 Active Grant(跳过 policy-version/工件行[无 grant_json]、终态)。分页扫全表——**每页立即抽出
# grant_json 逐行写临时文件**(避免多行 page JSON 混入 classifier 的逐行解析;NEXT 用 base64 传规避引号)。
SCAN_TMP="$(mktemp)"; : > "$SCAN_TMP"
NEXT=""
while : ; do
  if [ -n "$NEXT" ]; then
    KEYJSON=$(printf '%s' "$NEXT" | base64 -d)
    PAGE=$("${AWSQ[@]}" dynamodb scan --table-name "$GRANTS_TABLE" \
      --projection-expression "grant_json" --exclusive-start-key "$KEYJSON" --output json)
  else
    PAGE=$("${AWSQ[@]}" dynamodb scan --table-name "$GRANTS_TABLE" \
      --projection-expression "grant_json" --output json)
  fi
  # 每页:每个 grant_json 串写一行(去换行)。
  echo "$PAGE" | python3 -c "
import sys,json
for it in json.load(sys.stdin).get('Items',[]):
    s=it.get('grant_json',{}).get('S')
    if s: print(json.dumps(s))
" >> "$SCAN_TMP"
  NEXT=$(echo "$PAGE" | python3 -c "import sys,json,base64;k=json.load(sys.stdin).get('LastEvaluatedKey');print(base64.b64encode(json.dumps(k).encode()).decode() if k else '')")
  [ -z "$NEXT" ] && break
done
python3 - "$SCAN_TMP" <<'PY'
import sys, json
active=0; evaluable=0; noeval=0; ex_eval=[]; ex_noeval=[]
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    gj=json.loads(line)             # 一行 = 一个 grant_json 串(外层已 json.dumps)
    try: g=json.loads(gj)
    except: continue
    if g.get("status")!="active": continue
    active+=1
    pr=g.get("per_resource",[])
    has=any((r.get("scopes") or []) or (r.get("authorization_details") or []) for r in pr)
    if has:
        evaluable+=1
        if len(ex_eval)<3: ex_eval.append(g.get("grant_id","?"))
    else:
        noeval+=1
        if len(ex_noeval)<3: ex_noeval.append(g.get("grant_id","?"))
print(f"   Active Grant 共 {active}")
print(f"   ├─ 有可评估单元 = {evaluable}  → **会被策略收窄/吊销**(启用后按 policy 判 (resource,scope))")
if ex_eval: print(f"   │    例:{ex_eval}")
print(f"   └─ 无可评估单元 = {noeval}  → **恒保留、不受策略约束**(补强 ⑯;resource-less/空 scope+无 RAR)")
if ex_noeval: print(f"        例:{ex_noeval}")
print()
if evaluable==0:
    print("   ✅ 无有可评估单元 Grant:启用 authz 不会吊销/收窄任何现网 Grant(全 preserve)。")
else:
    print(f"   ⚠ {evaluable} 个有可评估单元 Grant 会被策略判定。**启用前须确认拟用策略对这些 (resource,scope) 的 permit/deny 符合预期**")
    print("     (被策略全 deny 的会 revoke,收窄的会 narrow;无可评估单元的 %d 个不受影响)。" % noeval)
PY
rm -f "$SCAN_TMP"

# ── B. 隔离租户机制演练 ───────────────────────────────────────
echo ""
echo "== B. 隔离租户机制演练(专用一次性 tenant,现网 tenant \"\" 零触碰)=="
echo "   委托 e2e/authz_recompute.sh:publish→bump current_pv→seed backfill 收窄→幂等→收紧 deny 吊销,trap 全清。"
if RECOMPUTE_FN="$RECOMPUTE_FN" GRANTS_TABLE="$GRANTS_TABLE" AWS_PROFILE="$PROFILE" REGION="$REGION" \
     bash "$HERE/authz_recompute.sh"; then
  echo "   ✅ 机制演练全绿(引擎在真机可用;未碰现网数据)"
else
  echo "   ❌ 机制演练失败——启用前 MUST 排查(引擎机制在真机不可用)。见上方输出。"
  exit 1
fi

# ── C. 打印真启用命令(不执行)─────────────────────────────────
echo ""
echo "== C. 真启用命令(**不执行**;运维审阅 A3 分类后手动照做,DEPLOYMENT §3)=="
POLICY_HINT="${POLICY_FILE:-<path/to/policy.cedar>}"
cat <<EOF
   前提:A1 GSI=ACTIVE ✅、A2 authz 现为关、A3 分类已审阅(确认有可评估单元 Grant 会被策略如期处置)。

   1) 带策略集部署 authz(synth 期强制 policySet 非空 + Cedar sanity):
        cd infra && AWS_REGION=$REGION \\
          AGENT_AUTH_AUTHZ_ENABLED=1 AGENT_AUTH_POLICY_SET_FILE=$POLICY_HINT \\
          npx cdk deploy AgentAuthDev --profile $PROFILE --require-approval never
        # SaaS 同理 deploy AgentAuthSaas(+ SAAS_* env);CDK authz 开时自动注入 RecomputeFn RECOMPUTE_ENABLED=1。

   2) RecomputeFn 首跑 publish + backfill(或等每小时调度):
        ${AWSQ[*]} lambda invoke --function-name $RECOMPUTE_FN \\
          --cli-binary-format raw-in-base64-out --payload '{"source":"enable"}' /tmp/out.json && cat /tmp/out.json
        # 查 CloudWatch 日志:POLICY_PUBLISHED ... backfill_recomputed=N;RECOMPUTE_PASS ... preserved=N revoked=M

   3) 验证:current_pv≥1 且存量 Grant effective_pv 追平;热路径不再对存量 503。

   回滚(随时):移除 AGENT_AUTH_AUTHZ_ENABLED 重 deploy → 主 Lambda 秒回字节等价(已发布工件/GSI 无害留存)。
EOF

echo ""
echo "🎉 启用演练完成(A 只读预检 + B 隔离机制演练全绿;C 真启用命令已打印,未执行)。"
echo "   真开 authz 请照 C 段手动执行(会改现网签发行为,不自动化)。"

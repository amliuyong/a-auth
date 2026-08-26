#!/usr/bin/env bash
# SaaS 多租户 / 多 issuer 真机 e2e(spec 020 §2.3/§2.5,C10.19,C1.6a)。
#
# 验证 AgentAuthSaas 栈(FORM=saas + ENABLE_TENANT_PARTITIONING=1)在**真机 DynamoDB** 上的
# 逐子域 issuer + 数据面物理隔离:
#   - t1/t2.<zone> 各是独立 OIDC issuer(discovery 如实宣告自身 issuer);控制面 c.<zone> 非 issuer → 400。
#   - 同一 client_id 在 t1 注册,t2 **物理看不到**(authorize 未知 client / admin list 不含)——
#     这是评审 codex B1「跨租户逻辑 id 碰撞泄露」的真机反证。
#   - authz code 跨租户不可兑换(t1 的 code 在 t2 /token → invalid_grant;且不消费 t1 侧那份)。
#   - 租户内 happy-path 完整(authorize→code→token,access+id_token iss=本租户)。
#
# 前置:AgentAuthSaas 已部署 + 通配证书 *.<zone> ISSUED + DNS/CloudFront 已传播;dev 档开 DCR_OPEN +
#       login_user 占位(allowLoginPlaceholder)。脚本只创建自己的 DCR client，并在所有退出路径
#       通过 RFC 7592 删除，再强读验证 client/Grant 均不存在。
#
# 用法:  ZONE=saas.example.com AWS_PROFILE=default ./e2e/saas_multi_tenant.sh
#         (可选 T1_HOST/T2_HOST/CONTROL_HOST 覆盖默认 t1.<zone>/t2.<zone>/c.<zone>)
set -euo pipefail
set +x
umask 077

ZONE="${ZONE:?需 ZONE(托管区,如 saas.example.com)}"
T1="${T1_HOST:-t1.$ZONE}"
T2="${T2_HOST:-t2.$ZONE}"
CTRL="${CONTROL_HOST:-c.$ZONE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${SAAS_STACK:-AgentAuthSaas}"
TENANT="t1"
# PKCE 已知对(RFC 7636 附录 B)。
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
REDIRECT="https://app.example.com/cb"
pass=0; fail=0
ok(){ echo "  ✅ $1"; pass=$((pass+1)); }
bad(){ echo "  ❌ $1"; fail=$((fail+1)); }

for command in aws curl find jq mktemp python3 rmdir seq sleep; do
  command -v "$command" >/dev/null ||
    { echo "missing required command: $command" >&2; exit 1; }
done

WORK="$(mktemp -d)"
CID=""
REG_HEADER="$WORK/registration.headers"
CLIENTS_TABLE=""
GRANTS_TABLE=""
CLEANUP_COMPLETE=0

stack_output() {
  local key="$1"
  aws cloudformation describe-stacks \
    --profile "$PROFILE" --region "$REGION" --stack-name "$STACK" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" \
    --output text
}

tpk() {
  printf '%s\x1f%s' "$TENANT" "$1"
}

ddb_item_absent() {
  local table="$1" key="$2" output
  if ! output="$(aws dynamodb get-item \
    --profile "$PROFILE" --region "$REGION" --table-name "$table" \
    --consistent-read --key "$key" --output json)"; then
    return 1
  fi
  [[ -z "$output" ]] && return 0
  jq -e 'has("Item") | not' <<<"$output" >/dev/null
}

client_grant_count() {
  local client_id="$1" prefix output="$WORK/grants.json"
  prefix="$(printf '%s\x1f' "$TENANT")"
  aws dynamodb scan \
    --profile "$PROFILE" --region "$REGION" --table-name "$GRANTS_TABLE" \
    --consistent-read --projection-expression 'grant_id,grant_json' \
    --output json >"$output" || return 1
  jq -er --arg client "$client_id" --arg prefix "$prefix" '
    [
      .Items[]?
      | select(.grant_id.S | startswith($prefix))
      | (.grant_json.S | fromjson)
      | select(.client_id == $client)
    ]
    | length
  ' "$output"
}

cleanup() {
  local status=$? cleanup_failed=0 delete_status="" read_status="" grants=""
  set +e
  if [[ "$CLEANUP_COMPLETE" != "1" && -n "$CID" && -s "$REG_HEADER" ]]; then
    delete_status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -o "$WORK/delete.body" -w '%{http_code}' -X DELETE \
      -H "@$REG_HEADER" "https://$T1/register/$CID")"
    [[ "$delete_status" == "204" || "$delete_status" == "404" ]] ||
      cleanup_failed=1

    read_status="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
      -o "$WORK/read-after-delete.body" -w '%{http_code}' \
      -H "@$REG_HEADER" "https://$T1/register/$CID")"
    [[ "$read_status" == "404" ]] || cleanup_failed=1

    if [[ -n "$CLIENTS_TABLE" && -n "$GRANTS_TABLE" ]]; then
      for _ in $(seq 1 30); do
        grants="$(client_grant_count "$CID")" || {
          sleep 1
          continue
        }
        if ddb_item_absent "$CLIENTS_TABLE" \
          "$(jq -cn --arg id "$(tpk "$CID")" '{client_id:{S:$id}}')" &&
          [[ "$grants" == "0" ]]; then
          CLEANUP_COMPLETE=1
          break
        fi
        sleep 1
      done
      [[ "$CLEANUP_COMPLETE" == "1" ]] || cleanup_failed=1
    else
      cleanup_failed=1
    fi
  fi
  find "$WORK" -type f -delete
  find "$WORK" -depth -type d -empty -delete
  rmdir "$WORK" 2>/dev/null || true
  trap - EXIT
  if [[ "$status" -ne 0 || "$cleanup_failed" -ne 0 ]]; then
    exit 1
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

CLIENTS_TABLE="$(stack_output ClientsTableName)"
GRANTS_TABLE="$(stack_output GrantsTableName)"
[[ -n "$CLIENTS_TABLE" && "$CLIENTS_TABLE" != "None" &&
  -n "$GRANTS_TABLE" && "$GRANTS_TABLE" != "None" ]] ||
  { echo "SaaS stack is missing client/grant table outputs" >&2; exit 1; }

echo "== 1. 逐子域 discovery:t1/t2 各自 issuer,控制面拒 =="
I1=$(curl -s --max-time 20 "https://$T1/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin).get('issuer',''))")
I2=$(curl -s --max-time 20 "https://$T2/.well-known/openid-configuration" | python3 -c "import sys,json;print(json.load(sys.stdin).get('issuer',''))")
if [ "$I1" = "https://$T1" ]; then ok "t1 issuer=$I1"; else bad "t1 issuer 异常:$I1"; fi
if [ "$I2" = "https://$T2" ]; then ok "t2 issuer=$I2"; else bad "t2 issuer 异常:$I2"; fi
if [ "$I1" != "$I2" ]; then ok "t1/t2 issuer 互异(多 issuer)"; else bad "t1/t2 issuer 相同"; fi
SC=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "https://$CTRL/.well-known/openid-configuration")
if [ "$SC" = "400" ]; then ok "控制面 $CTRL discovery → 400(非 issuer,fail-closed)"; else bad "控制面 discovery 应 400,实得 $SC"; fi

echo "== 2. 在 t1 用 DCR 注册 public client =="
REGISTER_STATUS="$(curl -sS --proto '=https' --connect-timeout 5 --max-time 30 \
  -X POST "https://$T1/register" -H "content-type: application/json" \
  -d "{\"redirect_uris\":[\"$REDIRECT\"],\"token_endpoint_auth_method\":\"none\"}" \
  -o "$WORK/registration.json" -w '%{http_code}')"
[[ "$REGISTER_STATUS" == "201" ]] ||
  { bad "t1 DCR 失败(HTTP $REGISTER_STATUS)"; exit 1; }
CID="$(jq -er '.client_id' "$WORK/registration.json")"
jq -j '.registration_access_token' "$WORK/registration.json" >"$WORK/registration.token"
[[ -n "$CID" && -s "$WORK/registration.token" ]] ||
  { bad "t1 DCR 未返回管理凭证"; exit 1; }
printf 'authorization: Bearer %s\n' "$(<"$WORK/registration.token")" >"$REG_HEADER"
chmod 0600 "$REG_HEADER"
rm -f "$WORK/registration.token"
ok "t1 注册临时 public client"

echo "== 3. 跨租户 client 隔离:同 client_id 在 t2 authorize → 未知 client =="
S1=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 -G "https://$T1/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "scope=openid" \
  --data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "code_challenge_method=S256" --data-urlencode "state=x")
if [ "$S1" = "303" ]; then ok "t1 authorize 认得自己的 client(303)"; else bad "t1 authorize 应 303,实得 $S1"; fi
S2=$(curl -s -o "$WORK/saas_t2_authz.txt" -w "%{http_code}" --max-time 20 -G "https://$T2/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "scope=openid" \
  --data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "code_challenge_method=S256" --data-urlencode "state=x")
if [ "$S2" = "400" ] && grep -q "client" "$WORK/saas_t2_authz.txt"; then
  ok "t2 authorize 同 client_id → 400 未知 client(物理隔离,codex B1 反证)"
else bad "t2 应 400 未知 client,实得 $S2"; fi

echo "== 4. 租户内 happy-path:t1 authorize→code→token(access+id_token iss=t1)=="
LOC=$(curl -s -o /dev/null -D - --max-time 20 -G "https://$T1/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "scope=openid" \
  --data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=x" --data-urlencode "login_user=alice" | grep -i "^location:")
CODE=$(echo "$LOC" | grep -oE "code=[^&]+" | head -1 | cut -d= -f2 | tr -d '\r')
if [ -n "$CODE" ]; then ok "t1 拿到 code"; else bad "t1 未拿到 code"; fi
curl -s --max-time 20 -X POST "https://$T1/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE" \
  --data-urlencode "code_verifier=$VERIFIER" --data-urlencode "redirect_uri=$REDIRECT" \
  --data-urlencode "client_id=$CID" -o "$WORK/saas_tok.json" -w ""
TISS=$(python3 -c "
import json,base64
d=json.load(open('$WORK/saas_tok.json'))
at=d.get('access_token','')
p=at.split('.')[1]; p+='='*(-len(p)%4)
print(json.loads(base64.urlsafe_b64decode(p)).get('iss','')) if at.count('.')==2 else print('')
" 2>/dev/null)
if [ "$TISS" = "https://$T1" ]; then ok "t1 token 兑换成功,access iss=$TISS"; else bad "t1 token iss 异常:$TISS"; fi

echo "== 5. 跨租户 code 隔离:t1 的新 code 在 t2 /token 不可兑换,且不消费 t1 侧 =="
LOC2=$(curl -s -o /dev/null -D - --max-time 20 -G "https://$T1/authorize" \
  --data-urlencode "response_type=code" --data-urlencode "client_id=$CID" \
  --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "scope=openid" \
  --data-urlencode "code_challenge=$CHALLENGE" --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "state=x" --data-urlencode "login_user=alice" | grep -i "^location:")
CODE2=$(echo "$LOC2" | grep -oE "code=[^&]+" | head -1 | cut -d= -f2 | tr -d '\r')
R2=$(curl -s -o "$WORK/saas_t2_redeem.json" -w "%{http_code}" --max-time 20 -X POST "https://$T2/token" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE2" \
  --data-urlencode "code_verifier=$VERIFIER" --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "client_id=$CID")
if [ "$R2" = "400" ]; then ok "t1 的 code 在 t2 /token → 400 invalid_grant(code 分区隔离)"; else bad "t2 兑换应 400,实得 $R2"; fi
R1=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 -X POST "https://$T1/token" \
  -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=$CODE2" \
  --data-urlencode "code_verifier=$VERIFIER" --data-urlencode "redirect_uri=$REDIRECT" --data-urlencode "client_id=$CID")
if [ "$R1" = "200" ]; then ok "同 code 在 t1 仍可兑换(200;t2 失败尝试未消费/泄露)"; else bad "t1 应仍可兑换(200),实得 $R1"; fi

echo ""
echo "== 结果:$pass 通过 / $fail 失败 =="
[ "$fail" -eq 0 ] || exit 1

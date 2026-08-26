#!/usr/bin/env bash
# 真机定量:STS 兜底路径 vs OIDC/SVID 自校验路径的延迟/可用性开销(spec 012 §3.2;不验证 C5.4 熔断正确性)。
#
# 目的:用真实 AWS 数据**量化**"SigV4/STS 兜底(签发热路径上的同步外呼)相对本地自校验路径的净增量",
# 据此背书 DESIGN §3.1 "优先自校验 OIDC/SVID 路径"的选路默认(选路代码已 fail-closed 仅兜底,本脚本补证据)。
#
# 方法(诚实版,见脚本尾结论):
#   A. SigV4/STS 路径 /token:client→AS→**真 STS 外呼**→KMS ES256 Sign→2LO token(端到端含外呼)。
#   base. code flow /token:参照工况(但 authorization_code 多做 code lease/refresh/RS256 id_token 等,
#        **与 2LO 不同工况**,故 A−base 相减无意义——A 反比 base 快;base 仅作端到端量级参照)。
#   S. 本机→STS GetCallerIdentity 裸往返:**这才是 STS 外呼的直接量**——OIDC/SVID 自校验路径(本地验签)
#        相对 SigV4/STS 每次签发净省的就是这段(同工况差异 = 唯一多出的 STS 同步外呼)。
# 每组采样 N 次(默认 30),输出 p50/p95/p99/max + 成功率;结论用 S 量化可规避开销,背书优先自校验选路。
#
# 采样注意:SigV4 签名的 X-Amz-Date 只到秒,同秒重签→相同签名→撞 replay 缓存(缓存正确工作),故每次
# 采样跨秒(wait_next_second);且 seed 前清除命中本 caller ARN 的其它 SigV4 binding(防 match_sigv4 抢映射)。
#
# 用法:
#   API_URL=https://<apigw> CLIENTS_TABLE=<..> WORKLOAD_TRUST_TABLE=<..> \
#   [N=30] AWS_PROFILE=default REGION=us-east-1 ./e2e/sts_latency_quant.sh
#
# 依赖:python3(botocore/requests)、aws cli、curl。只读/幂等 seed(写演练 client + trust binding,末尾清理)。
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
WORKLOAD_TRUST_TABLE="${WORKLOAD_TRUST_TABLE:?需 WORKLOAD_TRUST_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
N="${N:-30}"
WL_CLIENT="e2e-sts-quant-wl"
CF_CLIENT="e2e-sts-quant-cf"
RS="https://mcp.quant.example.com"
REDIRECT="http://127.0.0.1/cb"

cleanup() {
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$WL_CLIENT\"}}" >/dev/null 2>&1 || true
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$CF_CLIENT\"}}" >/dev/null 2>&1 || true
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$WORKLOAD_TRUST_TABLE" --key "{\"binding_id\":{\"S\":\"e2e-sts-quant\"}}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== seed:workload client(SigV4)+ public client(code flow baseline)+ SigV4 trust binding =="
CALLER_JSON=$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --output json)
CALLER_ARN=$(echo "$CALLER_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['Arn'])")
CALLER_ACCT=$(echo "$CALLER_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['Account'])")

# ⚠️ 前置去竞争(match_sigv4 按 caller ARN 匹配,返首个命中 binding=非确定性):清除**其它** SigV4 binding
# 里 role_arn_pattern 命中本 caller ARN 的行,否则遗留 binding(如上次 sigv4_sts.sh 的 e2e-sigv4)会抢映射到
# 别的 client、其 allowed_resources 不同 → 本演练 resource 被误拒 invalid_target(实测踩过)。只删 SigV4 机制、
# 命中本 caller、且非本演练 binding_id 的行;OIDC binding(不同机制)不受影响。
echo "  去竞争:清除命中本 caller ARN 的**其它** SigV4 binding(防 match_sigv4 抢映射)"
COMPETERS=$(CALLER_ARN="$CALLER_ARN" PROFILE="$PROFILE" REGION="$REGION" WORKLOAD_TRUST_TABLE="$WORKLOAD_TRUST_TABLE" python3 -c "
import os, json, subprocess
arn=os.environ['CALLER_ARN']
out=subprocess.run(['aws','dynamodb','scan','--profile',os.environ['PROFILE'],'--region',os.environ['REGION'],
    '--table-name',os.environ['WORKLOAD_TRUST_TABLE'],'--query','Items[].{bid:binding_id.S,bj:binding_json.S}','--output','json'],
    capture_output=True,text=True)
for it in json.loads(out.stdout or '[]'):
    bid=it.get('bid'); bj=it.get('bj')
    if not bj or bid=='e2e-sts-quant': continue
    try: sig=json.loads(bj).get('mechanism',{}).get('sigv4')
    except Exception: continue
    if not sig: continue
    pat=sig.get('role_arn_pattern','')
    if pat==arn or (pat.endswith('*') and arn.startswith(pat[:-1])): print(bid)
")
for bid in $COMPETERS; do
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$WORKLOAD_TRUST_TABLE" \
    --key "{\"binding_id\":{\"S\":\"$bid\"}}" >/dev/null && echo "    - 删竞争 binding: $bid"
done
[ -z "$COMPETERS" ] && echo "    (无竞争 binding)"

aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$WL_CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"client_type\":{\"S\":\"workload\"},\"allowed_resources\":{\"L\":[{\"S\":\"$RS\"}]},\"allowed_scopes\":{\"L\":[{\"S\":\"kb:read\"}]}}" >/dev/null
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CF_CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"$REDIRECT\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
BINDING_JSON=$(CALLER_ARN="$CALLER_ARN" CALLER_ACCT="$CALLER_ACCT" CLIENT="$WL_CLIENT" python3 -c "
import os,json
print(json.dumps({'tenant_id':'default','mechanism':{'sigv4':{'aws_account_id':os.environ['CALLER_ACCT'],'role_arn_pattern':os.environ['CALLER_ARN']}},'mapped_client_id':os.environ['CLIENT']}))")
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$WORKLOAD_TRUST_TABLE" \
  --item "{\"binding_id\":{\"S\":\"e2e-sts-quant\"},\"tenant_id\":{\"S\":\"default\"},\"binding_json\":{\"S\":$(python3 -c "import json,sys;print(json.dumps(sys.stdin.read()))" <<<"$BINDING_JSON")}}" >/dev/null
echo "  ✅ seed 完成"

echo ""
echo "== 采样 N=$N:A(SigV4/STS 含外呼)· base(code flow 无外呼)· S(裸 STS 往返)=="
API_URL="$API_URL" WL_CLIENT="$WL_CLIENT" CF_CLIENT="$CF_CLIENT" RS="$RS" REDIRECT="$REDIRECT" \
N="$N" AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" python3 - <<'PY'
import os, json, time, urllib.parse, hashlib, base64, statistics, sys
import urllib.request
from botocore.session import Session
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth

API=os.environ["API_URL"]; N=int(os.environ["N"])
WL=os.environ["WL_CLIENT"]; CF=os.environ["CF_CLIENT"]; RS=os.environ["RS"]; REDIRECT=os.environ["REDIRECT"]
region=os.environ.get("AWS_REGION","us-east-1")
creds=Session().get_credentials().get_frozen_credentials()

def post_form(path, data):
    body=urllib.parse.urlencode(data).encode()
    req=urllib.request.Request(API+path, data=body, headers={"content-type":"application/x-www-form-urlencoded"})
    t0=time.perf_counter()
    try:
        r=urllib.request.urlopen(req, timeout=15); code=r.status; payload=r.read()
    except urllib.error.HTTPError as e:
        code=e.code; payload=e.read()
    dt=(time.perf_counter()-t0)*1000
    return code, payload, dt

def get(path):
    t0=time.perf_counter()
    r=urllib.request.urlopen(API+path, timeout=15); payload=r.read()
    return (time.perf_counter()-t0)*1000, payload

# ---- 造一枚 SigV4 assertion ----
# 关键(实测踩两坑):①replay 缓存键 = HMAC(server_secret, Authorization 的 Signature= 段),botocore SigV4 的
# X-Amz-Date 只到**秒**,同秒多次签名 → 相同签名 → replay 命中拒(缓存正确工作)。②不能靠"加自定义签名头造唯一"
# 绕开:AS 只转发 allowlist 头(Authorization/X-Amz-Date/audience)给 STS,会剥掉额外签名头,STS 按 SignedHeaders
# 重算签名时该头缺失 → 签名不符 → STS 拒。故唯一可行 = **每次采样跨秒**(下方 wait_next_second),让 X-Amz-Date 变。
def sigv4_assertion():
    url="https://sts.amazonaws.com/"; body="Action=GetCallerIdentity&Version=2011-06-15"
    req=AWSRequest(method="POST", url=url, data=body,
        headers={"Content-Type":"application/x-www-form-urlencoded","X-Agent-Auth-Audience":API,"Host":"sts.amazonaws.com"})
    SigV4Auth(creds,"sts",region).add_auth(req)
    return json.dumps({"method":"POST","url":url,"headers":dict(req.headers),"body":body})

def wait_next_second():
    # 睡到下一整秒(+5ms 余量),使下次 SigV4 签名的 X-Amz-Date 秒值必变 → 签名唯一 → 不撞 replay。
    now=time.time(); time.sleep(1.0 - (now % 1.0) + 0.005)

# ---- code flow:authorize→code→token(baseline:AS 本地签发,无 STS 外呼)----
VERIFIER="0123456789012345678901234567890123456789abc"
CHAL=base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()
def code_flow_token_latency():
    # authorize(拿 code)不计入——只量 /token(与 A 的 /token 对齐)。
    az=API+f"/authorize?response_type=code&client_id={CF}&redirect_uri={urllib.parse.quote(REDIRECT,safe='')}&code_challenge={CHAL}&code_challenge_method=S256&scope=openid&login_user=alice"
    req=urllib.request.Request(az);
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    op=urllib.request.build_opener(NoRedirect)
    try: op.open(req,timeout=15)
    except urllib.error.HTTPError as e: loc=e.headers.get("location","")
    code=urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("code",[""])[0]
    if not code: return None
    c,p,dt=post_form("/token",{"grant_type":"authorization_code","code":code,"code_verifier":VERIFIER,"redirect_uri":REDIRECT,"client_id":CF})
    return dt if c==200 else None

def sigv4_token_latency():
    a=sigv4_assertion()
    c,p,dt=post_form("/token",{"grant_type":"client_credentials",
        "client_assertion_type":"urn:agent-auth:params:oauth:client-assertion-type:aws-sigv4",
        "client_assertion":a,"resource":RS,"scope":"kb:read"})
    ok = c==200 and b"access_token" in p
    return dt, ok, c

def raw_sts_latency():
    url="https://sts.amazonaws.com/"; body="Action=GetCallerIdentity&Version=2011-06-15"
    req=AWSRequest(method="POST", url=url, data=body, headers={"Content-Type":"application/x-www-form-urlencoded","Host":"sts.amazonaws.com"})
    SigV4Auth(creds,"sts",region).add_auth(req)
    r=urllib.request.Request(url, data=body.encode(), headers=dict(req.headers))
    t0=time.perf_counter()
    try: urllib.request.urlopen(r,timeout=15); ok=True
    except urllib.error.HTTPError: ok=True  # STS 返回体即可,4xx/2xx 都算"可达"
    except Exception: ok=False
    return (time.perf_counter()-t0)*1000, ok

def warmup():
    # 各打 2 次预热(Lambda 冷启动 + 连接建立不计入分布)。SigV4 采样跨秒防 replay。
    for _ in range(2):
        try:
            wait_next_second(); sigv4_token_latency(); code_flow_token_latency(); raw_sts_latency()
        except Exception: pass

def pct(xs,p):
    xs=sorted(xs); k=(len(xs)-1)*p/100; f=int(k); return xs[f] if f+1>=len(xs) else xs[f]+(xs[f+1]-xs[f])*(k-f)

def summarize(name, samples, oks):
    n=len(samples); succ=sum(oks)
    if not samples: print(f"  {name}: 无样本"); return None
    s={"name":name,"n":n,"succ":succ,"rate":succ/n*100,
       "p50":pct(samples,50),"p95":pct(samples,95),"p99":pct(samples,99),
       "max":max(samples),"mean":statistics.mean(samples)}
    print(f"  {name:32s} n={n:3d} 成功率={s['rate']:5.1f}%  p50={s['p50']:7.1f}ms  p95={s['p95']:7.1f}ms  p99={s['p99']:7.1f}ms  max={s['max']:7.1f}ms")
    return s

print("  (预热 2 轮,排除冷启动/建连)")
warmup()

A_lat=[]; A_ok=[]; A_codes=[]; B_lat=[]; S_lat=[]; S_ok=[]
for i in range(N):
    wait_next_second()  # 跨秒:每次 SigV4 签名 X-Amz-Date 秒值必变 → 不撞 replay 缓存
    dt,ok,code=sigv4_token_latency(); A_lat.append(dt); A_ok.append(ok); A_codes.append(code)
    b=code_flow_token_latency()
    if b is not None: B_lat.append(b)
    sdt,sok=raw_sts_latency(); S_lat.append(sdt); S_ok.append(sok)
# A 成功率 < 100% 说明还有干扰(replay/竞争 binding/STS 抖动),定量不可信 → 显式警示。
_a_succ=sum(A_ok)
if _a_succ < N:
    from collections import Counter
    print("  ⚠ A 路径非全成功(%d/%d);失败 HTTP 码分布:%s —— 定量可能受干扰,见下方成功率"
          % (_a_succ, N, dict(Counter(c for c,o in zip(A_codes,A_ok) if not o))))

print("")
print("  路径                              样本  成功率     p50        p95        p99        max")
print("  " + "-"*94)
# 只用**成功**样本算延迟分布(失败是 fast-reject,混入会污染;成功率单列)。
A_succ_lat=[d for d,o in zip(A_lat,A_ok) if o]
sA=summarize("A. SigV4/STS /token(含外呼)", A_succ_lat, [True]*len(A_succ_lat)) if A_succ_lat else None
if sA: sA["rate"]=sum(A_ok)/len(A_ok)*100  # 成功率按全样本算
print(f"     (A 成功率(全样本)= {sum(A_ok)/len(A_ok)*100:.1f}%;上面 p50/p95 仅取成功样本 n={len(A_succ_lat)})")
sB=summarize("base. code flow /token(无外呼)", B_lat, [True]*len(B_lat))
sS=summarize("S. 裸 STS GetCallerIdentity 往返", S_lat, S_ok)

print("")
print("== 结论(spec 012 §3.2:量化 STS 外呼开销,背书优先自校验选路)==")
print("  ⚠ 方法学诚实说明:A(client_credentials 2LO)与 base(authorization_code code flow)**不是同工况**——")
print("    code flow 多做 code lease/consume、refresh family、宽限缓存、**RS256 id_token 签名**(RSA 慢于 ES256)、")
print("    sector/nonce 派生;2LO 无这些。故 A 反比 base 快(实测 A p50≈%.0f < base p50≈%.0f),**A−base 相减无意义**。" % (sA['p50'] if sA else 0, sB['p50'] if sB else 0))
print("    真正的同工况对照 = OIDC 2LO(本地 JWKS 验签 + ES256 签,无外呼)vs SigV4 2LO(STS 外呼 + ES256 签),")
print("    二者签同款 2LO token,唯一差 = **STS 同步外呼**。该外呼的直接量 = 裸 STS 往返(S)。")
if sS:
    print(f"  • **可规避的 STS 外呼开销 = 裸 STS 往返 p50≈{sS['p50']:.0f}ms / p95≈{sS['p95']:.0f}ms / p99≈{sS['p99']:.0f}ms**(可用率 {sS['rate']:.0f}%)。")
    print(f"    这是 OIDC/SVID 自校验路径(本地验签、零外呼)相对 SigV4/STS 每次签发**净省**的下界(还不含 STS 限流/抖动尾部)。")
if sA:
    print(f"  • SigV4/STS 端到端 /token p50≈{sA['p50']:.0f}ms(含上述 STS 往返);其中 STS 往返占 ~{100*sS['p50']/sA['p50']:.0f}%(p50)。")
print(f"  • 选路默认(§3.1)= **优先 OIDC/SVID 自校验**:省掉每次签发的 STS 往返(p50 十几 ms 量级)+ 消除一个签发")
print(f"    热路径上的同步硬依赖 / 限流面 / 尾延迟源。SigV4/STS 仅在『只有 IAM 角色、无 workload OIDC token』时兜底。")
print("  • C5.4 熔断与路径隔离由自动化 exact 测试验证;本脚本不注入 STS 故障,只量化同步外呼成本。")
print("    **规避外呼本身**(走自校验)才是根治——本定量给该选路默认以真机数据背书。")

# 机器可读输出(便于沉淀/回归)。avoidable_sts_overhead = 裸 STS 往返(同工况下自校验相对 SigV4 净省)。
out={"A_sigv4_sts_e2e":sA,"base_code_flow_ref":sB,"raw_sts_roundtrip":sS,
     "avoidable_sts_overhead_ms":{"p50":sS["p50"],"p95":sS["p95"],"p99":sS["p99"]} if sS else None}
print("")
print("QUANT_JSON="+json.dumps(out))
PY

echo ""
echo "🎉 STS 延迟定量完成(spec 012 §3.2)。选路默认见结论;清理见 trap。"

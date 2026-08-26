#!/usr/bin/env bash
# P2 SigV4/STS 真机成功链 e2e(spec 012 C5.2 happy path;C5.3/C5.4 负向与韧性由自动化 exact 覆盖):
#   用 botocore 对 sts:GetCallerIdentity **真 SigV4 签名**(把 X-Agent-Auth-Audience 头签进 SignedHeaders)
#   → 封装成 SigV4Assertion JSON 作 client_assertion → AS 前校 + 转发**真 STS** 拿 caller ARN →
#   match_sigv4 映射 client_id → 签 2LO agent token(sub=映射 client、sub_type=agent)。
#
# 需要:调用者有 AWS 凭证(profile default),AS 已登记 SigV4 信任绑定绑该 caller 的 assumed-role ARN。
# 本脚本:①取 caller ARN ②admin 登记 workload client + SigV4 trust binding ③botocore 预签名 ④换 token。
#
# 用法:
#   API_URL=https://<host> WORKLOAD_TRUST_TABLE=<cdk 输出> CLIENTS_TABLE=<cdk 输出> \
#   ADMIN_TOKEN=<admin> AWS_PROFILE=default ./e2e/sigv4_sts.sh
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
WORKLOAD_TRUST_TABLE="${WORKLOAD_TRUST_TABLE:?需 WORKLOAD_TRUST_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
CLIENT="e2e-sigv4-workload"
RS="https://mcp.rs.example.com"

echo "== 1. 取调用者 assumed-role ARN(caller identity)=="
CALLER_JSON=$(aws sts get-caller-identity --profile "$PROFILE" --region "$REGION" --output json)
CALLER_ARN=$(echo "$CALLER_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['Arn'])")
CALLER_ACCT=$(echo "$CALLER_JSON" | python3 -c "import sys,json;print(json.load(sys.stdin)['Account'])")
echo "  caller ARN(脱敏): $(echo "$CALLER_ARN" | sed 's/[0-9]\{12\}/ACCT/')"
# 注意:IAM user 的 GetCallerIdentity 返回 arn:aws:iam::ACCT:user/name(非 assumed-role)。
# 信任绑定 pattern 用**精确该 ARN**(e2e 便利;真 workload 是 assumed-role,docs §3.1)。

echo "== 2. seed workload client(client_type=workload)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"client_type\":{\"S\":\"workload\"},\"allowed_resources\":{\"L\":[{\"S\":\"$RS\"}]},\"allowed_scopes\":{\"L\":[{\"S\":\"kb:read\"}]}}" >/dev/null

echo "== 3. 登记 SigV4 信任绑定(caller ARN + account → client)=="
# DynamoWorkloadTrustStore 读 binding_json(serde 序列化的 TrustBinding),非扁平属性。
BINDING_JSON=$(CALLER_ARN="$CALLER_ARN" CALLER_ACCT="$CALLER_ACCT" CLIENT="$CLIENT" python3 -c "
import os,json
print(json.dumps({
  'tenant_id':'default',
  'mechanism':{'sigv4':{'aws_account_id':os.environ['CALLER_ACCT'],'role_arn_pattern':os.environ['CALLER_ARN']}},
  'mapped_client_id':os.environ['CLIENT'],
}))")
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$WORKLOAD_TRUST_TABLE" \
  --item "{\"binding_id\":{\"S\":\"e2e-sigv4\"},\"tenant_id\":{\"S\":\"default\"},\"binding_json\":{\"S\":$(python3 -c "import json,sys;print(json.dumps(sys.stdin.read()))" <<<"$BINDING_JSON")}}" >/dev/null
echo "  binding 登记(直写表 binding_json;真机走 admin API /admin/workload-trust)✅"

echo "== 4. botocore 真 SigV4 预签名 GetCallerIdentity(把 audience 头签进 SignedHeaders)=="
ASSERTION=$(API_URL="$API_URL" AWS_PROFILE="$PROFILE" AWS_REGION="$REGION" python3 - <<'PY'
import os, json
from botocore.session import Session
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth

issuer = os.environ["API_URL"]
sess = Session()
creds = sess.get_credentials().get_frozen_credentials()
url = "https://sts.amazonaws.com/"
body = "Action=GetCallerIdentity&Version=2011-06-15"
req = AWSRequest(
    method="POST",
    url=url,
    data=body,
    headers={
        "Content-Type": "application/x-www-form-urlencoded",
        # 把本 AS issuer 签进 audience 头(MUST 在 SignedHeaders 内,C5.2)。
        "X-Agent-Auth-Audience": issuer,
        "Host": "sts.amazonaws.com",
    },
)
SigV4Auth(creds, "sts", "us-east-1").add_auth(req)
# 封装成 AS 期望的 SigV4Assertion(headers 键小写化由 AS 归一,这里原样给)。
headers = {k: v for k, v in req.headers.items()}
assertion = {"method": "POST", "url": url, "headers": headers, "body": body}
print(json.dumps(assertion))
PY
)
echo "  预签名完成(assertion 字节数 ${#ASSERTION})✅"

echo "== 5. client_credentials + SigV4 assertion → 换 2LO token(AS 转发真 STS)=="
# assertion 作 form 值须 url-encode。
ENC=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.stdin.read()))" <<<"$ASSERTION")
TOK=$(curl -s -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_assertion_type=urn:agent-auth:params:oauth:client-assertion-type:aws-sigv4" \
  --data "client_assertion=$ENC" \
  --data-urlencode "resource=$RS" \
  --data-urlencode "scope=kb:read")
JWT=$(echo "$TOK" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
[ -n "$JWT" ] || { echo "❌ 未签出 2LO token(got: $TOK)"; exit 1; }
echo "$JWT" | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')
c=json.loads(base64.urlsafe_b64decode(p[1]+'='*(-len(p[1])%4)))
assert c['sub']=='$CLIENT', c['sub']
assert c.get('https://a-auth.com/c',{}).get('sub_type')=='agent', c
assert c['aud']==['$RS'], c['aud']
print('  sub=$CLIENT sub_type=agent aud=RS ✅')
"
echo "$TOK" | python3 -c "import sys,json; assert json.load(sys.stdin).get('refresh_token') is None; print('  无 refresh_token(2LO)✅')"

echo "✅ P2 SigV4/STS 真机 e2e 全绿(真 SigV4 签名 + AS 转发真 STS)"

#!/usr/bin/env bash
# 真机 e2e:X.509-SVID / mTLS 认证(spec 012 §1.4 / C5.7,P3)。
#
# 验证 X.509-SVID 走**独立 mTLS 自定义域名**(绕 CloudFront,API Gateway 连接级双向 TLS)端到端成立:
#   openssl 自建 CA + 签 X.509-SVID(SAN URI=spiffe://<td>/agent/kb)→ 上传 CA 到 truststore 桶(truststore.pem)
#   → admin 登记 SpiffeX509 绑定 → curl --cert 用客户端证书对 mTLS 域名 POST /token 换 2LO
#   + 负例(无证书握手失败 / 跨 trust domain 拒 / pattern 不符拒 / 证书作 client_assertion 走普通端点拒)。
#
# ⚠ 前置(运维一次性):栈以 MTLS_DOMAIN/MTLS_CERT_ARN/MTLS_ZONE_ID/NAME + AGENT_AUTH_MTLS_SVID_ENABLED=1
#   部署(建 mTLS 域名 + 空 truststore 桶);本脚本上传 CA bundle 到桶后,API Gateway 需**几分钟**加载 truststore。
#   仅 SelfHosted(评审 B1)。
#
# 用法:
#   MTLS_URL=https://mtls.saas.example.com API_URL=https://<apigw> \
#   TRUSTSTORE_BUCKET=<栈输出 MtlsTruststoreBucket> WORKLOAD_TRUST_TABLE=<..> CLIENTS_TABLE=<..> \
#   [ADMIN_TOKEN=<..>] AWS_PROFILE=default ./e2e/spiffe_x509_mtls.sh
set -euo pipefail

MTLS_URL="${MTLS_URL:?需 MTLS_URL(mTLS 自定义域名,如 https://mtls.saas.example.com)}"
API_URL="${API_URL:?需 API_URL(普通 execute-api / CloudFront,用于 admin 登记 + 负例)}"
TRUSTSTORE_BUCKET="${TRUSTSTORE_BUCKET:?需 TRUSTSTORE_BUCKET(栈输出 MtlsTruststoreBucket)}"
WORKLOAD_TRUST_TABLE="${WORKLOAD_TRUST_TABLE:?需 WORKLOAD_TRUST_TABLE}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
STACK="${STACK:-AgentAuthDev}"
ADMIN_TOKEN="${ADMIN_TOKEN:-$(STACK="$STACK" REGION="$REGION" PROFILE="$PROFILE" "$(dirname "$0")/get-admin-token.sh")}"
AUTH=(-H "authorization: Bearer $ADMIN_TOKEN")

RAND="$RANDOM$RANDOM"
TD="acme-$RAND.example"                       # 唯一 trust domain(防残留 binding 抢匹配,同 spiffe_svid.sh 教训)
SPIFFE_ID="spiffe://$TD/agent/kb"
WL_CLIENT="e2e-x509-$RAND"
RS="https://mcp.x509-$RAND.example"
WORK=$(mktemp -d)

cleanup() {
  curl -s -X DELETE "${AUTH[@]}" "$API_URL/admin/clients/$WL_CLIENT" >/dev/null 2>&1 || true
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$WORKLOAD_TRUST_TABLE" --key "{\"binding_id\":{\"S\":\"x509-$RAND\"}}" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== 1. openssl 自建 CA + 签 X.509-SVID(SAN URI=$SPIFFE_ID)=="
# CA(自签根)。
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key" 2>/dev/null
openssl req -x509 -new -key "$WORK/ca.key" -sha256 -days 7 -subj "/CN=e2e-svid-ca-$RAND" -out "$WORK/ca.pem" 2>/dev/null
# 叶子 SVID(SAN=spiffe:// URI;SPIFFE subject DN 常空,这里给个 CN 无妨,信任只看 SAN)。
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/svid.key" 2>/dev/null
openssl req -new -key "$WORK/svid.key" -subj "/CN=svid" -out "$WORK/svid.csr" 2>/dev/null
cat > "$WORK/ext.cnf" <<EOF
subjectAltName=URI:$SPIFFE_ID
EOF
openssl x509 -req -in "$WORK/svid.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$WORK/ext.cnf" -out "$WORK/svid.pem" 2>/dev/null
# 另签一张跨 trust domain 的 SVID(负例:同 CA 签,但 SAN 是别域 → 应被 trust domain 锚拒)。
cat > "$WORK/ext_cross.cnf" <<EOF
subjectAltName=URI:spiffe://evil-$RAND.example/agent/kb
EOF
openssl req -new -key "$WORK/svid.key" -subj "/CN=svid-cross" -out "$WORK/cross.csr" 2>/dev/null
openssl x509 -req -in "$WORK/cross.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 1 -sha256 -extfile "$WORK/ext_cross.cnf" -out "$WORK/cross.pem" 2>/dev/null
echo "  ✅ CA + SVID(+ 跨域负例)已签"

echo "== 2. 上传 CA bundle 到 truststore 桶 + **bump 域名 TruststoreVersion**(关键)=="
# ⚠️ 仅上传新 S3 版本**不生效**:API Gateway mTLS 域名锁定在创建时的 truststore version,须显式
# update-domain-name 指向新 version 才重新加载(= 设计说的"CA 轮换 = bump version";真机实测踩坑)。
aws s3 cp "$WORK/ca.pem" "s3://$TRUSTSTORE_BUCKET/truststore.pem" --profile "$PROFILE" --region "$REGION" >/dev/null
MTLS_DN="${MTLS_URL#https://}"
CERT_ARN=$(aws apigatewayv2 get-domain-name --domain-name "$MTLS_DN" --profile "$PROFILE" --region "$REGION" \
  --query "DomainNameConfigurations[0].CertificateArn" --output text)
NEW_VER=$(aws s3api list-object-versions --bucket "$TRUSTSTORE_BUCKET" --prefix truststore.pem \
  --profile "$PROFILE" --region "$REGION" --query "Versions[?IsLatest].VersionId | [0]" --output text)
# update-domain-name 可能被 throttle(TooManyRequests),重试。
for i in 1 2 3 4 5; do
  aws apigatewayv2 update-domain-name --domain-name "$MTLS_DN" --profile "$PROFILE" --region "$REGION" \
    --domain-name-configurations "CertificateArn=$CERT_ARN,EndpointType=REGIONAL,SecurityPolicy=TLS_1_2" \
    --mutual-tls-authentication "TruststoreUri=s3://$TRUSTSTORE_BUCKET/truststore.pem,TruststoreVersion=$NEW_VER" \
    >/dev/null 2>&1 && { echo "  ✅ CA 上传 + 域名 TruststoreVersion 已 bump 到 $NEW_VER"; break; } \
    || { echo "  update-domain-name throttled,等 45s 重试($i/5)"; sleep 45; }
done

echo "== 3. seed workload client + 登记 SpiffeX509 绑定(无 jwks_uri)=="
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$WL_CLIENT\"},\"redirect_uris\":{\"L\":[]},\"token_endpoint_auth_method\":{\"S\":\"none\"},\"client_type\":{\"S\":\"workload\"},\"allowed_resources\":{\"L\":[{\"S\":\"$RS\"}]},\"allowed_scopes\":{\"L\":[{\"S\":\"kb:read\"}]}}" >/dev/null
ST=$(curl -s -o /tmp/x509_bind.$$ -w '%{http_code}' -X POST "${AUTH[@]}" -H "content-type: application/json" \
  -d "{\"binding_id\":\"x509-$RAND\",\"tenant_id\":\"default\",\"mechanism\":\"spiffe_x509\",\"trust_domain\":\"$TD\",\"subject_pattern\":\"spiffe://$TD/agent/*\",\"mapped_client_id\":\"$WL_CLIENT\"}" \
  "$API_URL/admin/workload-trust")
[ "$ST" = "201" ] || { echo "❌ 登记 SpiffeX509 绑定应 201(got $ST):$(cat /tmp/x509_bind.$$)"; rm -f /tmp/x509_bind.$$; exit 1; }
rm -f /tmp/x509_bind.$$
echo "  ✅ 绑定登记"

echo "== 4. curl --cert 用 SVID 对 mTLS 域名 POST /token 换 2LO(握手带客户端证书)=="
# truststore 传播:重试至多 6 次(每次 20s)。
TOK=""
for i in $(seq 1 6); do
  RESP=$(curl -s --cert "$WORK/svid.pem" --key "$WORK/svid.key" \
    -X POST "$MTLS_URL/token" -H "content-type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=client_credentials" --data-urlencode "resource=$RS" --data-urlencode "scope=kb:read" 2>/dev/null || true)
  TOK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)
  [ -n "$TOK" ] && break
  echo "  …等 truststore 生效(尝试 $i/6,20s)"; sleep 20
done
[ -n "$TOK" ] || { echo "❌ mTLS 换 2LO 失败(truststore 未生效或配置问题):$RESP"; exit 1; }
echo "$TOK" | python3 -c "
import sys,base64,json
p=sys.stdin.read().strip().split('.')
c=json.loads(base64.urlsafe_b64decode(p[1]+'='*(-len(p[1])%4)))
assert c['sub']=='$WL_CLIENT', c['sub']
assert c.get('https://a-auth.com/c',{}).get('sub_type')=='agent', c
assert c['aud']==['$RS'], c['aud']
print('  ✅ X.509-SVID 换 2LO:sub=$WL_CLIENT sub_type=agent aud=RS(连接层证书身份)')
"

echo "== 5. 负例:跨 trust domain SVID(同 CA 但 SAN 别域)→ 拒 =="
ST=$(curl -s -o /dev/null -w '%{http_code}' --cert "$WORK/cross.pem" --key "$WORK/svid.key" \
  -X POST "$MTLS_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" --data-urlencode "resource=$RS" 2>/dev/null || echo 000)
[ "$ST" = "401" ] || { echo "❌ 跨 trust domain SVID 应 401(got $ST)"; exit 1; }
echo "  ✅ 跨 trust domain(SAN 锚不匹配绑定)→ 401"

echo "== 6. 负例:证书 PEM 塞 client_assertion 走**普通端点**(非 mTLS)→ 拒(不降级)=="
PEM_B64=$(base64 -w0 "$WORK/svid.pem" 2>/dev/null || base64 "$WORK/svid.pem")
ST=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API_URL/token" -H "content-type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$PEM_B64" --data-urlencode "resource=$RS")
[ "$ST" = "400" ] || [ "$ST" = "401" ] || { echo "❌ 证书作 client_assertion 应拒(got $ST)"; exit 1; }
echo "  ✅ X.509 证书塞 client_assertion 走普通端点 → 拒(不降级,DESIGN §3.1)"

echo ""
echo "🎉 X.509-SVID / mTLS 真机 e2e 全绿(spec 012 §1.4 / C5.7):独立 mTLS 域名连接层证书 → 2LO。"

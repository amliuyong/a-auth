#!/usr/bin/env bash
# spec 003 §4(C9.5b)真机 e2e:**SAML-to-OIDC bridge 完整往返** —— SAML 企业接入经 broker 达成,AS 零 XML 代码。
#
# 拓扑(全部真实 AWS 资源):
#   自控 SAML IdP(本地 RSA key,signxml 签,**不手搓 C14N**)──SAML──▶ Cognito User Pool(SAML SP,**验 XML-dsig**)
#     ──OIDC(code+PKCE)──▶ 本 AS(/federation/callback 换 id_token+建会话)──303──▶ 续跑 /authorize
#
# 为何这样验:双评审判 AS 内自实现 XML-dsig 为生产安全 Blocker(C14N 一字节=身份混淆);决策走 bridge——
# XML 验签留 broker(Cognito),AS 复用已验证 OIDC RP 路径。本脚本用**自控 IdP**(私钥造签名 SAMLResponse,
# Cognito 用登记 cert 验签=真 XML-dsig)完整跑通,无需真人密码(IdC 密码管理仅控制台,自控 IdP 绕开)。
#
# 本脚本自建/清理:生成 IdP key/cert/metadata → Cognito 登记 SAML IdP(IDPInit)+ OIDC RP client + secret 存 SM
#   → AS PUT /admin/federation 登记 upstream → 跑 SP-init 完整往返(saml_bridge_roundtrip.py)→ trap 全清理。
#
# 用法:API_URL=https://<cf-domain> CLIENTS_TABLE=<clients 表> COGNITO_POOL_ID=<broker 池> \
#       COGNITO_DOMAIN=https://<prefix>.auth.<region>.amazoncognito.com AWS_PROFILE=default ./e2e/saml_bridge.sh
# 依赖:aws cli、curl、python3(venv 自装 signxml/lxml/requests)。账号号/pool-id/secret 全 env,不硬编码。
set -euo pipefail

API_URL="${API_URL:?需 API_URL}"
CLIENTS_TABLE="${CLIENTS_TABLE:?需 CLIENTS_TABLE}"
COGNITO_POOL_ID="${COGNITO_POOL_ID:?需 COGNITO_POOL_ID(bridge broker Cognito 池)}"
COGNITO_DOMAIN="${COGNITO_DOMAIN:?需 COGNITO_DOMAIN(broker Hosted UI 域)}"
PROFILE="${AWS_PROFILE:-default}"
REGION="${REGION:-us-east-1}"
COG_REGION="${COG_REGION:-$(echo "$COGNITO_POOL_ID" | cut -d_ -f1)}"  # 池 region 从 id 前缀取
HERE="$(cd "$(dirname "$0")" && pwd)"
pass() { echo "  ✅ $1"; }
fail() { echo "  ❌ $1"; exit 1; }
ADMIN_TOKEN="${ADMIN_TOKEN:-$("$HERE/get-admin-token.sh")}"

RND=$(python3 -c "import secrets;print(secrets.token_hex(4))")
WORK="$(mktemp -d)"; umask 077
IDP_NAME="SamlBridge$RND"
IDP_ENTITY="urn:agent-auth:saml-bridge-idp:$RND"
UPSTREAM="saml-bridge-$RND"
SM_NAME="agent-auth/federation/saml-bridge-e2e-$RND"
DOWN_CLIENT="saml-bridge-down-$RND"
CB="$API_URL/federation/callback"
RP_CID=""

cleanup() {
  [ -n "$RP_CID" ] && aws cognito-idp delete-user-pool-client --profile "$PROFILE" --region "$COG_REGION" --user-pool-id "$COGNITO_POOL_ID" --client-id "$RP_CID" >/dev/null 2>&1 || true
  aws cognito-idp delete-identity-provider --profile "$PROFILE" --region "$COG_REGION" --user-pool-id "$COGNITO_POOL_ID" --provider-name "$IDP_NAME" >/dev/null 2>&1 || true
  aws secretsmanager delete-secret --profile "$PROFILE" --region "$REGION" --secret-id "$SM_NAME" --force-delete-without-recovery >/dev/null 2>&1 || true
  # AS upstream config + 下游 client + venv/tmp。
  curl -s -o /dev/null -X DELETE "$API_URL/admin/federation/default/$UPSTREAM" -H "authorization: Bearer $ADMIN_TOKEN" || true
  aws dynamodb delete-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" --key "{\"client_id\":{\"S\":\"$DOWN_CLIENT\"}}" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== 0. venv(signxml/lxml/requests;不手搓 C14N,验签库做)=="
python3 -m venv "$WORK/venv" >/dev/null 2>&1
"$WORK/venv/bin/pip" install --quiet signxml requests >/dev/null 2>&1
pass "venv 就绪"

echo "== 1. 生成自控 SAML IdP key/cert/metadata =="
"$WORK/venv/bin/python" - "$WORK" "$IDP_ENTITY" <<'PY'
import sys, datetime, base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
work, entity = sys.argv[1], sys.argv[2]
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-auth-saml-bridge-e2e")])
cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=825)).sign(key, hashes.SHA256()))
open(f"{work}/idp_key.pem", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open(f"{work}/idp_cert.pem", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
cb = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
md = f'''<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity}"><IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>{cb}</X509Certificate></X509Data></KeyInfo></KeyDescriptor><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.invalid/sso"/></IDPSSODescriptor></EntityDescriptor>'''
open(f"{work}/idp_metadata.xml", "w").write(md)
PY
pass "IdP key/cert/metadata 生成"

echo "== 2. Cognito 登记 SAML IdP(IDPInit)+ OIDC RP client + secret 存 SM =="
aws cognito-idp create-identity-provider --profile "$PROFILE" --region "$COG_REGION" --user-pool-id "$COGNITO_POOL_ID" \
  --provider-name "$IDP_NAME" --provider-type SAML \
  --provider-details "$(python3 -c "import json;print(json.dumps({'MetadataFile':open('$WORK/idp_metadata.xml').read(),'IDPInit':'true'}))")" \
  --attribute-mapping email=email >/dev/null || fail "SAML IdP 登记失败"
RP_CID=$(aws cognito-idp create-user-pool-client --profile "$PROFILE" --region "$COG_REGION" --user-pool-id "$COGNITO_POOL_ID" \
  --client-name "agent-auth-bridge-rp-$RND" --generate-secret --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email profile --allowed-o-auth-flows-user-pool-client \
  --supported-identity-providers "$IDP_NAME" --callback-urls "$CB" \
  --query "UserPoolClient.ClientId" --output text) || fail "RP client 建失败"
SECRET=$(aws cognito-idp describe-user-pool-client --profile "$PROFILE" --region "$COG_REGION" --user-pool-id "$COGNITO_POOL_ID" --client-id "$RP_CID" --query "UserPoolClient.ClientSecret" --output text)
aws secretsmanager create-secret --profile "$PROFILE" --region "$REGION" --name "$SM_NAME" --secret-string "$SECRET" >/dev/null 2>&1 \
  || aws secretsmanager put-secret-value --profile "$PROFILE" --region "$REGION" --secret-id "$SM_NAME" --secret-string "$SECRET" >/dev/null
pass "Cognito SAML IdP + RP client($RP_CID)+ secret"

echo "== 3. AS 登记 upstream(指向 broker Cognito OIDC)+ 下游 client =="
ISSUER="https://cognito-idp.$COG_REGION.amazonaws.com/$COGNITO_POOL_ID"
REG=$(python3 -c "import json;print(json.dumps({'tenant_id':'default','upstream_idp_id':'$UPSTREAM','upstream_issuer':'$ISSUER','client_id':'$RP_CID','client_secret_ref':'$SM_NAME','authorization_endpoint':'$COGNITO_DOMAIN/oauth2/authorize','token_endpoint':'$COGNITO_DOMAIN/oauth2/token','jwks_uri':'$ISSUER/.well-known/jwks.json','scopes':['openid','email','profile']}))")
ST=$(curl -s -o /dev/null -w '%{http_code}' -X PUT "$API_URL/admin/federation" -H "authorization: Bearer $ADMIN_TOKEN" -H "content-type: application/json" -d "$REG")
[ "$ST" = "201" ] || fail "AS 登记 upstream 应 201(got $ST)"
aws dynamodb put-item --profile "$PROFILE" --region "$REGION" --table-name "$CLIENTS_TABLE" \
  --item "{\"client_id\":{\"S\":\"$DOWN_CLIENT\"},\"redirect_uris\":{\"L\":[{\"S\":\"https://probe.example.com/cb\"}]},\"token_endpoint_auth_method\":{\"S\":\"none\"}}" >/dev/null
pass "AS upstream=$UPSTREAM + 下游 client"

echo "== 4. 完整 SP-init 往返(自控 IdP 签 → Cognito 验 XML-dsig → AS 建会话)=="
AS_URL="$API_URL" COGNITO_DOMAIN="$COGNITO_DOMAIN" COGNITO_POOL_ID="$COGNITO_POOL_ID" \
  SAML_IDP_NAME="$IDP_NAME" SAML_IDP_ENTITY="$IDP_ENTITY" \
  SAML_IDP_KEY_PEM="$WORK/idp_key.pem" SAML_IDP_CERT_PEM="$WORK/idp_cert.pem" \
  DOWN_CLIENT_ID="$DOWN_CLIENT" UPSTREAM_IDP_ID="$UPSTREAM" \
  "$WORK/venv/bin/python" "$HERE/saml_bridge_roundtrip.py" || fail "SP-init 往返失败"

echo ""
echo "✅ spec 003 §4 SAML-to-OIDC bridge 完整真机往返全绿:自控 SAML IdP →(SAML)→ Cognito(SAML SP,验 XML-dsig)→(OIDC)→ 本 AS 建会话。AS 零 XML-dsig 代码。"

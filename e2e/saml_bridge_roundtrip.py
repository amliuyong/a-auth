#!/usr/bin/env python3
"""spec 003 §4 SAML-to-OIDC bridge 完整真机往返驱动(由 e2e/saml_bridge.sh 调,env 提供配置)。

证明 SAML 企业接入经 broker 达成,本 AS **零 XML-dsig 代码**:
  自控 SAML IdP(signxml 签名,不手搓 C14N)──SAML──▶ Cognito(SAML SP,**验 XML-dsig**)
    ──OIDC(code+PKCE)──▶ 本 AS(/federation/callback 换 id_token+建会话)──303──▶ 续跑 /authorize

无需真人密码:自控 IdP 的私钥造签名 SAMLResponse,Cognito 用登记的 IdP cert 验签(真 XML-dsig)。
SP-initiated:从 AS 发起 → 抓 Cognito 生成的 SAMLRequest ID + RelayState → 造带 InResponseTo 的
签名 SAMLResponse → POST Cognito ACS → Cognito 验签完成 SP-init → 302 回 AS callback(code+state)。

**凭证不打印**;所有配置走 env(见 saml_bridge.sh)。IdP 私钥仅测试临时(tmp,不进 repo)。
"""
import os, sys, base64, zlib, uuid, datetime, urllib.parse
import requests
from lxml import etree
from signxml import XMLSigner, methods

AS = os.environ["AS_URL"].rstrip("/")
COGNITO_DOMAIN = os.environ["COGNITO_DOMAIN"].rstrip("/")   # https://<prefix>.auth.<region>.amazoncognito.com
POOL = os.environ["COGNITO_POOL_ID"]
IDP_NAME = os.environ.get("SAML_IDP_NAME", "SamlTestIdp")   # Cognito 里登记的 SAML IdP 名
IDP_ENTITY = os.environ["SAML_IDP_ENTITY"]                  # 自控 IdP entity_id
IDP_KEY = os.environ["SAML_IDP_KEY_PEM"]                    # 自控 IdP 私钥 PEM 路径
IDP_CERT = os.environ["SAML_IDP_CERT_PEM"]                  # 自控 IdP cert PEM 路径
DOWN_CID = os.environ["DOWN_CLIENT_ID"]                     # 本 AS 下游 client
DOWN_CB = os.environ.get("DOWN_REDIRECT", "https://probe.example.com/cb")
UPSTREAM = os.environ.get("UPSTREAM_IDP_ID", "saml-test")   # AS 登记的 upstream
EMAIL = os.environ.get("SAML_TEST_EMAIL", "saml-bridge-test@example.com")
ACS = f"{COGNITO_DOMAIN}/saml2/idpresponse"
SP_ENTITY = f"urn:amazon:cognito:sp:{POOL}"
CH = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"  # 任意合法 S256 challenge

s = requests.Session()
P = "urn:oasis:names:tc:SAML:2.0:protocol"
SA = "urn:oasis:names:tc:SAML:2.0:assertion"


def fail(m):
    print(f"FAIL: {m}", file=sys.stderr); sys.exit(1)


def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_signed_response(in_response_to):
    now = datetime.datetime.now(datetime.timezone.utc)
    rid, aid = "_" + uuid.uuid4().hex, "_" + uuid.uuid4().hex
    resp = etree.Element(f"{{{P}}}Response", nsmap={"samlp": P}, ID=rid, Version="2.0",
                         IssueInstant=iso(now), Destination=ACS, InResponseTo=in_response_to)
    etree.SubElement(resp, f"{{{SA}}}Issuer", nsmap={"saml": SA}).text = IDP_ENTITY
    st = etree.SubElement(resp, f"{{{P}}}Status")
    etree.SubElement(st, f"{{{P}}}StatusCode", Value="urn:oasis:names:tc:SAML:2.0:status:Success")
    a = etree.SubElement(resp, f"{{{SA}}}Assertion", nsmap={"saml": SA}, ID=aid, Version="2.0", IssueInstant=iso(now))
    etree.SubElement(a, f"{{{SA}}}Issuer").text = IDP_ENTITY
    su = etree.SubElement(a, f"{{{SA}}}Subject")
    nid = etree.SubElement(su, f"{{{SA}}}NameID", Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"); nid.text = EMAIL
    sc = etree.SubElement(su, f"{{{SA}}}SubjectConfirmation", Method="urn:oasis:names:tc:SAML:2.0:cm:bearer")
    etree.SubElement(sc, f"{{{SA}}}SubjectConfirmationData", Recipient=ACS,
                     NotOnOrAfter=iso(now + datetime.timedelta(minutes=5)), InResponseTo=in_response_to)
    c = etree.SubElement(a, f"{{{SA}}}Conditions", NotBefore=iso(now - datetime.timedelta(minutes=5)),
                         NotOnOrAfter=iso(now + datetime.timedelta(minutes=5)))
    ar = etree.SubElement(c, f"{{{SA}}}AudienceRestriction")
    etree.SubElement(ar, f"{{{SA}}}Audience").text = SP_ENTITY
    an = etree.SubElement(a, f"{{{SA}}}AuthnStatement", AuthnInstant=iso(now), SessionIndex=aid)
    acx = etree.SubElement(an, f"{{{SA}}}AuthnContext")
    etree.SubElement(acx, f"{{{SA}}}AuthnContextClassRef").text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    ats = etree.SubElement(a, f"{{{SA}}}AttributeStatement")
    at = etree.SubElement(ats, f"{{{SA}}}Attribute", Name="email")
    etree.SubElement(at, f"{{{SA}}}AttributeValue").text = EMAIL
    # signxml 做 XML-dsig(exclusive-C14N + RSA-SHA256;不手搓 C14N)。
    signer = XMLSigner(method=methods.enveloped, signature_algorithm="rsa-sha256",
                       digest_algorithm="sha256", c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    sa = signer.sign(a, key=open(IDP_KEY, "rb").read(), cert=open(IDP_CERT, "rb").read(), reference_uri=aid)
    resp.replace(a, sa)
    return base64.b64encode(etree.tostring(resp)).decode()


# 1. AS 发起 SP-init(存 state/nonce/PKCE)→ 302 到 Cognito authorize。
authz = (f"{AS}/authorize?response_type=code&client_id={DOWN_CID}"
         f"&redirect_uri={urllib.parse.quote(DOWN_CB, safe='')}&code_challenge={CH}"
         f"&code_challenge_method=S256&scope=openid&state=samlbr&idp_hint={UPSTREAM}")
r = s.get(authz, allow_redirects=False, timeout=20)
if r.status_code != 303 or COGNITO_DOMAIN not in r.headers.get("location", ""):
    fail(f"发起腿应 303→Cognito,实得 {r.status_code} {r.headers.get('location','')[:80]}")
cog = r.headers["location"]
print("[1] AS 发起 SP-init 303 → Cognito authorize ✓")

# 2. Cognito(SAML SP)+ identity_provider → 生成 SAMLRequest + RelayState,302 到自控 IdP SSO。
r = s.get(cog + f"&identity_provider={IDP_NAME}", allow_redirects=False, timeout=20)
idp_sso = r.headers.get("location", "")
if "SAMLRequest=" not in idp_sso:
    fail(f"Cognito 未生成 SAMLRequest(应作 SAML SP),实得 {r.status_code} {idp_sso[:80]}")
q = urllib.parse.parse_qs(urllib.parse.urlparse(idp_sso).query)
authn_xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15)
req_id = etree.fromstring(authn_xml).get("ID")
relay_state = q["RelayState"][0]
print(f"[2] Cognito(SAML SP)生成 SAMLRequest(ID={req_id[:16]}…)+ RelayState → 302 自控 IdP SSO ✓")

# 3. 自控 IdP 造带 InResponseTo 的签名 SAMLResponse(signxml,真 XML-dsig)。
saml_resp_b64 = build_signed_response(req_id)
print("[3] 自控 IdP 签名 SAMLResponse(signxml XML-dsig,InResponseTo 绑定)✓")

# 4. POST SAMLResponse + Cognito RelayState → Cognito ACS(Cognito 验 XML-dsig)→ 302 回 AS callback(code+state)。
r = s.post(ACS, data={"SAMLResponse": saml_resp_b64, "RelayState": relay_state}, allow_redirects=False, timeout=20)
cb = r.headers.get("location", "")
if r.status_code not in (302, 303) or f"{AS}/federation/callback" not in cb or "code=" not in cb:
    fail(f"Cognito 验签+SP-init 应 302→AS callback 带 code,实得 {r.status_code} {cb[:100]}")
print("[4] Cognito 验 XML-dsig 通过 → 302 回 AS /federation/callback(带 code+state)✓")

# 5. AS callback:换 Cognito id_token + 验签 + 建会话 → 303 续跑 /authorize。
r = s.get(cb, allow_redirects=False, timeout=20)
if r.status_code != 303:
    fail(f"AS 回调应 303 续跑,实得 {r.status_code}: {r.text[:200]}")
if "__Host-agent_auth_session=" not in r.headers.get("set-cookie", ""):
    fail(f"AS 回调应建本地会话 cookie,headers={dict(r.headers)}")
cont = r.headers["location"]
if "/authorize" not in cont:
    fail(f"应续跑回 /authorize,实得 {cont[:80]}")
print("[5] AS 换 id_token+验签+建会话(Set-Cookie __Host-agent_auth_session)→ 303 续跑 /authorize ✓")

print("\n=== SAML-to-OIDC bridge 完整真机往返全绿 ===")
print("自控 SAML IdP →(SAML,signxml 签)→ Cognito(SAML SP,**验 XML-dsig**)→(OIDC)→ 本 AS 建会话。")
print("本 AS 零 XML-dsig 代码:SAML 验签风险全部留在 broker(Cognito)。")

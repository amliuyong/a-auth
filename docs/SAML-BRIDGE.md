# SAML 上游联邦运维指南 —— SAML-to-OIDC bridge

> 决策真相源:[`DESIGN.md §7`](./DESIGN.md)(上游 IdP 联邦)+ [`CONFORMANCE.md C9.5b`](./CONFORMANCE.md)。本文是**运维 runbook**,不复述决策,只给"怎么配、怎么验、注意什么"。

## 为什么是 bridge(不在 AS 内自实现 SAML)

企业上游有两类:**OIDC**(Entra/Okta/Cognito/Auth0 都支持)与**纯 SAML-only**。本 AS **只作 OIDC RP**,**不在进程内解析/验签 SAML XML**。自实现 XML-dsig/C14N 会引入高风险攻击面(C14N 差异、XML Signature Wrapping、XXE/DTD 及证书和重放处理)。

**做法**:把 SAML 的 XML-dsig 验签**委托给久经考验的 broker**(AWS Cognito User Pool 作 SAML SP),broker 再以标准 OIDC 把身份桥接给本 AS。

```text
企业 SAML IdP  ──SAML 2.0──▶  Cognito User Pool          ──OIDC(code+PKCE)──▶  本 AS(OIDC RP)
(Entra/Okta/                (SAML SP + OIDC OP;              (/federation/callback 换 id_token
 AWS IdC/PingFederate/…)     **做 XML-dsig 验签**,AWS 维护)     + 验签 + 建会话,零 XML 代码)
```

**收益**:XML-dsig / C14N / XSW / XXE 全部攻击面留在 broker;本 AS 侧新增能力 = 0 行 XML 代码(仅复用 OIDC 联邦路径)。这是企业 SSO 主流做法(把 SAML 收敛到一个 OIDC 面)。

---

## 配置步骤

### 1 · broker(Cognito)侧:登记企业 SAML IdP

在作 broker 的 Cognito User Pool 里,把企业 SAML IdP 登记为 **SAML identity provider**(Cognito 承担 SAML SP 角色 + 做 XML-dsig 验签):

```bash
# provider-details 用企业 IdP 的 metadata(URL 或 XML 文件);Cognito 用其中的签名证书验 SAMLResponse。
aws cognito-idp create-identity-provider --profile <profile> --region <cog-region> \
  --user-pool-id <POOL_ID> \
  --provider-name "EnterpriseSaml" --provider-type SAML \
  --provider-details 'MetadataURL=https://<企业 IdP>/saml/metadata,IDPSignout=true' \
  --attribute-mapping email=email,name=name    # 上游 SAML attribute → Cognito 标准属性
```

- **企业 IdP 侧**要登记 Cognito 作 SP:
  - **ACS(Assertion Consumer Service)URL** = `https://<cognito-domain>/saml2/idpresponse`
  - **SP entity_id / Audience** = `urn:amazon:cognito:sp:<POOL_ID>`
  - 断言至少携带 `email`(供下游 `federated_user_id` 派生)。
- Cognito 支持 **SP-initiated**(推荐)与 IdP-initiated(`IDPInit=true`);签名算法用 RSA-SHA256(SHA-1 应在企业 IdP 侧禁用)。

### 2 · broker(Cognito)侧:建 OIDC RP client 供本 AS 接入

```bash
aws cognito-idp create-user-pool-client --profile <profile> --region <cog-region> \
  --user-pool-id <POOL_ID> --client-name "agent-auth-rp" --generate-secret \
  --allowed-o-auth-flows code --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client \
  --supported-identity-providers EnterpriseSaml \
  --callback-urls "https://<AS-host>/federation/callback"
```

取回 `ClientId` + `ClientSecret`。**client secret 绝不进 repo / 环境变量明文**——存 Secrets Manager:

```bash
aws secretsmanager create-secret --profile <profile> --region <as-region> \
  --name "agent-auth/federation/<idp>-rp-secret" --secret-string "<ClientSecret>"
```

> IAM 已授权本 AS Lambda `secretsmanager:GetSecretValue` 前缀 `agent-auth/federation/*`(最小权限,见 CDK)。

### 3 · 本 AS 侧:登记 upstream(指向 broker 的 OIDC)

本 AS 对 broker 就是**普通 OIDC 上游**(与 §4 已验证的 Cognito OIDC 路径同款,无 SAML 专属分支):

```bash
curl -X PUT "https://<AS-host>/admin/federation" \
  -H "authorization: Bearer <admin-token>" -H "content-type: application/json" -d '{
    "tenant_id": "default",
    "upstream_idp_id": "enterprise-saml",
    "upstream_issuer": "https://cognito-idp.<cog-region>.amazonaws.com/<POOL_ID>",
    "client_id": "<ClientId>",
    "client_secret_ref": "agent-auth/federation/<idp>-rp-secret",
    "authorization_endpoint": "https://<cognito-domain>/oauth2/authorize",
    "token_endpoint": "https://<cognito-domain>/oauth2/token",
    "jwks_uri": "https://cognito-idp.<cog-region>.amazonaws.com/<POOL_ID>/.well-known/jwks.json",
    "scopes": ["openid","email","profile"]
  }'
```

- `client_secret_ref` = **Secrets Manager 引用名**(不传明文)。
- `upstream_issuer` / `jwks_uri` = broker Cognito 池的 **issuer host**(`cognito-idp` 域),**非** Hosted UI 域;`authorization_endpoint` / `token_endpoint` = **Hosted UI 域**(`<domain>.auth.<region>.amazoncognito.com`)。
- 本 AS 部署需 `AGENT_AUTH_FEDERATION_ENABLED=1`(默认关;见 CDK / DEPLOYMENT)。

### 4 · 用户登录流

用户经本 AS 发起:`GET /authorize?...&idp_hint=enterprise-saml` → 303 到 broker Cognito authorize(带 `identity_provider=EnterpriseSaml`)→ Cognito 作 SAML SP 向企业 IdP 发 `SAMLRequest` → 用户在企业 IdP 登录 → SAML 断言回 Cognito(**Cognito 验 XML-dsig**)→ Cognito 签 OIDC id_token → 本 AS `/federation/callback` 换 token + 验 id_token + 建会话(`__Host-agent_auth_session`)→ 续跑 `/authorize`。**全程本 AS 不解析任何 XML。**

---

## 验证

`e2e/saml_bridge.sh`(+ `saml_bridge_roundtrip.py`)真机完整往返(用**自控测试 SAML IdP**,signxml 签,免企业 IdP + 免真人密码):

```bash
API_URL=https://<AS-host> CLIENTS_TABLE=<clients 表> \
  COGNITO_POOL_ID=<broker 池> COGNITO_DOMAIN=https://<prefix>.auth.<region>.amazoncognito.com \
  AWS_PROFILE=<profile> ./e2e/saml_bridge.sh
```

5 腿全绿:AS 发起 SP-init → Cognito 生成 SAMLRequest → 自控 IdP 签 SAMLResponse → **Cognito 验 XML-dsig** → 302 AS callback → AS 建会话。脚本自建/清理(每跑唯一 IdP/RP/secret/upstream + trap 全清 + venv 自装 signxml),env 驱动、零凭证硬编码。

---

## 安全注意

- **client secret** 只走 Secrets Manager(`agent-auth/federation/*`),`PUT /admin/federation` 只收**引用名**,`GET` 不回显 secret。
- **逐租户隔离**(SaaS,C10.19):联邦 config 按 `(tenant_id, upstream_idp_id)` 复合键;不同租户不共享上游信任。broker 池 / SAML IdP 逐租户登记。
- **信任锚**:本 AS 验 broker 签的 id_token 用 broker 的 `jwks_uri`(登记 config 里,非 token header 的 jku/x5u);Cognito 验企业 IdP 的 SAML 用登记的 IdP metadata 证书(非 SAMLResponse 内嵌 KeyInfo)。两层信任锚都取自登记配置。
- **cert 轮换**:企业 IdP 换签名证书时,更新 Cognito IdP 的 metadata(`update-identity-provider`);broker 换 OIDC key 由 Cognito JWKS 轮换自动透传(本 AS JwksFetcher force-refresh)。
- **acr/amr assurance 映射**:上游 SAML 的 `AuthnContextClassRef` 经 Cognito → OIDC id_token 后，
  只有逐 tenant/IdP `strong_acr_values` 中精确 allowlisted 的 `acr` 才映射为 Agent Auth
  canonical strong；未知 `acr` 和 `amr` 只作观测证据，不提级(C9.5b/C12.4)。

---

## 与"AS 内建 SAML SP"的关系

`UpstreamProtocol::Saml` enum 在代码里保留占位,**但经 bridge 实现,非 AS 内 SAML SP**。若未来确有"AS 直接作 SAML SP"需求,必须先完整解决 XSW 位置与基数、transform pinning、C14N golden vectors、算法约束、XXE/DTD 硬化、WebSSO bearer 断言校验、证书约束和重放防护；默认不做。

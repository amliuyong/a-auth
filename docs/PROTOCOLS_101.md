# Agent Auth — 协议 101(Protocols Primer)

> 一份**概念科普**:Agent Auth 支持的每个协议/RFC 各解决什么问题、怎么工作、在本系统里落在哪。
> 面向"知道要接 OAuth,但对 PKCE / PAR / DPoP / CIBA / token-exchange 概念不清"的读者。
> 规范细节以 [`DESIGN.md`](./DESIGN.md) + [`CONFORMANCE.md`](./CONFORMANCE.md) 为准;接入示例见 [`USER_GUIDE.md`](./USER_GUIDE.md)。

标注约定:**✅ 已实现** · **◑ 部分/可选** · **P3** 硬化阶段(已实现的会注明)。

---

## 0 · 全景:一张表看懂

| 协议 / RFC | 解决什么 | 本系统 |
|---|---|---|
| **OAuth 2.1** | 授权框架:第三方拿受限 token 代表用户访问资源,不碰用户密码 | ✅ 核心;只留 Authorization Code |
| **OIDC**(OpenID Connect) | 在 OAuth 上加"**认证**":颁发 id_token 证明用户身份 | ✅ id_token + `/userinfo` + discovery |
| **PKCE**(RFC 7636) | 防授权码被截获重放(尤其 public client) | ✅ public 强制；confidential 推荐并可受控省略 |
| **RFC 9068** | Access token 用 JWT 的标准 profile(`typ=at+jwt`) | ✅ 签发口径 |
| **RFC 7591 / 7592** | 动态客户端注册(DCR)+ 管理端点 | ✅ 三档准入 + RFC 7592 |
| **RFC 8414 / OIDC Discovery** | 服务器自描述:端点/能力在 well-known 如实宣告 | ✅ 双份 metadata |
| **RFC 7517 / JWKS** | 公钥集,客户端/RS 据此验签 token | ✅ `/jwks.json`(EC+RSA 双活) |
| **RFC 8707** | `resource` 参数:token 绑定到具体受众(audience) | ✅ 一 token 一 aud |
| **RFC 9207** | 授权响应回带 `iss`,防 mix-up 攻击 | ✅ |
| **RFC 9728**(PRM) | 受保护资源元数据:RS 告诉客户端"我信哪个 AS" | ✅ 生成 + BYOD 托管 |
| **RFC 7662** | Token introspection:RS 反查 token 是否有效 | ✅ `/introspect`(aud 隔离) |
| **RFC 7009** | Token revocation:主动吊销 | ✅ `/revoke`(family 级) |
| **RFC 8628** | Device Authorization Grant(无浏览器设备) | ✅ device flow |
| **CIBA**(OIDC) | 带外授权:在另一台设备批准 | ✅ poll;◑ ping/push(P3) |
| **RFC 8693** | Token Exchange:委托换发(agent 代表用户) | ✅ 委托链 |
| **RFC 9396**(RAR) | 细粒度授权请求(比 scope 精细) | ✅ 内建词汇表;◑ 复杂策略(P3) |
| **RFC 9449**(DPoP) | Sender-constrained token(绑定持有者密钥) | ✅ P3(AS 签 + RS SDK 校) |
| **RFC 9126**(PAR) | 推送授权请求(参数先 POST,防篡改/泄露) | ✅ P3 |
| **SPIFFE / SVID** | workload 身份(JWT-SVID / X.509-SVID) | ✅ JWT via assertion;✅ X.509 via mTLS(P3,自部署) |
| **AWS SigV4 / STS** | 用 IAM 角色证明 workload 身份 | ✅ 兜底路径 |
| **mTLS**(RFC 8705 邻域) | 连接层双向 TLS,证书即身份 | ✅ workload X.509-SVID(独立域名) |
| **SAML 2.0** | 企业 IdP 联邦(上游登录) | ◑ 经 SAML→OIDC bridge(见 [`SAML-BRIDGE.md`](./SAML-BRIDGE.md)) |

**永久不支持**(OAuth 2.1 已弃 / 本系统非目标):implicit、hybrid、ROPC(password grant)。原因见下 §1。

---

## 1 · 地基:OAuth 2.1 + OIDC

### OAuth 2.1 —— "授权",不是"登录"

OAuth 解决:**让第三方应用代表你访问某个资源,而不把你的密码给它**。你在授权服务器(AS)登录 + 同意,AS 发一枚**受限 token** 给应用,应用拿 token 去资源服务器(RS)。

OAuth 2.1 是 2.0 的"安全收敛版":**只保留 Authorization Code 流**,砍掉历史上出过安全事故的:

- **implicit**(token 直接从浏览器地址栏回传)—— 易泄露,弃。
- **hybrid** —— 复杂、混合上述风险,弃。
- **ROPC / password grant**(应用直接收用户密码)—— 违背 OAuth 初衷,弃。

> Agent Auth 把这三个**永久排除**,且 discovery 里 `grant_types_supported` 明确不含它们。

### 授权码流(Authorization Code)四步

```text
1. 应用把用户重定向到 AS/authorize        (说明:我是谁、要访问哪个 RS、要什么权限)
2. 用户在 AS 登录 + 同意                    (密码只给 AS,应用看不到)
3. AS 重定向回应用,带一个一次性 code
4. 应用用 code 到 AS/token 换 access token  (后端到后端,code 一次性)
```

为什么要"先给 code 再换 token"而不直接给 token?—— code 短命一次性、只在受控回跳里出现;真正的 token 在后端通道换取,不经浏览器地址栏。

### OIDC —— 在 OAuth 上加"认证"

OAuth 只说"授权",不保证"用户是谁"。**OIDC** 在其上加一个 **id_token**(签名 JWT,含 `sub`/`iss`/`aud`/`auth_time` 等),让应用能**认证**用户身份;外加 `/userinfo` 端点和标准化的 **discovery**。

> 本系统:id_token 默认 RS256(per-client 可选 ES256),`/userinfo` 有独立 audience 隔离(拿 `/userinfo` token 才能调,防越界读)。

---

## 2 · 让授权码流变安全的几个补丁

### PKCE(RFC 7636)—— 防授权码被劫持

public client(如 SPA、CLI、移动端)没有可保密的密钥,授权码若被中间人截获就能换 token。PKCE 让应用:

- authorize 前生成随机 `code_verifier`,发它的哈希 `code_challenge`;
- 换 token 时出示原始 `verifier`,AS 校验哈希匹配。
截获 code 的人没有 `verifier`,换不了 token。

> 本系统对 public 与 CIMD 客户端强制 PKCE S256。Confidential 客户端仍应发送 PKCE；只有 ClientStore 中预注册/DCR client 的认证方法当前可执行且非 `none`，并在 token 端成功认证时，才可把 challenge 与 method 一起省略。空/单边 tuple 会被拒绝；任何已发送 challenge 都必须在 token 端校验 verifier，无 challenge 却提交 verifier 也会被拒绝。这个 OIDF Basic 兼容 profile 不把无 PKCE/无 nonce 的 confidential 场景宣称为完整 OAuth 2.1 draft-15 conformance。

### `resource` + audience 绑定(RFC 8707)—— token 不是万能钥匙

一枚 token 若能访问任意 RS,一处泄露就全线沦陷。RFC 8707 让请求方声明 `resource=<某个 RS>`,AS 签出的 token `aud` 就锁定那个 RS。

> 本系统**铁律:一个 access token 只对一个 RS(`aud` 单元素)**。要访问另一个 RS,得另换一枚。authorize 阶段声明的 resource 集合与授权流绑定,token 阶段只能从中选(不能中途改要别的 RS)。

### `iss` 回带(RFC 9207)—— 防 mix-up

同时接多个 AS 的客户端,可能被诱导把 A 的 code 送到 B。授权响应回带 `iss=<签发它的 AS>`,客户端核对来源。✅ 本系统 discovery 宣告 `authorization_response_iss_parameter_supported`。

### redirect_uri 精确匹配 —— 防开放重定向

code 只回跳到**注册时登记的精确 URI**(P0 支持 exact + loopback,无通配)。防攻击者把 code 导到自己的地址。

---

## 3 · 动态与自描述

### DCR(RFC 7591 / 7592)—— 客户端自助注册

传统 IdP 要人工预注册应用。agent 场景客户端来去频繁,需要**动态注册**:`POST /register` 拿 `client_id`。本系统三档准入:

- **open**(开发/内网)、**initial_access_token**(凭票据,收紧)、**software_statement**(签名声明,P0 未实现档拒)。
- RFC 7592 管理端点(`/register/{id}`)可改/删自己,含**降级确认**(改弱认证方式要显式确认)。

> workload 客户端的信任绑定**不走 DCR**(走管理面登记)——那三档面向 public/confidential。

### Discovery(RFC 8414 + OIDC Discovery)—— 服务器自描述

`/.well-known/openid-configuration`(OIDC)和 `/.well-known/oauth-authorization-server`(OAuth)列出所有端点、支持的 grant/scope/签名算法。
> **本系统公理**:未实现的能力**绝不**出现在 discovery(阶段门控 + feature 门控)。所以"先读 discovery"永远能拿到真实能力集。

### JWKS(RFC 7517)—— 怎么验 token 签名

AS 在 `/jwks.json` 公布公钥;token header 的 `kid` 指向用哪把。客户端/RS 据此离线验签,无需每次问 AS。
> 本系统 EC(ES256,access token)+ RSA(RS256,id_token)双活;支持[两相密钥轮换 + 紧急吊销](#9--密钥与-jwks-轮换rfc-7638-指纹p3)。

---

## 4 · token 是什么样(RFC 9068 + 委托)

### access token = RFC 9068 JWT

本系统 access token 是签名 JWT(`typ=at+jwt`,ES256),典型 claims:

```jsonc
{
  "iss": "https://auth.example.com",   // 谁签的
  "aud": ["https://mcp.rs.example"],   // 只给这一个 RS(单元素)
  "sub": "…",                          // 主体(可能 pairwise,RS 别反解)
  "client_id": "c_xxx",                // 强制带
  "scope": "kb:read",
  "https://…/c": { "sub_type": "user", "auth_grant": "…" },  // 命名空间:主体类型/授权引用
  "act": { "sub": "agt_…" },           // 委托链(agent 代表谁),见下
  "cnf": { "jkt": "…" }                // DPoP sender-constraint(见 §6)
}
```

- **`sub_type`**:`user`(真人)/ `agent`(机器)—— RS 可据此做策略(如"某路由拒机器")。
- **`aud` 单元素** + **短 TTL** 是 token 泄露的主要缓解。

### Token Exchange(RFC 8693)—— agent 代表用户

agent 已认证自己的 workload 身份,用户此前已授权(有个 Grant)。agent 拿"用户的 token + 自己的身份"到 `/token` 换一枚**代表用户、面向下游 RS** 的新 token:

- 新 token 带 **`act`**(actor,记录"是谁在代表")形成**委托链**,可观测;
- **权限恒 ⊆ 原 Grant**(换发的 resource/scope 必须在原授权内,不能扩权);
- pairwise 下用 `jti→{user_id}` 映射反查主体(**绝不试图解 `sub`**)。

> 这是 Agent Auth 的差异化核心:委托是一等公民、有边界、可观测。详见 [`DESIGN.md`](./DESIGN.md) §5。

### RAR(RFC 9396)—— 比 scope 更细的授权

scope 是粗粒度字符串(`kb:read`)。RAR 用结构化 `authorization_details` 表达"**可访问哪些具体资源、什么时间范围、最多多少条**":

```jsonc
"authorization_details": [{
  "type": "agent_auth_rar_v1",
  "resource_subset": ["doc:123","doc:456"],
  "valid_from": "…", "valid_to": "…", "max_records": 100
}]
```

- ✅ **内建词汇表**(上述标准字段):AS 签发时校准入、RS SDK 执行越界拒。
- ◑ **复杂/策略型 RAR**(P3):RS SDK 可插可插拔策略引擎(如 Cedar);SDK core 零引擎依赖,deny-only。

---

## 5 · 用户不在浏览器前:device flow / CIBA

### Device Authorization Grant(RFC 8628)—— 输入受限设备

智能电视、CLI、IoT 没有好用的浏览器。设备流:

```text
设备拿 user_code("WDJB-MJHT")+ verification_uri → 提示用户"在手机打开该网址输入码"
设备按 interval 轮询 /token → 用户批准后拿到 token(轮太快会被 slow_down)
```

✅ 本系统实现(`/device_authorization` + 轮询 + `/approve` 批准页)。

### CIBA(Client-Initiated Backchannel Authentication)—— 带外批准

客户端发起,用户在**另一设备**(如手机 App)收到并批准,客户端后台等结果。典型:呼叫中心坐席替你操作、你手机确认。

- ✅ **poll 模式**:客户端凭 `auth_req_id` 轮询 `/token`(标准错误码 `authorization_pending`/`slow_down`/`expired_token`)。
- ◑ **ping/push 投递**(AS 回调通知客户端,P3):含 SSRF 防护 + confidential 强制 + 通知令牌信封加密。

---

## 6 · sender-constrained token:DPoP(RFC 9449,P3)

普通 bearer token"谁拿到谁能用"——泄露即被冒用。**DPoP** 把 token 绑定到客户端持有的一把密钥:

- 客户端每次请求附一个 **DPoP proof**(用自己私钥签的短 JWT,含 `htu`/`htm`/`iat`);
- token 里带 `cnf.jkt`(那把公钥的指纹);
- RS 校验 proof 的公钥指纹 == token 的 `cnf.jkt` + proof 覆盖本次请求 —— 光偷到 token 没有私钥用不了。

> ✅ 本系统 P3:AS 侧签 `cnf.jkt`-bound token(接 5 条 grant 路径,refresh 延续绑定,jti 防重放)+ RS SDK 双语言校验器 + 委托 token cnf 继承(重绑到发起 actor 自己的 proof key)。

---

## 7 · MCP 资源服务器接入(PRM / introspection)

MCP RS 要做两件事:**让客户端发现它信哪个 AS**,和**校验收到的 token**。

### PRM(RFC 9728)—— 受保护资源元数据

RS 在自己的 `/.well-known/oauth-protected-resource` 公布 `{resource, authorization_servers}`,客户端据此知道"访问这个 RS 该找哪个 AS 要 token"。

- ✅ **投放方式 a**:AS 生成 PRM JSON,RS 自挂在自己 origin。
- ✅ **投放方式 b(BYOD,P3)**:RS 把自带域名 CNAME 到本系统,AS 按入站 Host 数据面托管 PRM(issuer 从登记绑定重建,防跨租户误导)。

### Introspection(RFC 7662)vs 本地验签

RS 校验 token 两条路:

- **本地验签(推荐)**:用 JWKS 公钥离线验(RFC 9068 基线 + aud/sub_type/RAR 检查)。零往返。
- **`/introspect`(RFC 7662)**:反查 AS 拿 token 状态 —— 能反映**吊销**(本地验签看不到吊销)。本系统 introspect 有 **aud 隔离**(RS-A 凭证查 aud=RS-B 的 token 返 inactive,防跨 RS 枚举)。

> RS SDK(`sdk/python`、`sdk/ts`)封装了基线校验 + RAR 执行 + DPoP 校验,直接用。

### Revocation(RFC 7009)

`/revoke` 主动吊销 refresh —— 本系统按 **refresh family** 级联失效(整条 rotation 链 + 关联 Grant),不只是单枚。

---

## 8 · workload / 机器身份(无用户、无长期密钥)

CI、Lambda、K8s pod、agent runtime 没有真人、也不该塞长期 client secret。它们用**运行时平台已经签发的身份**证明自己,类似 GitHub Actions OIDC 联邦到云厂商:

| 机制 | 怎么证明 | 状态 |
|---|---|---|
| **workload OIDC-JWT** | 平台签的 OIDC token 作 `client_assertion`,AS 本地验签(`aud` 必须定向本 AS) | ✅ |
| **SPIFFE JWT-SVID** | trust domain 签的 JWT-SVID 作 `client_assertion`;信任锚=从 SVID `sub` 解出的 trust domain(不用 `iss`) | ✅ |
| **SPIFFE X.509-SVID / mTLS** | X.509 证书作 **mTLS 客户端证书**(连接层,不降级成 assertion——裸证书无持有证明);走独立 mTLS 域名 | ✅ P3,仅自部署 |
| **AWS SigV4 / STS** | 预签名 `sts:GetCallerIdentity`,AS 转发 STS 拿到 caller ARN | ✅ 兜底 |

- **优先自校验路径**(OIDC/SVID:本地验签、无外呼);SigV4/STS 是"只有 IAM 角色、无 workload OIDC token"时的兜底，因为它给签发热路径引入同步外呼和额外的延迟/可用性依赖。
- 换出的是 **2LO token**：平台身份认证的 workload 为 `sub_type=agent`；通过标准
  client auth 且显式配置 2LO resource policy 的预注册 confidential service 为
  `sub_type=service`。两者都无 refresh；要代表用户须走 token-exchange(§4)。
- **信任绑定走管理面登记**(平台 issuer/trust domain + subject 模式 → 映射 client_id),**不走 DCR**。

---

## 9 · 密钥与 JWKS 轮换(RFC 7638 指纹,P3)

签名密钥要能换(定期轮换 / 泄露时紧急吊销)而**不中断验签**:

- **两相优雅轮换**:新 key 先进 JWKS(publish-ahead ≥ JWKS 缓存 max-age)→ 切用新 key 签 → 旧 key 留够 token TTL 后再移除。全程新旧 token 都能验、无停机；自动化与部署演练脚本覆盖该过程。
- **紧急吊销**:立即从 JWKS 移除泄露 key + CloudFront invalidate;诚实限界=离线缓存 JWKS 的 RS 上界 = JWKS max-age(非 token 剩余 TTL)。✅
- `kid` = 公钥 RFC 7638 指纹(thumbprint),`kid`↔`alg` 强绑定防算法混淆。

---

## 10 · 企业联邦(上游 IdP 登录)

用户不在本系统直接登录,而是用公司的 IdP(Okta/Entra/Cognito…):

- **OIDC 上游**:✅ 标准 OIDC 联邦(state/nonce/PKCE 一次性 + 上游 JWKS 验签 + canonical `acr` 映射 / `amr` 观测)。
- **SAML 上游**:◑ 经 **SAML→OIDC bridge**——AS 不自实现 XML-dsig,委托 broker(如 Cognito SAML SP)验 XML,AS 复用 OIDC RP 路径。见 [`SAML-BRIDGE.md`](./SAML-BRIDGE.md)。

---

## 延伸阅读

- 想动手 → [`GETTING_STARTED.md`](./GETTING_STARTED.md)(本地 5 分钟跑通)
- 接入示例 → [`USER_GUIDE.md`](./USER_GUIDE.md)
- 规范全文 + 为什么这么设计 → [`DESIGN.md`](./DESIGN.md)
- 每条 MUST/SHOULD + 验收点 → [`CONFORMANCE.md`](./CONFORMANCE.md)
- 落地进度(哪些已实现 / 在建)→ [`../specs/index.md`](../specs/index.md)

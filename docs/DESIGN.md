# Agent Auth — 面向 Agent 时代的 OAuth 2.1 / OIDC 授权系统设计

> 状态：**pre-1.0 活跃设计**。配套文档:[`CHANGELOG.md`](./CHANGELOG.md)(公开版本变更)、[`DEPLOYMENT.md`](./DEPLOYMENT.md)(多租户/密钥迁移等实现细节)、[`CONFORMANCE.md`](./CONFORMANCE.md)(MUST/SHOULD 清单 + 测试项)。本文只保留协议内核。
> 动机：让"agent 代表用户经 OAuth 连第三方 MCP RS"这条主流 connector 场景零配置可用。现成 IdP 的 DCR、PKCE、public-client provider、callback 匹配和资源绑定能力并不总能覆盖 agent 工作流，本设计把这些边界在 AS 层显式化。
> 一句话定位：**一个把 "agent 代表用户连资源" 当作头号场景的授权服务器（AS）**，
> 原生兼容 OAuth 2.1、OIDC Core 与 MCP Authorization 规范，AWS serverless 原生部署。
> 两种交付形态：**① 企业自部署**（部署进客户自己 AWS 账号，类 Keycloak）与 **② Agent OAuth SaaS**（我们运营的多租户平台，类 Auth0），共享同一协议内核（详见 §0.5）。

---

## 0 · 设计哲学：把踩过的每个坑变成一条设计公理

Cognito 的问题不是"功能少"，而是它诞生于 **人类用户 × 预注册 Web 应用** 的时代。
Agent 时代的客户端画像完全变了：

| 维度 | 传统 Web 时代（Cognito 的假设） | Agent 时代（本系统的假设) |
|---|---|---|
| 客户端注册 | 管理员在控制台手动预注册 | **客户端动态出现**（mcp-remote、Claude Code、AgentCore provider），必须 DCR 零配置 |
| 客户端类型 | confidential 为主 | **public + PKCE 为主**，confidential 是特例 |
| callback URL | 固定的几个 URL | **每次都变**（AgentCore UUID callback、loopback 随机端口） |
| 谁在行动 | 用户本人操作浏览器 | **agent 代表用户**行动，且可能多级委托（agent → sub-agent） |
| token 消费方 | 自家后端 | **第三方 MCP 资源服务器**，必须能独立、无歧义地校验 token |
| 授权时机 | 用户在场、同步 | **用户常常不在场**——异步 consent、device flow、CIBA |
| 失败排查 | 自家全栈可见 | **跨三方黑盒**，状态机必须自解释 |

由此得出八条公理（每条都锚定原文档的一个坑）：

1. **Discovery 元数据永远如实**（坑 2.2/2.5）——宣告的就是实现的，实现的就宣告；
   **且分阶段如实**：每个发布版本只宣告当前真正落地的 grant/端点，路线图未到的能力绝不提前出现在 metadata 里（否则客户端会试图走一个不存在的流程）。
2. **public/PKCE 客户端是默认形态**（坑 1.7/2.5）——confidential 是可选升级，不是准入门槛。
3. **DCR 是内置能力不是外挂 facade**（坑 2.1）——`POST /register` 开箱即用，策略可收紧。
4. **委托关系写进 token，不靠启发式**（坑 1.6）——`sub_type` + `act` 声明，杜绝 `sub==client_id` 巫术。
5. **一切异步状态可观测**（坑 1.1/1.2/1.3）——授权会话是显式状态机，下游错误透传。
6. **redirect URI 支持受控前缀匹配**（坑 2.4）——host 精确 + path 前缀 + 单层通配。
7. **提供 PATCH 部分更新语义，安全降级必须显式确认**（坑 2.6）——标准 `PUT` 全量替换保留,`PATCH` 作为扩展补上"只改传入字段",避免全量替换静默复位。
8. **同源**（坑 2.3）：`issuer` 与**所有 AS 自身端点**（discovery/authorize/token/jwks/…）**同一 origin**，一个 CloudFront 域名收拢。（注：RS 的 PRM 属 RS 自己的 origin，不在此列——见 §6/§8。）

### 0.1 · 显式非目标 + 威胁模型摘要

**明确不做(Non-Goals,防止把"缺席"误判为遗漏)**:

- **不支持 implicit / hybrid response types**(`token`/`id_token`/`token id_token`)——遵 **OAuth 2.1 BCP**(注:2.1 仍是 IETF draft,业界已普遍当事实权威 BCP;本文按其规约走),只做 authorization code + PKCE。故只跑 **OIDC Basic OP profile**(§10)。
- **不支持 ROPC**(resource owner password credentials,2.1 已弃)。
- **P0 不做**:token vault(存下游第三方 token,§11 #1 评估)、logout/会话终止(§7,P1 联邦后补)、DPoP(P3)、PAR(P3)、多 resource 下采样(P1)。
- **不自造授权**:token-exchange 只认已有 Grant,超白名单直接拒、不内联补授权(§5.2)。

**威胁模型摘要(细节散见各节,此处集中锚定)**:

| 威胁 | 防线(节) |
|---|---|
| 授权码注入/劫持 | public 强制 PKCE、registered confidential 推荐 PKCE且受控省略时强制 token 端客户端认证(§3)、redirect canonicalize 精确匹配(§3.3)、code 一次性 + 两阶段 lease(§8) |
| 跨租户伪造 token | 逐租户 CMK 密码学隔离(DEPLOYMENT §1/§8) |
| 跨租户越界读/会话越界 | PRM Host 绑定(§6)、cookie `__Host-`(§8)、WebAuthn `rp_id` 逐租户(§7)、introspect 按 aud 隔离(§6) |
| 委托链滥用(任意 workload 插入) | 每跳准入闸:发起 actor ∈ Grant `actor_allowlist`(签发前校验)+ 深度限;`may_act` 按 RFC 8693 单对象叠加(§5.2) |
| token 转用/confused-deputy | audience 恒受限单值(§1/§2)、workload OIDC-aud 前提 + STS 头签名内(§3.1) |
| 静默扩权 | resource↔code 绑定(§1)、Grant 白名单(§5.2)、降级需确认(§3.2) |
| token 重放/泄露 | refresh rotation + 复用检测、DPoP 可选(§2)、宽限窗收紧绑定(§2) |
| 密钥泄露 | 紧急吊销(重叠期=0,§8) |
| 注册/发信滥用 | DCR 配额 + 未验证标识(§3.2)、magic-link 冷却(§7) |

---

## 0.5 · 两种交付形态（贯穿全文的部署维度）

本系统面向**两类用户**，是一份贯穿全文的架构维度——同一份协议内核、两种打包与信任模型。**协议面（§1/§2）、客户端模型（§3）、委托模型（§5）、MCP 集成（§6）的语义两形态一致**；分叉在**租户模型、issuer 形态、信任边界、数据驻留、部署打包、控制面**。⚠️ **两处是"形态敏感的线协议/token 配置"(不只是部署拓扑)**:**`subject_types`/`sub` 隐私 profile**(SaaS pairwise / 自部署 public,§11 #12)与 **issuer 域名**(§1)——它们进 discovery、进 token,实现/conformance 须按各自形态口径读,不能当"两形态完全一致"。

| 维度 | **① 企业自部署（Self-Hosted，类 Keycloak）** | **② Agent OAuth SaaS（类 Auth0）** |
|---|---|---|
| 部署位置 | 客户**自己的 AWS 账号**里，客户自运维 | 我们运营的**多租户 fleet** |
| 租户模型 | **单组织**（一个部署 = 一个租户），无需租户隔离 | **多租户强隔离**（数据/密钥/策略/配额逐租户）——隔离**能力从 P0 就按"可关闭一等能力"内建**，SaaS 多租户**上线在 P2/P3**（见 DEPLOYMENT §1、§10） |
| issuer | **单一 issuer**（一个部署一个域名） | **每租户独立 issuer**（子域，`t1.saas.example.com`；已定，见 §11 #3） |
| 信任边界 | 边界=企业自身；RS/agent 多为**自家**资产 | 边界**跨租户/跨账号**；PRM CNAME、Cedar 策略、DCR 都是**真实攻击面** |
| 用户认证 | 常**联邦到企业 IdP**（Entra/Okta/现有 Cognito，§7） | 每租户自配 IdP + 平台托管的无密码登录 |
| DCR 策略默认 | 可较宽松（内网、可信）（§3.2） | **默认收紧**（每租户配额、abuse 防护、未验证客户端标识必显） |
| 数据驻留/合规 | 客户在**自己账号/region** 内自负（天然满足驻留） | **平台须提供** region pinning、逐租户数据隔离、GDPR 删除（§11） |
| KMS 签名密钥 | 客户账号内自有 key set | **每租户独立 key set 为第一天基线**(EC+RSA 两把 signing CMK,轮换期 ≤4;密码学隔离,`CreateKey` 同步返回；非"派生子密钥"——KMS 不支持);规模/成本按 key set 口径算(DEPLOYMENT §1);claims 级共享 key 仅低保障可选（见 DEPLOYMENT §1/§8） |
| 控制面 | 轻量 admin（单组织配置） | 完整租户管理 + 计费 + 限流分级 + onboarding |
| 交付物 | **可分发的 CDK app**（版本化、含升级/迁移脚本、cdk-nag 合规基线） | 我们持续运营的服务，客户只碰控制台/API |

**设计取舍原则**:

- **协议内核单一实现,两形态共享**——避免分叉出两套代码;形态差异收敛到**配置 + 部署拓扑 + 控制面**,而非协议逻辑。
- **多租户隔离做成"可关闭的一等能力"**:SaaS 打开(按租户分区 DynamoDB、逐租户 KMS key、按 Host 路由 issuer);自部署退化为"单租户"这一特例(同一套隔离代码,租户数=1),**不为自部署单独写非隔离路径**。⚠️ **承认代价**:单租户自部署客户的 CDK app 会背上它用不到的分区键/Host 路由逻辑(死重、额外审计负担、略增攻击面);判断仍是"不分叉 > 这点死重",但不假装无成本。
- **信任边界更严者为设计基准——但仅限"跨租户/跨账号真实存在攻击面"的机制**:**PRM CNAME 的跨租户 Host 伪造(§6)、redirect prefix 的共享 host 风险(§3.3)** 这类**按 SaaS 更严阈值设计**,自部署继承、不会更差。
  ⚠️ **区分**:另一类是**"形态天然合理有不同默认"**的项(**DCR 开放度 §3.2、Cedar 策略暴露 §11**)——自部署在自己可信内网里默认可较松(`open` DCR、自由写策略),SaaS 默认收紧(票据注册、受限模板)。**这类是默认值本就随形态而变,不属于上一类"继承更严默认"**,两者别混。
- **自部署的额外交付责任**:CDK app 必须是**可分发、可升级**的制品——含 schema 迁移、KMS key 轮换脚本、跨版本兼容策略;这些在纯 SaaS 下由我们内部 CD 消化,自部署则要交到客户手里(见 §8/§10)。

> 下文各节遇到形态敏感处,用 **【自部署】/【SaaS】** 标注差异;未标注处两形态一致。
>
> **实现细节已抽出**:多租户隔离的落地路径(数据/控制两平面、逐租户 CMK 基线、BYOD 置备)、跨形态 migration 与共享 key→CMK 在线迁移,详见 **[`DEPLOYMENT.md`](./DEPLOYMENT.md)**。本文只保留上表的语义/信任模型对照与取舍原则;协议内核各节引用 DEPLOYMENT.md 的地方标 "见 DEPLOYMENT §x"。**冻结要点(供本文其他节引用)**:
>
> - **SaaS 密钥基线 = 第一天逐租户独立 key set**(EC+RSA 两把 signing CMK;密码学隔离;EC+RSA 两次 `CreateKey` 同步返回、非编排;成本/配额按 key set 口径,DEPLOYMENT §1;claims 级共享 key 仅"显式 opt-in + 风险披露"的低保障档);
> - **数据平面永远纯运行时配置**(`tenant_id` 贯穿),自部署 = 租户数为 1 的特例;**唯一异步编排是 BYOD 自带域名**的证书/DNS(评估 CloudFront SaaS Manager);
> - **跨形态升级用 expand-contract + `schema_version`/`min_reader_version` 双标记**(见 DEPLOYMENT §2)。

---

## 1 · 协议面：完整端点清单

域名 `https://<issuer>`（issuer == origin，无跨域）。**issuer 随形态而定**:**【自部署】= 客户自己配置的域名**(如 `https://auth.customer.example`,**不硬编码我们的域名**);**【SaaS】每租户 = `https://t{N}.saas.example.com`** 子域,**`https://c.saas.example.com` 是我们 SaaS 的 control-plane / 文档示例 origin、不是租户 issuer,也不作为 AS 对外签发**(只有控制面 API,不暴露 `/authorize`、`/token`、AS discovery、签名 JWKS——避免第三种未定义的"平台 issuer"形态)(§0.5/§11 #3、DEPLOYMENT §0)。discovery/JWKS/cookie/RFC 9207 `iss` 一律按**请求 Host 对应的 issuer** 口径。详见 DEPLOYMENT §0。

"阶段"列对应 §10 路线图；**metadata 按阶段如实宣告**（公理 1），任一端点/grant 在其所属阶段落地前**都不出现在 discovery 里**（P1/P2/P3 项在到达前对客户端不可见）。

**P0 就带 RFC 9207**（`iss` authorization response parameter）：多租户 SaaS 下每租户独立 issuer 正是 **mix-up 攻击**温床,授权响应回带 `iss` 让客户端确认"这个响应来自我发起请求的那个 AS/租户";实现成本极低,metadata 宣告 `authorization_response_iss_parameter_supported: true`。

| 端点 | 规范 | 阶段 | 说明 |
|---|---|---|---|
| `GET /.well-known/openid-configuration` | OIDC Discovery | P0 | 与 oauth-authorization-server **值一致但非同一份**——OIDC 必填字段齐备,不能塞一份 OAuth 最小 JSON。`subject_types_supported` **按该部署/租户实际选定值宣告**(【SaaS】默认 `["pairwise"]`、企业租户可 opt-in `["public"]`;【自部署】默认 `["public"]`、可选 `["pairwise"]`;§11 #12、DEPLOYMENT §0),其余 `id_token_signing_alg_values_supported`、`response_types_supported` 等照常 |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | P0 | 如实宣告 `code_challenge_methods_supported: ["S256"]` 等**当前阶段真正支持**的能力 |
| `GET /openapi.json` | OpenAPI 3.1 | P0 | 由运行时路由与 schema 生成的完整 API 契约；公开可下载,与仓库 `openapi/openapi.json` 同一真相源 |
| `GET /jwks.json` | RFC 7517 | P0 | 公钥来自 KMS，含轮换重叠期的双活 key |
| `POST /register` · `GET/PUT/PATCH/DELETE /register/{id}` | RFC 7591/7592 + PATCH 扩展 | P0 | DCR 与客户端管理 |
| `GET/POST /authorize` | OAuth 2.1 / RFC 9700 compatibility profile | P0 | query 与 form 两种传输使用同一参数校验；仅 authorization_code；public 强制 PKCE S256，confidential 可按 §3.1 的受控条件省略；隐式 grant 不存在 |
| `POST /token` | OAuth 2.1 | P0 | 见下方 grant 矩阵（各 grant 有自己的阶段） |
| `POST /introspect` | RFC 7662 | P1 | 给不想验 JWT 的 RS 用 |
| `POST /revoke` | RFC 7009 | P1 | |
| `GET/POST /userinfo` | OIDC Core | **P0** | 提到 P0:纯 OIDC 无 resource 时的默认 audience 指向它(§1),不能签出指向不存在端点的 token;POST 同时支持 `Authorization: Bearer` 与 form `access_token` |
| `POST /login/password` · `POST /login/password/change` | 自有登录仪式 | P1 | Admin 预置本地用户的密码登录与首次强制改密(§7/C9.7-C9.10)。它们不是 OAuth ROPC grant,无对应 discovery metadata 字段;`grant_types_supported` 仍永久排除 `password` |
| `GET /sessions?client_id=me`（列表）· `GET /sessions/{session_id}` | 自有扩展 | P1 | **可观测授权会话状态机**；列表端点让 confidential 客户端凭 client 认证发现自己名下会话 id（详见 §4） |
| `GET/DELETE /account/sessions` · `DELETE /account/sessions/{id}` | 自有账户安全扩展 | P1 | 当前用户列出和吊销自己的 browser login session，并可保留当前会话、退出其他会话；仅暴露 tenant-bound opaque 管理 handle 和规范化设备/时间元数据。该资源与面向 OAuth 客户端的 `/sessions` AuthzSession 是不同领域对象(详见 [`LOGIN_SESSION_MANAGEMENT.md`](./LOGIN_SESSION_MANAGEMENT.md)) |
| `GET /account/credentials` · `PATCH/DELETE /account/passkeys/{id}` · `PUT /account/password` | 自有账户安全扩展 | P1 | 当前用户查看脱敏凭据摘要、命名/移除自有 passkey、首次设置或轮换本地密码；写操作要求 300 秒内重新认证，敏感变更推进 login-session generation、吊销 refresh family，并阻止删除最后可用因子。恢复材料轮换继续使用 `POST /recovery/generate` 的 show-once 契约(详见 [`CREDENTIAL_MANAGEMENT.md`](./CREDENTIAL_MANAGEMENT.md)) |
| `GET /end-session` | OIDC RP-Initiated Logout | P1 | **RP-initiated logout / 会话终止**(与上游联邦同期,§7/C9.6):清 AS 会话 cookie、可选联动上游 IdP 登出;支持 `id_token_hint`/`post_logout_redirect_uri`(后者须按注册的 `post_logout_redirect_uris` 精确匹配)。⚠️ **discovery 必须随之宣告 `end_session_endpoint`**(P1 起,与本端点同阶段上架——按公理 1 未落地前不宣告);前/后通道登出留 post-P1 |
| `GET /scim/v2/ServiceProviderConfig` | RFC 7643/7644 | P1 | tenant-scoped SCIM capability 文档;使用与普通 Admin 分离的逐租户 bearer credential |
| `POST/GET /scim/v2/Users` · `GET/PUT/PATCH /scim/v2/Users/{id}` | RFC 7643/7644 Users profile | P1 | 企业目录 provision/mover/deprovision 最小切片;事务性 `externalId`/`userName` alias、exact POST retry、分页与 `eq` filter;`active=false` 复用统一用户 lifecycle 并级联吊销,完整契约见 [`SCIM_USERS.md`](./SCIM_USERS.md) |
| PRM 托管（RS origin 或 RS CNAME vhost 上，**不在 AS origin**） | RFC 9728 | P1 | 替注册的 MCP RS **生成/托管** PRM 文档,PRM 的 URL 与 `resource` 都是**该 RS 的标识**——**AS 的 issuer origin** 上不存在能代表任意 RS 的全局 PRM（详见 §6，故不列为 AS 自身端点） |
| `POST /device_authorization` | RFC 8628 | P2 | 无头 agent / CLI 首次授权 |
| `POST /bc-authorize` | CIBA | P2 | agent 发起、用户异步在别处批准 |
| `GET/DELETE /grants` · `/grants/{grant_id}` | FAPI Grant Management 风格 | P2 | 用户查询/吊销"我授权过哪些 agent" |
| `POST /par` | RFC 9126 | P3 | Pushed Authorization Requests（防参数篡改，agent 平台友好） |
| `GET /rs/attributes` | 自有扩展 | P1 | **RS 命名空间用户属性读取**（aud-self-scoped，§6.1）：用 `aud=<resource>` 的 access token 读该命名空间下自己 `sub` 的属性；**独立于 `/userinfo`（不改 C2.11）** |
| `PUT /admin/users/{id}/attributes?namespace=<uri>` | 自有扩展 | P1 | **管理面写用户属性**（整命名空间全量替换，admin 超级权限，§6.1）；AS 不解释 value 语义 |

**PAR 的定位**：P3 引入后**默认可选、可按客户端策略强制**（confidential/高保障客户端可要求 `require_pushed_authorization_requests=true`）；它同时是 §4 会话在 `GET /authorize` 重定向流之外向 **public 客户端回传 `session_token`** 的最自然载体（PAR 响应体里带回）——confidential 客户端不靠它、用 `GET /sessions?client_id=me`（见 §4）。

### 支持的 grant 矩阵

| grant | 阶段 | 场景 | token 里的身份形态 |
|---|---|---|---|
| `authorization_code` + PKCE | P0 | 3LO：agent/应用代表用户 | `sub`=用户，`client_id`/`azp`=client |
| `refresh_token`（rotation + 复用检测） | P0 | 续期 | 同上 |
| `client_credentials` | P2 | 2LO：agent/服务以机器身份自主行动 | `sub`=workload，workload 客户端 `sub_type="agent"`、纯服务后端 `sub_type="service"` |
| `urn:ietf:params:oauth:grant-type:token-exchange`（RFC 8693） | P2 | **委托核心**：agent 用自己的 workload token + 用户 grant 换取代表用户的下游 token | `sub`=用户，`act.sub`=agent，可多级链 |
| `urn:ietf:params:oauth:grant-type:device_code` | P2 | 无浏览器环境首次授权 | 同 3LO |
| CIBA (`urn:openid:params:grant-type:ciba`) | P2 | agent 发起、用户手机/IM 上异步批准 | 同 3LO |

**面向 MCP RS 的 access token 强制 `resource` 参数**（RFC 8707 Resource Indicators）→ 这些 token 都是 audience 受限的，
这是 MCP Authorization 规范（2025-06 起）的硬要求，也天然防 token 混用。

> **P0/P1 口径(消除阶段分裂)**:**P0 就支持"单 `resource` + 绑定 code/token"并签发 audience-bound token**(这是 MCP 硬要求、不能推迟);P1 补的是 **PRM 托管 + RS 校验 SDK + 多 `resource` 下采样**的完备。即 §10 P1 那行"`resource` 强制"指**完备化**(默认/例外/多值),不是 P0 不做 audience 绑定。**P0 的 mcp-remote 验收**据此:走单 resource 的 audience-bound token,PRM 发现用旧版 fallback(§10)。

但"强制"要留出**默认与例外**，否则会误伤普通 OIDC 客户端：

- **纯 OIDC 场景**（只要 ID token / `GET /userinfo`，不访问任何 MCP RS）**不要求** `resource`——但 code flow 的 token response **仍必须返回 access_token**(+ id_token),不能因无 `resource` 就不发 access token(那会违反 OAuth/OIDC)。此时签发的 access token **`aud` 为绝对 URI 形式的 `/userinfo` 端点**(即 `<issuer>/userinfo`,非路径串——与 RFC 8707/aud 的"绝对 URI"约定一致)。⚠️ **阶段约束**:既然默认 audience 指向 `/userinfo`,则 **`/userinfo` 必须与它同阶段可用**——见 §10,`/userinfo` 从 P1 提到 **P0**(否则 P0 会签出指向不存在端点的 token);或 P0 暂不提供纯 OIDC 无 resource 路径(discovery 不暴露 `/userinfo`、要求 P0 客户端必带 resource)。**取前者:`/userinfo` 进 P0**。
  ⚠️ **`/userinfo` 访问与带 resource 的 token 互斥,如何兼得**:一旦 token `aud`=某 MCP RS,它就调不动 `/userinfo`(会被 `/userinfo` 的 aud 校验拒)。**同时要 userinfo + 访问 MCP RS 的客户端**:把 **`/userinfo` 当成一个 resource**,用 refresh 下采样(§1)另换一个 `aud=/userinfo` 的 token。实践中多数 agent 用 ID token 里的身份、不碰 `/userinfo`,影响小;但规则写死:userinfo 访问权是一个独立 audience,不搭其他 RS token 的便车。**完整的 audience 优先级 + sub sector 规则收拢在 §2.8。**
- **refresh 续期**默认沿用原 token 的 audience，无需重复携带 `resource`;但**授权记录绑定的是 `/authorize` 声明的整个 `resource` 集合**(非单个 audience),续期时可**在该集合内下采样**到任一 RS——这正是"一次多 resource 授权后拿到第二个 RS token"的路径(见下条)。⚠️ **该"授权记录"的载体随阶段而变**:**P0/P1 = refresh-token family 记录**(Grant 前身),**P2 起 = Grant 对象**(§5.1 过渡期说明)。
- **单一默认 RS**：客户端注册时可声明 `default_resource`，省略 `resource` 时按默认值绑定（RFC 8707 未定义"default resource"语义、也未禁止 AS 自定省略时的默认行为——`default_resource` 是**本系统的设计选择**,非规范条款）。⚠️ **优先级(与上面"纯 OIDC 无 resource→`aud=/userinfo`"的交界)**:省略 `resource` 时 **`default_resource` 优先于 `/userinfo` 回落**——注册了 `default_resource` 的客户端若只想查 `/userinfo`,必须**显式带 `resource=<issuer>/userinfo`**。完整顺序写死在 **§2.8**。
- **多 `resource` 值的行为(明确决策)**:RFC 8707 允许 authorize 请求带多个 `resource`、token 请求收窄到一个。本系统采**"一个 access token 只绑一个 audience"**——签发的 `aud` 数组恒为单元素(数组只为格式统一/未来兼容,不表示多 audience 万能 token)。
  - **单一 resource 时 token 端点可继承**:authorize 请求只带一个 `resource` 时,`/token` **不必重复携带**,直接继承(常见客户端不会重复带);
  - **多 resource 时必须在 `/token` 选一个**:首次 `/token`(用 code)兑换出**第一个 RS** 的 access token + 一个 refresh token;
  - **访问其余 RS 靠 refresh 下采样**(闭合路径,否则 code 一次性消费后就拿不到第二个):refresh token 绑定的是 `/authorize` 的**整个 resource 集合**,后续用 refresh + `resource=第二个 RS` 换该 RS 的 token,无需重走浏览器。**这就是为什么 refresh/Grant 必须绑集合而非单 audience**(见上条)。
    ⚠️ **rotation 保集合不保单值(易踩)**:每次轮换产生的新 refresh token **必须继续绑定整个 resource 集合**,不能收窄成"本次下采样用的那个 resource"——否则第一次为 RS1 refresh 后就再也拿不到 RS2 的 token。
  - (**P0 拒绝多 resource**:一个请求带多个 `resource` 直接拒,每 RS 单独授权——见 §10、C2.5a P0 MUST;多 resource 下采样属 P1+。此处口径与 C2.5a 一致,非"可选"。)
- **`resource` 与授权码绑定(闭合"审批的是什么、拿到的是什么")**:`/authorize` 阶段声明的 `resource` 集合(单个或多个)**与该次授权流绑定、写入 §4 会话记录**;`/token` 换发时选定的 `resource` **必须 ∈ 该集合**,超出即拒。这与 §5.2"委托 token 权限恒 ⊆ 原 Grant"、PKCE `code_verifier`↔`code_challenge`、redirect_uri 精确匹配是**同一类绑定**——consent 页据 `resource` 显示"授权访问哪个 RS",换发时不得改口要另一个 RS,否则"用户同意的 audience"与"token 实际 audience"脱钩,正是本设计反复堵的静默扩权。
- 采用**按 RS 策略**而非全局硬门槛：默认要求、RS 可放宽——避免与"零配置"承诺冲突（见 §6）。
- **`scope` 是否必填**:纯 OIDC 至少要 `openid`;面向 MCP RS 的请求 `resource` 必填但 `scope` **可为空**(表示"该 RS 的默认/最小权限",由 RS 策略定)——空 `scope` 不等于拒绝,签发的 token `scope` 取**授权记录**里该 resource 的授权 scopes 与请求的交集(§6)。⚠️ 该"授权记录":**P0/P1 = refresh-family 记录**、**P2 起 = Grant `per_resource[].scopes`**(§5.1)。

---

## 2 · Token 设计：让资源服务器一眼看清"谁、代表谁、以什么身份"

Access token 采用 RFC 9068 JWT profile（`typ: at+jwt`），核心创新是**显式身份三元组**：

> **私有 claim 命名(线协议契约,已定死)**:本系统自创的 claim 全部收进**单个抗碰撞命名空间对象** `https://a-auth.com/c`(RFC 7519 §4.2 Collision-Resistant Name;命名空间**只出现一次**,不给每个 claim 都付 URI 体积)。其下三个字段:`sub_type`、`auth_grant`、`actor_types`(委托链的"agent_id → 类型"叠加视图,见 `act` 说明)。
>
> - **`act` 保持纯 RFC 8693**(只有 `sub` + 嵌套 `act`),不塞私有字段——标准 delegation-aware RS 照 8693 直接读委托关系;类型信息另放命名空间的 `actor_types`。
> - **为什么用命名空间对象而非裸前缀(如 `aa_`)**:裸前缀是 RFC 7519 §4.3 Private Name、规范明示"会碰撞、慎用";命名空间是 §4.2 抗碰撞正规做法,且"付一次"就不肿。§6 的 RS SDK 把这些 key 封装掉,RS 开发者不手打,URI 长一点无实际成本。
> - **AS 签发、RS SDK、introspection 回带、conformance 断言全部用这套**。下文叙述为简洁写短名(`sub_type` 等),**一律指代 `https://a-auth.com/c` 命名空间下的对应字段**。
>
> ⚠️ **签名算法(access token vs ID token 分开定,别混)**:
>
> - **access token**:**P0–P2 一律 ES256(单一算法)**——不做算法分流,避免多 alg JWKS 的算法混淆面、第三方 RS 间歇拒签、水位路由复杂度;主容量靠**拉长 access_TTL + 跨区/账号分片**(都确定性,§2.1/§8)。**ES256/RS256 双池水位分流降级为 P3 可选优化**(仅当实测容量确需把单区上限抬到两池之和时才启用,届时须配套"PRM 声明 alg 非固定 + 逐 RS 关分流开关",§8/§6)。⚠️ 注意:**这不影响 ID token**——ID token 仍按 per-client `id_token_signed_response_alg` 签(未声明默认 RS256,见下),故 RSA 池 P0 起就因 ID token 而在用,只是 access token P0–P2 不往里分流。
> - **ID token**:**必须按客户端 DCR 注册的 `id_token_signed_response_alg` 签**——**OIDC 动态注册未声明该字段时默认是 `RS256`**。故对没显式声明的 OIDC 客户端**默认签 RS256 ID token**,绝不能因"AS 主算法是 ES256"就给它签 ES256(会破 OIDC 互操作与 conformance)。**算法分流只作用于 access token**,不动 ID token 的 per-client 约定。
> - metadata 如实宣告 `id_token_signing_alg_values_supported` 含 `RS256`(及 ES256)。同一 AS 同时挂 EC(ES256)+ RSA(RS256)KMS key。

```json
{
  "iss": "https://<issuer>",               // 该请求 Host 对应的 issuer(SaaS 租户子域/自部署客户域,§1)
  "sub": "usr_01HXX...",                   // pairwise:随 sector 变(§2 sub 要点)
  "act": { "sub": "agt_01HYY..." },        // 纯 RFC 8693:只有 sub + 嵌套 act
  "client_id": "cli_01HWW...",
  "azp": "cli_01HWW...",
  "aud": ["https://mcp.knowledge.example.com"],
  "scope": "kb:read kb:search",
  "authorization_details": [ {"type":"...", ...RFC 9396 RAR, 如 "只能读 2026 年文档"} ],
  "grant_id": "gnt_01HVV...",             // P2 起才有(Grant 正式化后);P0/P1 的 3LO token 无此字段,见 §2 grant_id 说明
  "cnf": { "jkt": "dpop-key-thumbprint" },
  "auth_time": 1751940000,
  "jti": "...", "iat": ..., "exp": ...,
  "https://a-auth.com/c": {            // 本系统私有 claim,收进单个抗碰撞命名空间
    "sub_type": "user",                    // 主体类型
    "auth_grant": "token_exchange",        // 发行时的 grant type
    "actor_types": { "agt_01HYY...": "agent" }  // 委托链 agent_id→类型 叠加视图(对应 act 链)
  }
}
```

设计要点：

- **`sub` 形态按部署形态定(§11 #12,P0 锁)**:**【SaaS】默认 pairwise**(连第三方 RS、防跨 RS 关联)、**【自部署】默认 public**(首方 RS 需跨 RS 关联)。⚠️ **pairwise 的 sector 键 / `sub` 派生公式 / ID/access/userinfo 的 sub 一致性:全部见 §2.8(唯一权威定义)**,此处不重述。要点仅记两条:①**pairwise 时用户级关联(委托链/introspection/审计)靠内部 `user_id`,不靠 `sub`**;②**同一次 code flow 里 ID token 与 MCP access token 的 `sub` 必然不同**(sector 不同),客户端/RS 不得假设相等。
- **`client_id`（RFC 9068 必填）**：RFC 9068 的 `at+jwt` profile 把 OAuth 客户端标识放在 `client_id`，
  这也是按 9068 实现的第三方 RS 中间件会查的字段——**必须签发**。`azp` 是 OIDC ID token 概念（**RFC 9068 全文未提 `azp`**）,
  仅当确有 OIDC 风格消费方时**并存**保留;**"不能拿 `azp` 顶替 `client_id`"是本系统的工程判断(非规范条文)**——因为按 9068 实现的第三方 RS 只认 `client_id`,顶替会让 §6 "第三方 RS 零配置"落空。
- **`sub_type` ∈ {`user`, `agent`, `service`}（命名空间 `.../c` 下）**：资源服务器的 per-user 通道只需一行判断
  `claims["https://a-auth.com/c"].sub_type == "user"`，彻底取代 `sub == client_id` 启发式（坑 1.6 的正解）。
  取值语义：`user`=真人（3LO）；`agent`=workload 客户端的机器身份（2LO/委托链成员）；
  `service`=非 workload 的纯服务后端（confidential client 走 client_credentials）。
  ⚠️ **未在 IANA 注册**、off-the-shelf 中间件不认识——由 §6 的配套 RS SDK 解释。
- **`act` 委托链（纯 RFC 8693,不含私有字段）**：谁在替谁行动、几级委托，靠标准 `act.sub` + 嵌套 `act` 自描述——**标准 delegation-aware RS 直接读**。
  **嵌套方向**：`act` 是**最近的直接执行者**，其内层 `act` 是"更外围/更早的委托方"，逐层向根委托者展开
  （RFC 8693 的语义，实现时极易搞反——**单测直接断言 RFC 8693 §4.1 的原示例**(外层 `service16`=current actor、内嵌 `service77`=prior actor),别自己编例子）。
  **委托链各跳的类型**放命名空间的 **`actor_types`**(`agent_id → user/agent/service` 映射),**不塞进 `act`**——保持 `act` 纯净。
  MCP 资源服务器可按策略拒绝超过 N 级的委托链（示例只画一级，深链需 grant 的 `max_act_chain` 显式放开，见 §5.1）。
  ⚠️ **与 RFC 8693 §4.1「prior actor 仅信息性、不用于访问控制」的关系(避免 conformance 误判)**:`max_act_chain` 是**基于链长的策略安全阀**,**不基于任何 prior actor 的身份**做授权判定——它数的是嵌套深度、拒的是"链太长",不是"因为链里有某个 prior actor 就授予/拒绝"。§5.1 的 `actor_allowlist` 校验的也只是**当前直接执行者(最外层 act.sub)**是否在准入名单,同样不消费 prior actor 身份。故本系统读嵌套 act **仅用于深度护栏**,与 §4.1「prior actor 不参与访问控制决策」不冲突。
- **`auth_grant` 声明（命名空间 `.../c` 下）**：直接写明发行时的 grant type，2LO/3LO 无需推断。
  （**刻意不叫 `grant`**——避免与 §5 的 Grant 授权记录实体混淆；这是 grant *type* 字符串，不是授权记录。）
- **`grant_id`（P2 起才出现)**：指回用户的授权记录(§5.1 Grant 对象),支持"用户吊销 grant → 关联 token 失效"。⚠️ **P0/P1 的 3LO token 不带 `grant_id`**——Grant 对象是 P2 才正式化(§5.1 过渡期说明),P0/P1 期间吊销以 refresh-family 为单位、身份关联靠内部 `user_id`。
  ⚠️ 语义要如实：对做**离线 JWT 校验**的 RS，吊销**不立即生效**，access token 在其**剩余 TTL(= 该 RS 配置值,默认 ≤15min)**内仍有效；
  只有 refresh token 立即失效、且做 introspection 的 RS 立即感知（见 §5.1）。
- **`aud` 恒为数组、且恒为单元素受限**：面向 MCP RS 的 token 没有"万能 audience"（一个 token 只绑一个 RS，多 RS 靠 refresh 下采样换发，见 §1）。
- **`cnf.jkt`（DPoP，RFC 9449）**：可选 sender-constrained——token 被偷也用不了，
  对"token 存在 agent 平台 vault 里"的场景是重要纵深。
  - **AS 侧签发口径(P3;此前 §5.2:511 只列了'需做什么',此处固化为规范条文)**：`/token` endpoint
    **有 DPoP proof 时**校验并把 `cnf:{jkt}` 写进签发的 access token;**无 proof 时照常发 bearer**
    (**opt-in**,不强制——与 SDK "token 无 cnf.jkt 时跳过"呼应,不破坏 P0–P2 bearer 假设)。
    AS 在 token endpoint 的校验(RFC 9449 §4.3 的 AS 子集,比 RS 少 `ath`——此刻 access token 尚未签发):
    ① DPoP proof JWT header `typ=="dpop+jwt"`、`alg` 非对称且非 `none`、带内嵌 `jwk` 公钥且 **MUST NOT**
    含私钥字段(`d`/`p`/`q`/`dp`/`dq`/`qi`);② `alg` 与 jwk 类型自洽(EC/P-256→ES256)防 alg 混淆;
    ③ 用内嵌 jwk **自验签**(proof 由持私钥者签);④ `htm=="POST"` 且 `htu` 规范化(去 query/fragment)
    **== 本 AS token endpoint URL**(`<issuer>/token`);⑤ `iat` 在 ±时钟偏移窗(§复用 ±30s / DPoP 接受窗
    分钟级,`iat` 过旧/未来拒);⑥ **`jkt = base64url(SHA-256(RFC 7638 canonical(jwk)))`**(EC canonical
    字段序 `{crv,kty,x,y}`,复用 `infra-core::ec_thumbprint`,与 RS SDK `compute_jkt` 逐字节等价)→
    写 `cnf.jkt=jkt`。**校验失败 MUST 拒**(`invalid_dpop_proof`),**MUST NOT 静默降级为 bearer**
    (带了 proof 却签无约束 token = 客户端以为 sender-constrained 实则不是)。
    - **jti 重放(首版必做)**:AS MUST 在 proof `iat` 接受窗内按 `(issuer/tenant, jkt, jti)`
      条件插入 replay 短命项去重(同 `dpop_jti`);重复 → 拒。**不可仅靠 iat 窗**——AS proof 无 `ath`
      (access token 此刻才签),窗内捕获的 proof 可重放。
    - **refresh 绑定延续(RFC 9449 §5)**:DPoP-bound 首签时 `jkt` MUST 持久化到 refresh family;
      refresh 换发 MUST 出示匹配 `jkt` 的 proof,缺/不匹配 → 拒,**MUST NOT 降级 bearer**(否则 DPoP
      拿到的 refresh 可后续换无约束 bearer = 降级洞)。
    - **require_dpop 策略**:client 可注册 `require_dpop=true`,启用则缺 proof 拒(防中间件丢头/
      漏配静默降级);缺省 false(opt-in)。降级算安全姿态弱化,走 §3.2 降级确认。
    - **alg**:v1 仅 `ES256`(EC P-256);RSA/其它非对称 proof 暂拒(不加宽解析面)。
    - **DPoP-Nonce**(RFC 9449 §8):首版不下发(非 MUST,留 P3+)。
    - **各 grant 路径统一**:code flow / refresh / 2LO client_credentials / device / CIBA 的 access token
      签发点**同款**(有 proof 即绑 cnf.jkt)。委托 token(token-exchange)的 cnf 继承见 §5.2 ③——**不由
      AS 直接 grant 签发解锁**:继承须绑**发起 actor 自己的 proof key**(非入站 subject_token 的 cnf),
      作为独立受控路径实现,3b"入站带 cnf → 拒"闸保持。
- **上例是 3LO(token-exchange)形态。2LO(`client_credentials`)下省略 `auth_time`(无用户登录、无意义)与 `grant_id`(2LO 不挂 Grant,§5.1);`sub`=workload、命名空间 `sub_type`=agent/service、无 `act`/`actor_types`。**
  - ⚠️ **2LO 的 `sub` 不做 pairwise、不受 §11 #12 形态选择影响(写死,消除实现分歧)**:`sub` 恒**等于或稳定派生自 workload 的 `client_id`**、**跨 RS 恒定不分 sector**。原因:§2.8 的 pairwise/sector 规则**只针对用户主体**(保护自然人跨 RS 不可关联);2LO 无自然人,且 `client_id`(RFC 9068 必填、明文在同一 token 里)本就**可跨 RS 关联**——若再把 2LO `sub` 做 pairwise-per-resource 哈希,会造成"同一 token 里 `sub` 隐私分区、`client_id` 不分区却指向同一 workload"的自相矛盾。故 **pairwise 只作用于 `sub_type=user`;`sub_type=agent/service` 一律 public 语义的 workload sub**。

ID token 按 OIDC Core 标准，**`aud` = client_id、不承载授权语义**(与 access token 的 `aud`=RS 形成对照,防 RS/audience 混淆)——RS **绝不接受 ID token 当访问凭证**,只认 access token。
**`nonce` 透传**:客户端**是否发** `nonce` 在 code flow 非强制;但**一旦发了,必须原样回填进 ID token(OIDC Core MUST,不是"可选 echo")**——实现别漏。
Refresh token 不透明、强制 rotation、复用即全链吊销（防重放）；
但**留一个短宽限窗**（如 60s 内同一 refresh token 重复提交返回同一结果），
以容忍 vault/客户端因网络抖动重试续期——否则一次丢包就会误判重放、连锁吊销整条链。
⚠️ **宽限窗必须收紧绑定,否则成了攻击者复用泄露 token 的窗口**：仅当**同一 `client_id` + 同一 DPoP key/设备实例(有 `cnf.jkt` 时)+ 同一请求指纹**时才返回缓存的同一组新 token；任何维度不符仍按复用检测处理(全链吊销)。宽限窗返回的是**已生成的同一结果,不是再签一组新 token**。

- **无 DPoP 的 public 客户端绑定偏弱**:此时退化为 `client_id + 请求指纹`,攻击者若在窗口内复制请求指纹即可取到同一组 token。故对**无 `cnf.jkt` 的 public 客户端用更短的窗口**(如 ≤5s)或更严的指纹维度,并把这一差异写进实现。
- **存储位置与保护**:宽限窗要短暂缓存"已签发的 token 响应本体"(含**可直接使用的 access+refresh token 明文**),落 DynamoDB 短命项(TTL=窗口时长,如 60s)。⚠️ 这偏离了"refresh token 只存 hash/族状态"的常规,保护要求写死为 **item-level 应用层信封加密**:token 响应 payload只存在于KMS data key加密的密文信封中;DynamoDB可明文保留主键、请求匹配与TTL元数据,但不得明文保存access/refresh/id token、scope或expires_in。**Decrypt 权限只授给 token 端点这一条代码路径**;表级 SSE-KMS 只是额外基线(它对任何有 `GetItem` 权限的路径透明、拦不住拿到明文 token,**不等于**应用层信封加密)。审计事件仍只落 `jti`/哈希,宽限缓存不进审计湖。
- ⚠️ **宽限缓存 × 吊销必须闭合(否则吊销后 60s 内仍可命中旧 token)**:grant 吊销 / refresh 复用检测触发全链吊销时,**必须同时条件删除该 refresh family 的宽限缓存项**——否则 §5.1"grant 吊销 → refresh 立即失效"的承诺在宽限窗内被缓存命中破坏。吊销是"失效缓存"的触发点之一。
- 宽限窗返回的是**已生成的同一 token**,故窗口末尾重试拿到的 access token 剩余 TTL 已缩短(如 55s 后重试只剩 ~14min)——可接受,但叠加离线 RS 的吊销残留窗口时,该 token 的实际有效期是"剩余 TTL"而非满 TTL,规划时按此。

### 2.1 · Token / 会话生命周期矩阵（集中定义，供 DEPLOYMENT §2 重叠期与 §5.1 吊销窗口引用）

散落各处的时效在此集中，作为**默认值**（可按客户端/RS 策略调整），避免各节各说各话：

| 项 | 默认时效 | 说明 |
|---|---|---|
| access token（JWT，KMS 签） | **默认 ≤15min,普通 RS 可按容量放宽(如 60min,§2.1 容量杠杆)** | ⚠️ **grant 吊销残留窗口 = 该 RS/客户端实际配置的 access TTL,不是写死 15min**(§5.1)。放宽 TTL 换签名容量的同时,吊销残留同步变长——高敏 RS 才用 15min + introspection |
| ID token（JWT，KMS 签） | ≤60min(默认) | OIDC Core;同受 KMS key 轮换影响,故进重叠期计算 |
| refresh token（家族，**不透明、不经 KMS**） | 滑动 30 天 / 绝对 90 天(默认) | 查库随机串,非 JWT、不靠 JWKS 验签;强制 rotation;复用检测 + 60s 宽限窗(§2)。**与 KMS key 轮换无关** |
| refresh rotation 周期 | 每次使用即轮换 | 一次一用,旧的立即失效(宽限窗除外) |
| authorization code | **≤60s、一次性** | 客户端认证成功后进入语义兑换即消费(成功或语义拒绝,§4);认证前失败释放 lease、不消费 |
| DPoP `jti` 重放缓存 | = DPoP proof 的 `iat` 接受窗口(分钟级,RFC 9449) | 对齐的是 **proof 重放窗口**,非 access token 生命周期(取 ≤15min 作窗口即可) |
| session / device_code | device code ≤15min;session 覆盖整个授权流(如 ≤30min) | 短命项 |
| magic-link / OTP | ≤10min、一次性 | |
| refresh 宽限缓存 | = 宽限窗(如 60s;无 DPoP public ≤5s) | 应用层信封加密,命中后按此过期(§2) |
| recovery operation success-result | 60s | 恢复提交事务内写入；tenant-bound operation HMAC + code HMAC/lookup/user/epoch/session 绑定。只允许同 operation+同码找回仍权威的原 session，重放 cookie 仅用 session 剩余寿命(§7) |
| **`/jwks.json` 的 `Cache-Control: max-age`(冻结参数)** | **默认 `max-age=300`(5min);CloudFront TTL 取同值** | 这是 AS 自己设置的响应头,**决定 key 轮换 publish-ahead 要提前多久**(§8:新 key 必须早于开始签名 ≥ 本值上架 JWKS,否则缓存旧 JWKS 且不做"未知 kid 重取"的 RS 会拒新 key 签的 token)。**必须显式冻结、不能留空让实现者猜**。关系:装了本系统 RS SDK 的 RS 靠"未知 kid 立即重取"可绕过该等待(§6);**不装 SDK 的第三方 RS 完全依赖这个值** → 取值是"轮换敏捷度 vs JWKS 请求量"的权衡,5min 是保守默认,按需下调(下调则 publish-ahead 窗口同步缩短) |
| **CMK 轮换重叠期** | **= KMS 所签 JWT 的最长寿命 = max(access TTL, ID token TTL)，即分钟~小时级** | ⚠️ **不是 refresh 的 90 天**——refresh token 不透明、不由 KMS 签,与 key 轮换无关;旧公钥只需覆盖"最后一个用旧 key 签的 access/ID token 何时过期"。DEPLOYMENT §2 B 直接引用此值 |
| **KMS Sign 配额(容量,非时效)** | 账号+区域**按密钥类型各一个池**(ECC 一池、RSA 一池)、可提额。**具体数值有区域/时间差异,⚠️ 部署前按目标 region 实查、别硬编码占位数** | ⚠️ 是 **Sign 次数**上限,不是请求数。**一次登录 = access(ES256,打 ECC 池)+ ID(RS256,打 RSA 池)**——**两签落在两个独立池、各计 1,不折半同一池**。**P0–P2:access 恒 ES256 只吃 ECC 池,RSA 池只承 ID token**(access 分流是 P3 可选,§2/§8)。同池内多 CMK **不**提升吞吐(共享该池),只能跨区域/账号分摊(§8) |

> ⚠️ **DynamoDB TTL 只做垃圾回收,不是有效期判断**:TTL 删除是**异步、官方口径可延迟至数天**。故 code / device_code / session_token / DPoP jti / 宽限缓存 / recovery operation result 的**有效性一律在读/写路径校验 `expires_at` 字段**,命中已过期项即拒/删,**绝不能靠"TTL 到了会消失"来保证过期**。TTL 仅省清理成本。
> ⚠️ **统一时钟偏移余量**:上面极短时效项(code ≤60s、DPoP proof `iat` 窗口、宽限窗)在跨 Lambda/RS 时钟偏移下易误杀。**全局声明可接受偏移(如 ±30s)**,校验 `exp`/`nbf`/`iat` 时统一套用;移除轮换旧 key 也留同样余量。
>
> 这些数字直接决定 DEPLOYMENT §2 的重叠期、§5.1 的吊销残留窗口、§8 的 TTL 清理节奏——**改任一处都要回看这三处**。
> **KMS key 轮换/迁移只受 JWT(access+ID token)寿命约束**,把重叠期与 refresh 寿命绑定是错误——那会让一把可能因怀疑泄露而轮换的旧 key 被无谓信任 90 天,削弱轮换本身的安全意义。

**签名容量模型(真正的 SaaS 规模瓶颈是稳态 refresh,不是登录速率)**:

- **初次登录项**:登录时 access(ES256→ECC 池)+ ID(**按 per-client `id_token_signed_response_alg` 落池:默认 RS256→RSA 池,注册 ES256 的客户端→ECC 池**,§2)**各打各池、各 1 次**(默认口径下 ID 几乎全在 RSA 池;登录 ECC 负载 ≈ 登录速率 × (access 1 + ES256-ID 客户端占比))。
- **稳态 refresh 项(主导)**:每条活跃会话每 `access_TTL` refresh 一次、**默认只重签 access token(ES256→ECC 池)**,故每会话恒定耗 `1 / access_TTL` 次 ECC 池签名。
  - 举例(代入**实查的 ECC 池配额** Q ops/s):access_TTL=15min 时每会话 ≈ **1/900 Sign/s** → 仅 refresh 就被 **Q×900 活跃会话**打满(Q=1,000 ⇒ ~90 万)。**主导瓶颈是 ECC 池的稳态 refresh**;RSA 池只承登录时的 ID token,负载低得多。**按部署区实查的 Q 算,别套 1,000**。
  - ⚠️ **P0–P2 access 恒 ES256、只吃 ECC 池**(不分流,§2);要抬单区上限**先靠拉长 access_TTL + 跨区分片**(下方杠杆)。**P3 可选启用 ES256/RS256 分流**后,稳态签名才摊到两池、上限 ≈ `(Q_ecc + Q_rsa − ID_token 对 RSA 池的负载) × access_TTL`——但那是 P3 的叠加红利,不是 P0–P2 的容量假设。
- **决策(明确 refresh 是否重发 ID token)**:**默认 refresh 只重签 access token、不重发 ID token**(ID token 是登录事实的证明,不必每次续期刷新;需要新 ID token 的客户端显式请求)——把稳态签名负载压到每会话 1 Sign。
- **容量杠杆的主次顺序(写死,别把次要的当主力)**:
  1. **主杠杆 = 拉长 access_TTL**:TTL 15min→60min 直接把稳态签名负载降到 **1/4**——**确定性、无运行时依赖**;代价是离线校验 RS 的吊销残留窗口相应变长(§5.1),故是**吊销即时性 vs 签名容量的显式权衡**,按 RS 敏感度分档(高敏 RS 用 introspection + 短 TTL,普通 RS 可长 TTL)。
  2. **主杠杆 = 跨区/跨账号分片**:每区各有独立两池配额,线性扩容(§8、§11 #9)。
  3. **P3 可选 = ES256/RS256 两池分流**:把单区上限抬到两池之和,但它是 **best-effort 软机制**(水位路由),**不作主容量保证**——⚠️ 恰在负载最高时若路由出 bug,会在最需要吞吐时把签名打偏,还引入多 alg JWKS 算法混淆面 + 第三方 RS 间歇拒签。故**降级为 P3 可选优化**:P0–P2 用 TTL + 分片满足容量(都确定性),**仅当实测确需再抬单区上限时才在 P3 启用分流**,届时配套 PRM 声明 alg 非固定 + 逐 RS 关分流开关(§8/§6)。SaaS 天花板不押在分流均衡上。

### 2.8 · 纯 OIDC / `/userinfo` 的 `sub` 与 audience（🔒 pairwise/sector/sub 派生规则的**唯一权威源**）

> **单一权威源约定**:pairwise 的 **sector 键、`sub` 派生公式、ID/access/`/userinfo` 的 sub 一致性、省略 `resource` 的 audience 优先级** 全部在本节定义;§1 / §2 sub 要点 / §11 #12 / DEPLOYMENT §0 / C1.1b 只**引用**本节、不重述规则(它们各自只保留形态默认值等本地决策)。任何规则改动**只在本节做**,避免多处漂移。

pairwise 下"谁按什么算 `sub`""哪个 token 能调 `/userinfo`"两条规则散见 §1/§2 正文,此节集中定死(其它节引用此处):

- **`/userinfo` 的 audience 是一个独立 resource**:能调 `/userinfo` 的**当且仅当** token `aud` = 绝对 URI 形式的 `/userinfo` 端点(`<issuer>/userinfo`);`aud`=某 MCP RS 的 access token **调不动** `/userinfo`(被 `/userinfo` 的 `aud` 校验拒)。两者不搭便车——同时要 userinfo + MCP RS 的客户端,靠 refresh 在授权集合内**下采样**另换一个 `aud=/userinfo` 的 token(§1 多 resource 下采样)。
- **`resource` 省略时的 audience 优先级(写死,消除 §1 "纯 OIDC 无 resource" 与 "default_resource" 两条规则的交界冲突)**——`/token` 请求未带 `resource` 时,按以下**顺序**决定签发的 `aud`:
  1. 客户端注册了 `default_resource` → `aud` = `default_resource`(该 RS);
  2. 未注册 `default_resource` → `aud` = `<issuer>/userinfo`(纯 OIDC 落地)。
  - ⚠️ **即:注册了 `default_resource` 的客户端,省略 `resource` 会拿到指向该 RS 的 token、而非 `/userinfo`**。这类客户端若**只想登录/查 `/userinfo`**,必须**显式带 `resource=<issuer>/userinfo`**(把 userinfo 当作一个 resource 显式请求)——不能靠"省略 resource"回落到 userinfo,因为省略已被 `default_resource` 占用。
    - 🔴 **反直觉尖角(discovery 文档须对客户端明说)**:因 §1 的 authorize↔token resource 绑定,拿 `/userinfo` token 的客户端必须**在 `/authorize` 与 `/token` 两跳都带 `resource=<issuer>/userinfo`**(authorize 阶段就绑进授权集合,token 阶段继承或传同值)——**只在 `/token` 传会因不属于 authorize 绑定集合而被拒**。这一点写进面向客户端的 discovery/接入文档,别让注册了 `default_resource` 的客户端在"为什么登录不了"上卡住。对应 C2.8 case ③ 测试。
- **pairwise 的 sector 键(两条路径)**:
  - **MCP 路径**(token `aud`=某 RS):sector 键 = **resource 标识** → 每 RS 得不同、不可跨 RS 关联的 `sub`;
  - **纯 OIDC / `/userinfo` 路径**:sector 键 = **OIDC sector identifier**(按 RFC 派生,**非简单 client_id**):客户端所有 `redirect_uri` 同一 host → 用该 host;**多个不同 host → DCR 强制 `sector_identifier_uri`**(取其 host 集为一 sector),否则 `sub` 无法确定 → **拒注册**。
    - 🔴 **实现尖角(极易踩反,签发代码里把 `/userinfo` 钉成显式分支)**:`aud=<issuer>/userinfo` 的 token **绝不能套用 MCP 路径的"sector=resource"规则**——它必须走 OIDC sector identifier,否则 `/userinfo` token 的 sector 会 ≠ ID token 的 sector,导致 **C2.11 要求的"`/userinfo` token 的 `sub` 与 ID token 一致"失败**。两条 sector 规则并列、通用 resource 规则会顺手误用到 `/userinfo`;在 SDK/签发代码里用 `if aud == issuer+"/userinfo": sector = OIDC_sector_identifier` 显式分支注释钉死。
  - **同一次 code flow 里,ID token 与并发签发的 MCP access token 的 `sub` 必然不同**(前者按 sector identifier、后者按 resource)——这是 pairwise 的**正确行为**,客户端/RS **不得假设二者相等**。唯一强一致约束:**ID token 与 `/userinfo` 返回的 `sub` 必须一致**(OIDC 硬要求,二者同 sector)。
- **实现**:`sub = HMAC(server_secret, user_id‖sector)`(可复现、不可逆推 `user_id`)。**用户级关联(委托链/introspection/审计)一律靠内部 `user_id`,非 `sub`**——pairwise 下 `sub` 随 sector 变。
- **public 形态**(【自部署】默认):无 sector 分区,`sub` 跨 RS 恒定;上述 pairwise 规则不适用,但 audience 优先级(省略 `resource` 的回落顺序)对两形态一致。
- **本节 sector/pairwise 规则只作用于用户主体(`sub_type=user`,3LO / `/userinfo`)**。⚠️ **2LO(`client_credentials`,`sub_type=agent/service`)的 `sub` 不在此列**:它恒等于/派生自 workload `client_id`、跨 RS 恒定、**不做 pairwise、不受形态选择影响**(理由见 §2 的 2LO 说明——无自然人可保护,且 `client_id` 已明文可关联,再哈希 `sub` 反自相矛盾)。

---

## 3 · 客户端模型：三种形态 + 受控 redirect 匹配

### 3.1 客户端类型

| 类型 | 认证方式 | 典型对象 |
|---|---|---|
| `public`（**默认**） | `none` + PKCE S256 强制 | mcp-remote、Claude Code、CLI、桌面端 |
| `confidential` | `client_secret_basic/post` 或 RFC 7523 `private_key_jwt` | 传统后端、AgentCore CustomOauth2 provider |
| `workload`（**agent 一等公民**） | **平台身份联邦认证**：用 AWS SigV4 / IAM 角色 OIDC token / SPIFFE SVID 证明"我是这个 workload"，**无长期 secret** | AgentCore Runtime、Lambda、K8s pod 里的 agent |

**PKCE 策略(RFC 9700 §2.1.1 / OIDF Basic compatibility profile)**:

- `public` 的 authorization code 请求 **MUST** 带非空 `code_challenge` 且显式使用 `S256`；`workload` 不得走 authorization code。
- `confidential` 仍 **SHOULD** 使用 PKCE。只有 ClientStore 中预注册或 DCR 创建的 client 当前仍为 `confidential`、其注册的 `token_endpoint_auth_method` 在当前运行时可执行且不为 `none` 时，`/authorize`、PAR 与 `/consent/decision` 才可接受 challenge 与 method **同时完全缺失**的请求；空 challenge、仅 method 等畸形 tuple 一律拒绝。CIMD client 因兑换使用授权时快照而不重评估当前 client，MUST 使用 PKCE。
- 任一 client 一旦在授权请求发送 challenge，AS **MUST** 在 token 端要求并校验对应 verifier。反向不一致也 fail closed：没有 challenge 的 code 若携带 verifier，返回 `invalid_request`。
- `/token` 兑换任何 authorization code 都重新读取 ClientStore 当前记录；若 client 已重分类为 workload，必须在认证前释放 code lease 并拒绝。无 challenge 的 code 还不得固化一份宽松认证策略：若 client 已降级为 public/`none`、改成当前运行时不可执行的方法或不能成功认证，同样拒绝。这使授权后的类型/能力变化不能绕过 policy，也允许修复配置后重试原 code。

**OAuth 2.1 draft 边界**:2026-03 的 draft-15 §7.5.1.1 仅在 confidential client 且 AS 有合理把握其正确实现 OIDC nonce 时允许省略 PKCE。OIDF Basic OP profile 同时包含 confidential code-flow 无 PKCE场景和“无 nonce 也应成功”模块，因此上述兼容 profile 为通过该生态验收，允许已认证 confidential client 在未证明 nonce 行为时省略 PKCE。它满足 RFC 9700 对 AS 的强制义务，但该特定场景**不宣称完整符合 OAuth 2.1 draft-15**；客户端仍应发送 PKCE。

**`private_key_jwt` 信任与重放边界**:注册时提供 inline public JWKS 或受保护 HTTPS `jwks_uri`(恰一),并逐 client pin `RS256` 或 `ES256`。RSA modulus 限 2048..8192 bit，exponent 限 1..8 byte；URI 最长 2048 byte。断言 MUST 有唯一 `kid`,`iss=sub=client_id`,`aud` 精确等于当前认证端点(含 `/sessions/{id}` 具体路径)的绝对 URL,并带 `iat`/`nbf`/`exp`/非空 `jti`;寿命上限 300s、时钟偏差 30s。`jti` 以 tenant+client 隔离、HMAC 后原子消费。远程 JWKS 仅允许 HTTPS:443、公网 DNS 和固定解析 IP,禁代理/重定向,限制 64KiB/10 keys；仅接受 `use` 缺省/`sig` 且 `key_ops` 缺省/含 `verify` 的 key。缓存最多 256 个 URI；冷取与 unknown-`kid` 强刷按 URI 单飞，失败在 5s 限速窗内负缓存。能力仅在 replay store 可用时进入 discovery/DCR/Admin；已持久化 private client 若依赖缺失则 fail closed。

`workload` 类型是关键创新：agent 不再靠 client_secret，而是拿自己运行时的
平台身份（如 assume 的 IAM 角色）来认证，类似 GitHub Actions OIDC 联邦。
密钥零管理、可精确到"哪个 Lambda/哪个 Runtime 才是这个 agent"。
⚠️ **`workload` 客户端只用于 2LO(`client_credentials`)与 token-exchange 的 actor 身份,不可走 `authorization_code`/3LO**(它是机器身份、无浏览器、无真人 consent)。要代表用户,workload 用自己的身份 + 用户 Grant 走 token-exchange(§5.2),不直接跑 3LO。

> ⚠️ **这是全文最有原创性、也最需要在 P2 开工前落到序列图的一块**——"用 SigV4"一句话不可直接实现，
> 因为 AS 的 `/token` 端点**拿不到调用方的 AWS 密钥、无法重算 SigV4 签名**。下面按平台明确认证机制与**验证路径**：

这些不是 registered-client 的标准 `token_endpoint_auth_method`,而是本系统定义的**自定义 workload auth method**(仅在 token metadata 中按 phase 显式命名,如 `aws_sigv4_caller_identity`、`workload_oidc_jwt`、`spiffe_jwt_svid`、`spiffe_svid_mtls`;信任绑定走管理面而非公开 DCR),别与标准 `private_key_jwt` 混淆——后者是客户端**自签**认证 JWT,而这里 assertion 由**平台签发**,信任锚是平台而非客户端自持密钥。

| workload 平台身份 | 落到 OAuth 的机制（自定义 auth method） | AS 侧验证路径 |
|---|---|---|
| **IAM 角色 / SigV4**（Lambda、Runtime、EC2） | 客户端提交**预签名的 `sts:GetCallerIdentity` 请求**作为 `client_assertion`（借鉴 HashiCorp Vault AWS auth） | AS 转发给 STS → 拿**已验证 caller ARN** → 按信任策略映射 client_id。**防重放/防转用是硬要求**（见下方⚠️） |
| **Runtime / K8s OIDC token**（推荐，自校验） | **workload federation assertion**：`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`，assertion 是**平台签发的 OIDC JWT** | AS 用平台 JWKS **本地验签**（无外部调用），校验 `aud`=本 AS、`exp` 短、按 `iss`+`sub`(role/subject) 匹配信任策略——最干净 |
| **SPIFFE JWT-SVID**（`spiffe_jwt_svid`，自校验，推荐） | JWT-SVID 作 `client_assertion`（同 `jwt-bearer` wire type；`sub`=SPIFFE ID、`aud`=本 AS、由 trust domain 签名 key 签，签名即持有证明——**非签发后 holder-of-key，仍是 bearer assertion**） | AS 用该 **trust domain 的 trust bundle JWKS 本地验签**（无外部调用；bundle **独立于 AS 自身 JWKS**），校验 `aud`=本 AS、`exp`/`nbf` 短、**信任锚 = 从 `sub` 解出的 trust domain**（**MUST NOT 以 `iss` 作信任锚**——SPIRE 的 `iss` 常是 server URL、非 trust domain），按完整 SPIFFE ID 匹配信任策略 → client_id。支持 ES256(SPIRE 默认 EC P-256)+ RS256 |
| **IAM Roles Anywhere / X.509-SVID mTLS**（`spiffe_svid_mtls`，**已实现 P3,仅 SelfHosted**） | X.509 SVID 作 **mTLS 客户端证书**（PoP 依赖 TLS 握手的私钥证明）| 校验证书链到受信 trust bundle,按 SPIFFE ID 映射 client_id。**⚠️ X.509-SVID 不降级成裸 `client_assertion`**——脱离 mTLS 握手,裸证书可复制冒充(无 PoP);故 X.509 路径**只走 mTLS**,需单独 mTLS 自定义域名(见下方⚠️)。**落地形态**:独立 API Gateway mTLS 自定义域名(绕 CloudFront——统一入口不转发客户端证书),truststore=S3 桶存签发 SVID 的 CA bundle,链验证在握手期由 API Gateway 承载;AS 从 `requestContext.authentication.clientCert` 取已验链叶子证书 → SAN 唯一 `spiffe://` URI → trust domain 锚 → 映射 client_id。**仅 SelfHosted + Phase≥P3 + feature 开**才启用(单 mTLS 域名 Host 不携带租户,SaaS 逐租户解析延后);启用时 discovery 宣告 `spiffe_svid_mtls`(经独立 mTLS 端点) |

⚠️ **OIDC 路径的隐含前提(决定哪些平台能走这条最干净的路)**:平台 token 的 `aud` **必须能被定向到本 AS issuer**。可配置 audience 的平台没问题(K8s projected SA token 可指定 audience、GitHub Actions OIDC 可传 `audience`);但有些运行时的平台 token audience **固定**(如指向 `sts.amazonaws.com` 或平台自身)——这种 token **不能用**,**绝不可为迁就它而放宽 `aud` 校验**(放宽 `aud` 正是 confused-deputy/token 转用的入口)。做不到 audience 定向的平台**只能走 SigV4/STS 兜底**。

⚠️ **SigV4/STS 路径必须堵住"预签名请求即 bearer 凭证"的风险**——预签名 `GetCallerIdentity` 一旦泄露,在其有效期(~15min)内谁拿到谁就能冒充,还可能被拿去打别的 Vault 类服务再转用:

- **audience 绑定 + 该头必须在签名范围内(真正的锁扣)**：要求客户端把本 AS 标识签进一个头(如 `X-Agent-Auth-Audience: <as-issuer>`,对标 Vault 的 `X-Vault-AWS-IAM-Server-ID`)。**AS 必须先确认该头出现在请求的 `SignedHeaders` 列表里、再校验其值 = 自己**——STS 只验签名覆盖的内容、根本不看这个自定义头,若 AS 不检查它是否被签名,攻击者就能在转发前塞一个**未签名的伪造头**绕过绑定。
- **短 TTL + replay cache**：只接受签发时间很近的请求,并按请求哈希/`jti` 做一次性 replay 缓存(DynamoDB `dpop_jti` 同类短命项),窗口内重复即拒;
- **STS host allowlist**：只转发给固定 STS endpoint,拒绝客户端自带的 endpoint(防 endpoint 伪造)、header allowlist。
- ⚠️ **STS 是签发热路径上的同步外部依赖**——与 §8 把 AVP 移出热路径是同一类问题(尾延迟 + 硬依赖 + 限流面)。故 SigV4/STS 兜底路径要加**超时 + 熔断上限**,延迟/可用性影响须定量;这也强化"**优先自校验 OIDC/SVID 路径**"的方针(它本地验签、无同步外呼)。

⚠️ **SPIFFE 的两种 SVID → 两条独立路径(client_assertion vs mTLS)**:SPIFFE 定义 **JWT-SVID**(JWT)与 **X.509-SVID**(证书)。二者 PoP 模型不同,落到本系统是**两个独立 auth method**:

- **JWT-SVID = `spiffe_jwt_svid`(client_assertion,已实现路径)**:JWT-SVID 是自包含 JWT,**签名即持有证明**(与 `workload_oidc_jwt` 同构,无 mTLS 依赖),走 `client_assertion` 应用层验签最干净。**这是 client_assertion 路径下唯一 PoP 自洽的 SVID 形态**。
- **X.509-SVID = `spiffe_svid_mtls`(mTLS,已实现 P3,仅 SelfHosted)**:X.509-SVID 的 PoP **本就依赖 TLS 握手对私钥的证明**;若把裸证书当 `client_assertion` 提交(脱离握手),证书可复制冒充 = **无 PoP**,故 X.509 **只能走 mTLS**、不降级成 client_assertion。而 API Gateway HTTP API 的 mTLS 是**按自定义域名、连接级**的,想在同一个 `/token` 上混 `none`/PKCE/SigV4 与连接级 mTLS 相性很差,需**单独的 mTLS 自定义域名**。**落地形态**:建**独立 mTLS 自定义域名**(绕 CloudFront,直连 API Gateway 连接级双向 TLS;truststore=S3 CA bundle,链验证在握手期完成),映射到同一 HttpApi/`$default`;X.509 身份**仅当** `requestContext.authentication.clientCert` 存在才激活(execute-api/CloudFront 回源路径恒空 → 不误触),连接层身份**排他**(忽略 body client_assertion)。**仅 SelfHosted**:单 mTLS 域名 Host 不携带租户、SaaS issuer 是 per-tenant,故 SaaS X.509-mTLS(per-tenant mTLS 域名 + per-tenant truststore)**延后**为独立后续;discovery 在 **SelfHosted + Phase≥P3 + feature 开**时宣告 `spiffe_svid_mtls`,否则不宣告。

**ARN/subject → client_id 的信任绑定**在管理面登记时声明（类比 GitHub Actions OIDC 的 subject claim 信任策略），
支持前缀/条件匹配（如"这个 Runtime ARN 前缀下的都是此 agent"）。
> ⚠️ **caller ARN 的形态(SigV4 路径实现契约,钉死避免踩坑)**:`sts:GetCallerIdentity` 返回的是**assumed-role ARN**——`arn:aws:sts::<账号>:assumed-role/<RoleName>/<SessionName>`,**不是** IAM role ARN `arn:aws:iam::<账号>:role/<RoleName>`。故信任绑定的 `role_arn_pattern` **MUST 按 assumed-role 形态书写**(如 `arn:aws:sts::<账号>:assumed-role/AgentRuntime-*/*` 或前缀 `arn:aws:sts::<账号>:assumed-role/AgentRuntime-*`),AS **按 STS 原样返回的 ARN 直接匹配、不做 sts↔iam 归一**(归一会引入"把 session 名当角色名"等歧义)。管理面登记 workload 信任时须用 assumed-role 形态;文档/控制台须提示这一点(踩坑高发)。SessionName 由 assume 方控制、不可信,故 pattern 通常只锚到 RoleName 段、SessionName 用 `*`(但绝不用纯 `*` 匹配一切,见前缀匹配 fail-closed)。
**优先自校验的 OIDC/SVID 路径**（无同步外部依赖）；SigV4/STS 路径给"只有 IAM 角色、没有 workload OIDC token"的场景兜底。
> **登记路径**:`workload` 客户端**不走 §3.2 的开放/票据/软件声明三档 DCR**(那三档面向 public/confidential)——它的信任绑定(ARN/subject/SPIFFE ID → client_id + 匹配条件)是**管理面配置**,经 Admin/控制面 API 登记(【自部署】admin 配置、【SaaS】租户控制台),因为绑定的是平台身份信任策略、非自助注册。
>
> **【SaaS】** 跨账号场景下 SigV4/STS 路径要额外核对 caller 账号是否属于该租户已登记的可信账号集(防他人账号 assume 出的 ARN 冒充);OIDC 联邦则按**逐租户** trust bundle 验签,不同租户不共享信任锚。**【自部署】** caller 多在同账号内,信任绑定可简化为账号内 ARN 前缀匹配。

### 3.2 客户端准入优先级与 DCR fallback

- **优先级固定**:tenant-scoped 预注册 client → 未知 URL-form `client_id` 的 CIMD → RFC 7591 DCR fallback。预注册 URL client 永远优先,远端文档不得 shadow 本地控制面记录。
- **MCP 新集成优先 CIMD**:只有 discovery 宣告 `client_id_metadata_document_supported:true` 时客户端才使用。resolver 只接受 tenant/deployment allowlist 内、默认 443 端口的 HTTPS 非 root URL；SSRF/DNS rebinding/重定向/大小/总时限全部 fail closed，并以 tenant+host 出站令牌桶和进程内无等待并发闸限制匿名冷缓存 fetch。授权时验证的 metadata snapshot 随 code 与 refresh family 持久化,token/refresh 不重新 fetch 可变文档。public 使用 `none`；confidential 仅接受文档内 inline JWKS 的 `private_key_jwt`。
- **信任策略不是开放 Internet 开关**:`AGENT_AUTH_CIMD_ALLOWED_DOMAINS` 提供部署级精确 host allowlist，`AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS` 提供 SaaS tenant 覆盖/补充。缓存按 tenant + 精确 URL 隔离；未配置非空策略时即使 gate 打开也拒启动且 discovery 不宣告。
- **DCR application type**:`web` redirect 必须是 HTTPS host，且拒绝 localhost 与私有/保留 IP 字面量；`native` 仅 reverse-domain private-use scheme 或 HTTP loopback。新记录显式持久化，旧记录缺失或未知字段按 `web` 处理。DNS 名称的公开可达性不作为注册时安全边界，避免把一次性 DNS 结果误写成防重绑定保证。

- `POST /register` **默认策略随形态而变**：**【自部署】** 内网可信，可默认 `open`；
  **【SaaS】** 目标默认收紧到 `initial_access_token`（`open` 仅按租户显式开启），逐租户独立配额。P0 已实现
  `open` / `initial_access_token`；`software_statement`（签名声明注册）保留为后续兼容能力，但不再优先于
  MCP CIMD，在验签与 issuer 信任锚落地前必须 fail-closed 返回 501，不得作为可部署档宣称可用。
- **当前 SaaS 部署边界**:逐租户 mode/ticket 控制面尚未落地，`AgentAuthSaas` 在 Stack 构造期禁止
  fleet-wide DCR mode/共享票据，`/register` 缺省全拒。该限制避免一张平台级票据跨租户注册 client；
  后续只能以逐租户配置开放 `open` 或 `initial_access_token`。
- **"零配置连接"的适用边界(避免与收紧默认冲突)**:
  - **`open` 档(自部署默认、SaaS 显式开启的租户)** → 真正零配置:客户端可直接匿名 `POST /register` 拿 client_id；受控批量调用方也可显式带 tenant-scoped IAT，改走票据自身限额。显式无效 IAT 必须拒绝，不能回落匿名;
  - **`initial_access_token` 档(SaaS 目标默认)** → **不是无凭证零配置**,客户端需先持有注册票据。此时"零配置"指**发现链路零配置**(PRM→AS metadata→register 端点自动走通),但注册那一步要票据。票据的分发是**控制面/onboarding 的事**(如租户在控制台生成 initial access token 交给其 agent 部署),不在协议自动发现范围内。P1 `software_statement` 落地后同理要求客户端先持有签名声明。
- 防滥用：配额以**应用层 DynamoDB 令牌桶/计数为主**(按 client_id/租户聚合),**WAF 只做 IP/Host/ASN 粗兜底**。⚠️ **WAF 做不了按 client_id 限流(硬约束,别把它挂 WAF 上)**:WAF rate-based rule 的聚合键只有 IP/forwarded-IP/header/cookie/query/URI/method/JA3/ASN——**不含 body 及 body 内字段**。而 `POST /token` 的 `client_id` 在 **form body**(public)——WAF 抓不到;只有 confidential 的 `Authorization` 头勉强可聚合。API Gateway HTTP API 也无 per-client usage plan。故**"主控闸按 client_id"必须落应用层**(Lambda + DynamoDB),这直接决定 P0 的配额表设计。(`/authorize` 的 client_id 是 query 参数、SaaS 租户可按 Host,这两个 WAF 能限。)
- **未使用的动态客户端回收**。⚠️ **回收是显式流程,不是裸 TTL**(与 §8"`clients` 绝不能挂裸 TTL"一致):后台任务按 `last_used_at` 扫描、**确认该 client 无 active refresh-token family、无未过期 code/session、无 active Grant(Grant 是 P2 才有;P0/P1 靠前两项)后才回收**——否则会删掉仍有活跃 refresh token 的 client,形成悬空引用。
  且**回收先转 tombstone、保留到 access token 最大 TTL 之后再硬删**(其间还有离线校验的 access token 引用该 client_id);**审计元数据不随 client 记录消失**(单独留存)。仅"从未激活、无任何关联"的注册残渣可挂 TTL(见 §8 例外)。
  ⚠️ **且 per-IP 本就不适合 agent**:本系统客户端是 agent,常从少数集中出口 IP(Lambda NAT、Runtime、K8s egress)发高频请求,per-IP 阈值要么松到无用、要么误杀——更坐实"主控闸必须按身份维度落应用层"。
  ⚠️ **但 `client_id` 维度对 open DCR + public 有绕过口**:public 的 `client_id` 是 `POST /register` 免费自助铸造的,攻击者注册 N 个就得 N 个限流桶。故**匿名/首次注册这一跳**用 **per-IP 粗兜底 + 全局配额(+ 可选 PoW)**,注册后再切到 `client_id` 维度。受控批量任务显式携带有效 tenant-scoped IAT 时走可撤销的票据桶，不提高匿名容量；无效 IAT 不得匿名降级。SaaS 因默认票据注册自然化解;缺口在自部署 `open` 档与通用 public 路径——写进"零配置边界"。
- **RFC 7592 管理端点鉴权(open DCR + CORS 场景尤其重要)**:`GET/PUT/PATCH/DELETE /register/{id}` 必须凭 DCR 首次响应下发的 **`registration_access_token`**(Bearer)访问、且只能操作对应 `registration_client_uri` 指向的那个 client;`registration_client_uri` 必须是由当前可信 issuer 派生的同源 fully qualified URL,客户端按原值使用,不得自行拼接。无 token 或 token 不匹配一律拒。绝不能因 `open` DCR 就让管理端点匿名可达。
  C4.3 的 exact 证据由 `dcr_register_then_code_flow`、`dcr_invalid_host_is_rejected_before_client_is_persisted`、`rfc7592_self_service_and_domain_isolation`、`register_per_ip_flood_throttled` 与 `dcr_open_accepts_valid_iat_without_weakening_anonymous_flood_gate` 组成，分别固定可信 issuer 派生 URI/不可信 Host 零持久化、management token 归属与 PATCH/DELETE 生命周期、IP A/B 独立匿名桶，以及 t1/t2 IAT 凭据与额度隔离。
- **防 consent phishing**：`open` 档下任何人都能注册任意 `client_name`/`logo_uri`，而 RFC 7591 元数据是**自声明、不可信**的。
  故 consent UI 对动态注册客户端显示"**未验证**"标识、对 `logo_uri` 做同源/尺寸约束或干脆不渲染外链图片，
  防止攻击者用仿冒品牌的客户端诱导用户授权。
- RFC 7592 管理端点全支持：标准 **`PUT` 全量替换**保留,另**扩展 `PATCH` 部分更新**（只改传入字段,坑 2.6 的正解）；
  任何**降低安全姿态的变更**必须带 `"confirm_downgrade": true` 才生效，响应中列出降级明细。
  ⚠️ 判定用**"安全姿态单调性"原则 + 一份可扩展清单**:当前公开可变面中的放宽 redirect、**认证方式弱化**(如 `private_key_jwt` → secret → `none`)和 DPoP 由强制转可选都算降级；PUT 省略可选字段按全量替换默认值参与同一判定。refresh rotation 在当前 profile 恒开启、token validity 不提供 per-client 延长字段,二者不能靠 `confirm_downgrade` 解锁；`push + require_dpop` 因不存在客户端 token 请求 proof seam 始终无效。共享 classifier 仍固定 rotation/validity 的更弱方向，公开 PATCH/PUT schema 以闭合集合强制未来新增受管字段先完成方向与接线审计。

### 3.3 Redirect URI 匹配（坑 2.4 的正解）

三种模式，注册时按 URI 逐条声明。**注册值与入站值都先按下方规则 canonicalize,再比较**（不用"字节级/原始串"措辞,以免与规范化冲突）：

1. `exact` —— 默认，**canonicalize 后完全相等**。
2. `prefix` —— **host 精确 + scheme 必须 https + path 前缀固定 + 尾部单层通配**：
   `https://bedrock-agentcore.us-east-1.amazonaws.com/identities/oauth2/callback/*`
   一条就覆盖 AgentCore 所有 UUID callback。通配段禁止 `..`、`?`、`#`、二级路径。
3. `loopback` —— RFC 8252：`http://127.0.0.1:*/callback` **与 `http://[::1]:*/callback`（IPv6 环回也要覆盖）**，端口任意（CLI/桌面客户端标配）。**只认 IP 字面量,不认 `localhost`**(RFC 8252 最佳实践——`localhost` 可被 DNS/hosts 劫持到非环回;这是**有意排除**,用 `localhost` 的客户端须改用 `127.0.0.1`/`[::1]`)。

**canonicalize 规则(三种模式统一适用),顺序关键**（否则绕过防线）：**先 parse URI 成组件(scheme/host/port/path/query),再分组件处理**——解码检查只作用于 **path/通配段**,query 走独立的精确匹配,两者不混。

1. **path/通配段:先百分号解码一次 → 再做 `..`/`//`/`?`/`#`/二级路径检查**——否则 `%2e%2e`、`%2f` 等编码形式会绕过 `..` 拦截。
   **只解码一次,且解码后若 path 段仍含 `%` 一律拒绝**(不允许双重编码,如 `%252e%252e`)——**不做递归解码到不动点**,递归解码本身历史上就是绕过来源。
   > ⚠️ **已知限制(安全取舍,非 bug)**:此规则拒掉 path 段"解码一次后仍含 `%`"的 URI(含字面 `%25` 的 path 罕见,接受此限制)。
2. **query 不参与上面的 path 解码规则**:按**规范化后的原始 query 精确匹配**——`prefix`/`exact` 模式下入站 query 必须与注册值**逐字节相等**(注册时声明了 query 就精确对,没声明就要求入站也无 query);**通配段 `*` 绝不吞 query**(§`prefix` 的通配只在 path 末段)。即:query 不解码检查、只精确比对,故与"解码后拒 `?`"不冲突——`?` 是组件分隔符、在 parse 阶段已切出,不是 path 里的字面 `?`。
3. 其余组件:**port**（loopback 忽略、其余精确）、**userinfo**（一律禁止 `user:pass@host`）、**尾部斜杠**（`/callback` 与 `/callback/` 视为不同,显式声明）、**host** 小写化后精确比对（scheme、host 大小写不敏感;path 大小写敏感）。

⚠️ **阶段**:**P0 只落地 `exact` + `loopback`**(canonicalize + 精确匹配,C4.4a);**`prefix`/通配匹配随 prefix 模式到 P1**(C4.4b + C4.6,§10 P1 的 redirect fuzz 一并验收)——P0 客户端要覆盖多 callback 只能逐个登记 exact。
`prefix` 模式默认关闭，需管理策略显式允许该 host（allowlist），防开放重定向。
⚠️ **多租户共享 host 的残余风险**：示例前缀的 host（`bedrock-agentcore.*.amazonaws.com`）是**全体 AWS 客户共享**的——
任何人建 provider 都能拿到该前缀下自己的 UUID callback。故 `prefix` 模式**仅允许授予 confidential 客户端**
（**PKCE 已挡住外部拦截者兑换**;此限制额外防的是**共享 host 上攻击者自建同前缀 callback + 无 secret 兑换**——confidential 的 secret 是这层的补充防线,与 PKCE 互补非冗余）；**public 客户端禁用 prefix**,否则授权码可能被送进攻击者可控的同前缀 callback。(注:mcp-remote/Claude Code 等 public 客户端通常不走共享 host 前缀、AgentCore 又是 confidential,主用例未被挡。)

---

## 4 · 可观测授权会话状态机（坑 1.1/1.2/1.3 的正解）

每次授权流（authorize / device / CIBA / token-exchange 异步 consent）创建一个
**授权会话**，`GET /sessions/{id}` 返回下方状态。

**查询鉴权（防 IDOR / 枚举）**：`session_id` 会落进日志、URL、代理，故**绝不能只凭 id 查询**。**两种可接受的鉴权方式(满足其一)**:
  (a) **`session_token`**——高熵、一次性绑定该会话(不进 authorize URL,随 PAR 响应体 / device 响应 / 会话创建响应返回),`Authorization: Bearer <session_token>` 出示;
  (b) **confidential client 认证 + 会话归属校验**——client 认证通过且该会话的 owner client_id == 认证身份,才放行。
下面按客户端类型说明各走哪条:

- **confidential 客户端如何拿到 session_id**:凭 client 认证调 **`GET /sessions?client_id=me`** 列出自己名下会话(P1 落地,这是它的主要获取路径),再对具体 id 查询;不依赖任何响应体回带。
- **public 客户端凭 `session_token`**——它与 PKCE `code_verifier` **独立**,不复用 code_challenge 派生物(那玩意在 authorize URL 里公开,任何旁观者都能拿来查状态与 `last_error`)。`session_token` 的载体(PAR 响应体 / device 响应 / 会话创建响应)见下方阶段对齐。
- 比对用**常量时间**，未命中统一返回 404（不泄露"会话是否存在"），杜绝枚举。

> **阶段对齐(重要,否则 P1 的 public 客户端拿不到查询凭证)**:
>
> - **confidential 客户端 P1 即可用**——`GET /sessions?client_id=me` 列表 + 按 id 查询,全程 client 认证,不需要任何响应体回带(AgentCore 类消费方即属此列,§4 的可观测性对它 P1 就真正可用);
> - **public 客户端**的 `session_token` 载体(device 响应 P2、PAR 响应体 P3)晚于端点(P1),而纯 `GET /authorize` 是浏览器重定向流、无安全响应体——在 P1/P2 期间,同步 3LO 的 public 客户端在场、直接拿 code,本就不需要轮询;真要提前,备选是 P1 加轻量 **`POST /sessions/authorization-init`**(建会话、响应体回 `session_token` + 供 `/authorize` 引用的 `session_ref`,即 PAR 极简前身),**默认不做**。
> P1 验收口径据此(见 §10)。

```text
created
  → pending_user_authentication      # 等用户登录
  → pending_consent                  # 已登录，等用户点同意
  → code_issued_awaiting_exchange    # code 已发，等 client 来换（对应坑 1.1 的 AWAITING_COMPLETE）
  → exchange_failed                  # 交换被拒 —— 附结构化 last_error
  → complete                         # token 已发
  → expired / denied / revoked
```

上面的状态是 **auth-code 流**的形状;**device / CIBA 流有各自的等价态**(避免 P2 落地时临时加字段):

| 通用态 | auth-code | device flow | CIBA (poll) |
|---|---|---|---|
| 等用户动作 | `pending_user_authentication`/`pending_consent` | `authorization_pending`(含 `slow_down` 节流) | 通知投递中 / `authorization_pending`(审批中) |
| 已授权、待客户端取 token | `code_issued_awaiting_exchange` | 用户已批、等客户端轮询 `/token` | 用户已批、等客户端凭 `auth_req_id` 轮询 `/token` |
| 成功 / 失败 / 过期 | `complete` / `exchange_failed` / `expired` | 同 | 同 |

- **`last_error` 透传**：交换失败时原样带出 `{"error":"invalid_redirect_uri", "error_description":"...", "at":"token_endpoint", "ts":...}`——
  这一个字段就能消灭原文档里"tokenEndpoint 零调用 → 错误归因"的整段弯路（坑 1.2）。
- **`exchange_failed` 后 authorization code 的命运(状态机自解释,写死语义)**:
  客户端认证成功并证明自己是 code 绑定的 client 后，code 在首次**授权语义兑换**
  尝试时即被消费(防重放)；redirect URI、PKCE、resource/scope 或账户状态等语义失败
  落 `exchange_failed`，不能用同一 code 重试，须重走授权得新 code。客户端认证前的
  失败(未知/已回收 client、Basic/form 身份冲突、secret/assertion 错误)不得让未认证
  请求烧掉 code：释放 signing lease、不迁移会话状态，合法客户端仍可重试。
- **成功兑换后的 code 重放**:再次呈现已消费 code 的请求仍须先证明 code-bound client
  authority 及原 redirect/PKCE 绑定；错误 client/secret/redirect/verifier 不得触发撤销 DoS。
  绑定验证成功后返回 `invalid_grant`，并按
  RFC 6749 §4.1.2 的 SHOULD 尽可能吊销首次兑换创建的 Grant、refresh family 与宽限缓存。
  该清理在普通 client 签发限流之前执行，限流桶耗尽不能让已认证且绑定正确的 replay 跳过撤销。
  `/userinfo` 与 introspection 必须读取同一在线授权状态，使该 code 签发的 access token
  在这些在线验证面立即失效；不声称能在 JWT 到期前强制未 introspect 的离线 RS 停止接受。
- **可观测性对不同客户端的可用性**:见 §4 上方——confidential 凭 `GET /sessions?client_id=me` 幂等查询(不存在"每次轮询开新会话"的暗坑,坑 1.3);public 凭 `session_token`。
- 每次状态迁移发 EventBridge 事件 → 审计湖。⚠️ **权威状态是 DynamoDB 会话记录,EventBridge 事件只是投影**(at-least-once、无序投递)——"完整回放一次授权"以会话记录 + 带**单调序号(每会话递增)**的事件为准,按序号去重排序,**不依赖事件到达顺序,也不把回放能力押在事件流上**。

---

## 5 · Agent 委托模型：user → agent → sub-agent

这是整个系统区别于"又一个 OAuth server"的核心。

### 5.1 Grant：一等公民的授权记录

> ⚠️ **阶段与"过渡期载体"(消除 Grant 阶段归属矛盾,实现者必读)**:**完整的 Grant 对象 + `/grants` API 是 P2** 交付(§10)。但 §1/§2/§6 描述的若干 **P0/P1 协议行为**要引用"授权记录"作为权威源——**resource 集合绑定**(§1)、**scope 交集权威源**(§1/§6)、**`grant_id` 指向**(§2)。这几件事 P0/P1 就要有落点,不能悬空。规则:
>
> - **P0/P1 阶段这些职责的实际载体 = refresh-token family 记录**(它充当 **"Grant 前身"**):`/authorize` 声明的整个 `resource` 集合、每 resource 的 scopes、绑定关系,**都记在 refresh-family 记录上**;下采样、scope 交集在 P0/P1 以该记录为权威源读取。
> - **`grant_id` claim 从 P2 才出现**(Grant 对象正式化后)——P0/P1 的 3LO token **不带 `grant_id`**,身份/授权关联靠 refresh-family id + 内部 `user_id`。§2 的 `grant_id` 说明按此标注起始阶段。
> - **P2 把 refresh-family 里的隐式授权数据迁移/正式化为独立 Grant 对象**(带 `per_resource[]`/`constraints`/`status`),此后权威源转为 Grant;refresh-family 回归"纯 token 轮换记录"。这一步是 §5.1 "非隐式的 refresh token 副作用"设计初衷的**兑现点**——P0/P1 是**知情的过渡妥协**(用 family 记录兜底),不是永久退回隐式语义。
> - §3.2 client 回收逻辑已按此写(P0/P1 靠 refresh-family/code/session,Grant 是 P2 才判),此处与之对齐。

用户对 agent 的授权固化为 **Grant 对象**（P2;非隐式的 refresh token 副作用）：

```text
Grant {
  grant_id, user_id, agent_id (workload client),
  // ⚠️ 按 resource 结构化,不用扁平数组——否则"哪个 scope/RAR 属于哪个 RS"
  //    只能靠 kb:/mail: 命名规约隐式担保,下采样逻辑压在脆弱规约上易出事
  per_resource: [
    { resource: "https://mcp.kb.example.com",
      scopes: ["kb:read","kb:search"],
      authorization_details: [ {RFC 9396 RAR，如 "只能读 2026 年的文档"} ] },
    { resource: "https://mcp.mail.example.com", scopes: ["mail:read"], ... }
  ],
  constraints {
    max_act_chain: 1,                    // 深度闸
    actor_allowlist: ["agt_...","spiffe://.../agent/*"],  // 身份闸:只有这些 workload 可作 actor(§5.2)
    expires_at, ip/vpc 约束...
  },
  status: active | revoked | expired
}
```

> **Grant 专用于 3LO 与委托链,`user_id` 必填。2LO 不走 Grant**:`client_credentials`(2LO,P2)的 token 无用户、不挂 Grant,workload 自主行动"能拿哪些 scope/resource"由 **client 注册时的 allowed scopes/resources 策略**约束,不是 Grant。别把两条路径混进同一张表——一个是"用户授权记录",一个是"客户端注册策略"。

- 用户可在自助页面/`GET /grants` 查询"我授权过哪些 agent 做什么"，一键吊销。
- Grant 吊销的**生效边界要如实说明**（勿夸大成"立即全失效"）：
  - **refresh token 立即失效**（续期即被拒）；**同时条件删除该 family 的宽限缓存项**（§2），否则吊销后宽限窗内仍会命中旧 token；
  - **access token 的即时性取决于 RS 校验方式**：做 introspection 的 RS 立即感知；
    做**离线 JWT 校验**的 RS 有**残留窗口 = 该 RS 配置的 access token TTL(默认 ≤15min,放宽到 60min 则残留 60min)**，期间 token 仍被接受——这是随 TTL 变的**实际值**,不是固定 15min 的承诺。
    ⚠️ **RS 若缓存 introspection 结果(性能常见做法),即时性随缓存 TTL 流失**——"秒级吊销"名不副实。RS SDK 须明确 **introspection 缓存 TTL 语义**:高敏路由缓存 TTL 应 ≤ 秒级或不缓存,否则退化成"离线校验 + 残留窗口"。
  - 需要"秒级吊销"的高敏 RS 应选 introspection(且短/无缓存)或更短 access TTL。
- **`max_act_chain`**：默认 `1`（只允许一级委托）；需要 agent→sub-agent 深链时在 Grant 里显式放开，
  与 §2 token 的 `act` 链深度对应（示例 token 只画一级正因默认即 1）。

### 5.2 三种把 token 交到 agent 手里的路径

1. **同步 3LO**：经典 authorization_code + PKCE，用户在场点同意。
2. **异步 consent（CIBA / device）**：agent 先行动，撞到需要授权 →
   AS 生成 consent URL / 推送到用户注册的通道（邮件、IM webhook）→
   用户异地批准 → agent 侧会话状态翻转为 `complete`。
   **这为 MCP elicitation（`-32042` URL elicitation）提供服务端原语**——
   agent 平台把 consent URL 经 elicitation 推给前端即可，AS 天然配合。
   （注意：这解的是**直连**路径的异步授权，并不能让坑 3.1/3.2/3.5 的 **Gateway** 死路复活——见 §9 措辞。）
   **CIBA 投递模式**先只做 **poll**（无需回调基建，最简单）。
   ⚠️ **轮询主体必须走 CIBA 规范**:`POST /bc-authorize`(**必带用户标识:`login_hint`/`login_hint_token`/`id_token_hint` 三选一,标识给哪个用户推批准**;poll 模式一样要,否则 CIBA conformance 对不上)返回 `auth_req_id`,客户端轮询 **`POST /token`**（`grant_type=urn:openid:params:grant-type:ciba` + `auth_req_id`）,用标准错误码 `authorization_pending`/`slow_down`/`expired_token` 区分状态——**这条链完全不经过 §4 的 `/sessions`**,否则标准 CIBA 客户端与 OIDC conformance 对不上。**`binding_message` 的阶段口径(消除 DESIGN↔CONFORMANCE 冲突)**:**P2 起——请求侧可不带 `binding_message`(可选),但一旦带了,批准页 MUST 展示它**(C7b.6);发起方信息(AS 恒知)P2 起无论如何都展示。**P3 只补 ping/push 投递模式**(不改 binding_message 的展示义务)。
   `GET /sessions` 只是**面向 agent 平台/运维的可观测性旁路**(如 agent 想在开始轮询 `/token` 前先查有没有人已点同意),两者并存、职责不同,不互相替代。
   🔴 **`/bc-authorize` 必须节流(防"批准疲劳"轰炸,与 magic-link 发信滥用对称,P2 MUST)**:CIBA 会**向用户注册通道(邮件/IM webhook)推真实的登录批准请求**,故攻击者拿到某用户的 `login_hint`(邮箱等常见标识)即可反复调 `/bc-authorize` 对该用户狂推批准——这是 Uber/Cisco 那类 **MFA 推送轰炸/批准疲劳**同源攻击,后果**比单纯发信骚扰更重**(用户被高频打扰后可能误触"同意"→ 未授权委托)。要求:**per-`login_hint`(按被推送用户)冷却 + 全局推送配额**,与 §7 magic-link 的 per-email 冷却同一套机制;并**批准页去掉"一键同意"惯性**(展示 `binding_message`/发起方、加短延迟或二次确认,让轰炸下的误触更难)。poll 与 ping/push 模式一样适用。补 C7b 对应测试。
   ping/push 依赖客户端可被回调，推到 P3 视需求再加(P3 只加投递模式;`binding_message` 的"带了就必须展示"义务 P2 起已生效,见上)。
3. **Token exchange（RFC 8693）**：已有 Grant 的前提下，agent 用 workload 身份
   静默换取下游 audience 的委托 token，**无需每次都走浏览器**。参数需精确对齐 RFC 8693：
   - **`subject_token` = 代表的用户身份**，`subject_token_type` 取 `urn:ietf:params:oauth:token-type:access_token`（用户入站 access token）或 `id_token`；
     **grant 引用不是标准 subject_token**——如需以 `grant_id` 换发，须定义**自有 token type**（如 `urn:agent-auth:params:token-type:grant-ref`），
     且该引用**必须绑定发起 agent、短时、不可当 bearer 泛用**（防泄露即越权）。
   - 🔴 **subject 解析:从 `subject_token` 还原内部 `user_id`(pairwise 下的关键闭环,别漏)**:token-exchange 要为**另一个**下游 RS 签发委托 token,必须先拿到 **内部 `user_id`**——才能算出新 sector 的 pairwise `sub`(§2.8)、定位 Grant。⚠️ **pairwise 下入站 `subject_token` 里只有 `sub = HMAC(secret, user_id‖sector)`,HMAC 单向、算不回 `user_id`**,故**不能靠解 `sub` 还原**。写死解析路径:
     - **AS 不信任 `sub` 做反解**,而是**在每次签发 token 时落一条 `jti → {user_id, sector}` 映射**(与该 token 同/略长于其 TTL 的短命项),token-exchange 时**用入站 `subject_token` 的 `jti` 直查 `user_id`**;
     - **或**维护一张 **`(sub, sector) → user_id` 反查索引**(等价、但需按 sector 落多行)——二选一,推荐 `jti → user_id`(单一来源、随 token 天然过期、不额外泄露关联面)。
     - **public 形态无此问题**(`sub` 跨 RS 恒定、本身可作 user 键),但**SaaS 默认 pairwise 是 P0 锁死、token-exchange P2 落地**,故 P2 实现这条**必须在 pairwise 下走 `jti`/反查,不能假设 `sub` 可当 user 键**。此路径进 §8 access-pattern 清单 + C7.x conformance。
     - `id_token` 作 subject_token 时同理:`id_token` 的 `sub` 也是 pairwise(按 sector identifier),同样走 `jti`/反查拿 `user_id`,不解 `sub`。⚠️ **两条额外约束(否则此路径落不了/有歧义)**:
       - **① `id_token` MUST 带 `jti` 且有 `jti→{user_id, family_id?, grant_id?}` 映射**——ID token 默认不一定带 `jti`,但要作 subject_token 就必须带并落映射,否则无从还原 `user_id`(不能解 `sub`)。签发 ID token 时一并落映射;`grant_id` 记录**该 token 签发时所属的源 Grant**(单指针)。`sector` 不落映射(验签后从源 token 的 `aud` 拿)。
       - **② Grant 选择消歧 = `jti→grant_id` 单指针(实现收敛口径;access_token 与 id_token 同口径,不做类型二分)**:每枚 token 的 `jti` 映射记录**它签发时所属的唯一源 Grant**(`grant_id`),故换发时**确定性定位该 Grant**——active 就用它、不 active 就拒,**绝不回退到 user 名下的另一个 Grant**。因此常规路径**无多 Grant 歧义**(原"ID token 不指向任何 Grant"的问题已被 jti 单指针闭合)。**`grant-ref` 只用于真正的跨 Grant 换发**(用 Grant A 签的 subject_token 去换 Grant B 的 resource):此时 MUST 显式带 `grant-ref`(§5.2 自有 token type)指定目标 Grant;不带时**只能换源 Grant 的 resource,跨 Grant 请求 fail-closed 拒**(安全)。此规则补 C7.x conformance。
   - **`actor_token` = 发起的 agent（workload）身份**，`actor_token_type` 为 workload 认证换来的 token 类型；AS 据此填 `act.sub=agent`。
   - **委托授权 = 深度 + 身份两道闸(不能只限深度)**:`max_act_chain` 只限链长,**必须同时限"每一跳具体是谁"**,否则"任意 workload 只要拿到上级委托 token + 自己身份 + 深度未超限就能把自己插进链"是个说不清的攻击面。写死规则:
     - **准入判断在签发前、独立于 `may_act`**:每次 token-exchange,AS 用发起 actor 的**已认证 workload 身份**(§3.1,非客户端自称)对 **Grant 的 `actor_allowlist`**(client_id / SPIFFE 通配前缀集)做匹配,不在即拒——这是**签发前的准入闸,不写进 token**。allowlist 的多值/通配语义由这层承载。
     - ⚠️ **`may_act` 用不用、怎么用(RFC 8693 §4.4 结构约束)**:RFC 8693 的 `may_act` 是**单个对象**(如 `{"sub":"agt_A"}`),**无数组/通配语义**——**不能把多值 `actor_allowlist` 塞进 `may_act`**。本系统:**主准入用上面的 allowlist 判断**;`may_act` 仅在需要"token 自带下一跳唯一委托者"时**按 RFC 8693 原义填单个 actor**(如 subject_token 本就来自另一 AS、带了标准 `may_act`,则叠加校验)。**若要表达多候选 actor,那是 `actor_allowlist`(Grant 侧)的职责,不是 `may_act`(token 侧)**——两者不混,`may_act` 严格遵标准结构。
     - 逐级校验:每跳都验(深度未超限 ∧ 发起 actor ∈ 该 Grant 的 `actor_allowlist` ∧ 若上游 token 带标准 `may_act` 则命中之),任一不满足即拒。这样 sub-agent(第二级)的越权边界是"**Grant allowlist 显式授权的 actor**",而非"任何持 token 者"。
   - **换发时比对 Grant 白名单**：请求的 `resource`/`scope` 必须 ∈ **Grant 的 `per_resource[]` 白名单**(§5.1),不能静默扩权——委托 token 的权限恒 ⊆ 原 Grant。**超出白名单时的行为写死**:token-exchange 是静默/用户不在场路径,**默认直接拒**(返回 `invalid_scope`/`access_denied`);"补授权"**不在 token-exchange 内联发起**——需要扩权时由 agent 平台改走 §5.2 路径 2 的**异步 consent(CIBA/device)**重新征得用户同意、生成新 Grant,再回来换发。(即:token-exchange 只认已有 Grant,不自造授权。)
   - **`cnf` 传播(策略已定;机制随 P3 DPoP 落地)**:*是否继承*的决策(C7.9 要求"须明确")在此固化——**① 默认不继承**:委托 token 默认为 bearer(不带 `cnf`),因为 sender-constraint 的强制点在 RS、AS 侧签 `cnf` 需先做 DPoP proof 校验(读 `DPoP` 头 + RFC 7638 jkt 计算 + 校 htu/htm/iat/ath),这套 AS 侧签发机制属 P3(见 §8 P3 硬化、`P0 不做` 清单)。**② 不静默降级(不可谈判的安全不变量,现在即成立)**:若入站 `subject_token` 本身已 sender-constrained(带 `cnf`),下游委托 token **MUST** 也 sender-constrained 或**直接拒**,**MUST NOT** 悄悄签出丢 `cnf` 的 bearer(那会把整条委托链从 sender-constrained 降级为 bearer,破坏上游已建立的安全属性);"不带 cnf" 仅适用于入站本就非 sender-constrained 的情形。**③ 继承机制(P3)**:P3 上 DPoP 时,发起 agent 以其 DPoP key 证明持有,下游 `cnf.jkt` 绑定该 key;无有效 proof 时按策略拒或不带 `cnf`(绝不声称 sender-constrained 却不绑 key)。⚠️ P3 若要允许"入站 sender-constrained 但**有意**降级为 bearer 换发给不要求 sender-constraint 的下游 RS",MUST 走**每-RS 显式 opt-in**(不得默认放开 ② 的红线)——否则默认无条件拒的 fail-safe 被悄悄削弱。**当前状态**:P0–P2 无任何签发路径产出带 `cnf` 的 token,故 ①②③ 中唯 ② 需在 token-exchange 受理侧作为红线守住(入站带 cnf → 现阶段只能拒,不能降级),继承机制待 P3。

### 5.3 与 AgentCore 的互操作

本系统作为 AgentCore `CustomOauth2` provider 的对端时：

- 给 AgentCore 开 confidential client（它强制要 secret，坑 1.7）——但同一 AS 上
  mcp-remote/Claude Code 走 public+PKCE，**两种客户端共存无冲突**，因为
  discovery 如实宣告全集、且 token 端点按 client 记录的 `token_endpoint_auth_method` 逐一校验。
- AgentCore 的 UUID callback 用一条 `prefix` redirect 全覆盖，重建 provider 零运维。

---

## 6 · MCP 原生集成：资源服务器的零配置接入

MCP Authorization 规范要求的三件套，本系统一站式提供：

> ⚠️ **"零 facade、纯标准"承诺的已知星号**:通用 RFC 9068 校验器只认 `sub`/`act.sub`——**基本委托关系(谁代表谁)标准 delegation-aware RS 拿得到**;但本系统的**类型语义(命名空间 `.../c` 下的 `sub_type`/`auth_grant`/`actor_types`)是私有扩展,需本节 RS SDK 或 introspection 才能读到**(§2)。故"第三方 RS 零配置"指**连接/发现零配置**;要用到细粒度委托语义,RS 需接 SDK 或 introspect——这是一条顶层已知限制,别让读者对"纯标准即得全部语义"有落差。
> ⚠️ **零配置的第二条已知星号——(仅 P3 启用分流时)签名算法非固定**:**P0–P2 access 恒 ES256**,无此问题;**若 P3 启用 ES256/RS256 两池分流**(§8 可选优化),则同一逻辑 token 类型的 `alg` 会变。**规范实现的 RS(按 JWKS `kid` 派生 `alg`)无感**,但**硬编码单一 `alg` 的现成中间件会间歇 ~50% 拒签、极难排查**——这也是分流被降级为 P3 的理由之一。P3 启用时 **PRM/接入文档须显式声明"alg 非固定、RS 必须按 `kid` 派生 `alg`、勿硬编码"**;对做不到的第三方 RS 支持**按 client/RS 关闭分流、退化为固定 ES256**。

1. **PRM 托管**（RFC 9728）：资源服务器在控制面注册
   `https://mcp.example.com` → 我们生成 PRM 文档。
   ⚠️ **PRM 是按"受保护资源自身标识"派生的，不是 AS origin 下的单份文档**——
   **AS 的 issuer origin** 上不存在一份能代表任意 RS 的全局 PRM。故设计要求：
   **每个 RS 有自己的 PRM URL、`resource` 字段等于该 RS 的资源标识**，AS 按 RS 身份分别生成/托管、并做资源标识匹配校验。
   RFC 9728 URL 派生必须使用结构化 URL 处理:origin resource `https://mcp.example.com`
   对应 `https://mcp.example.com/.well-known/oauth-protected-resource`;带路径 resource
   `https://mcp.example.com/mcp/v1` 对应
   `https://mcp.example.com/.well-known/oauth-protected-resource/mcp/v1`(端口保留)。
   resource 标识不得带 userinfo/query/fragment;显式配置的 PRM URL 必须是可安全放入
   Bearer challenge 的绝对 HTTPS URL,校验通过后逐字使用。path/query 只接受 RFC 3986
   component 字符与合法 percent-escape,避免不同语言 URL parser 自动转义后产生不同 URL。
   resource 与显式 PRM URL 均拒绝 encoded authority 和会被 parser 重写的非 canonical
   host;resource 还拒绝 literal/percent-encoded dot-segment。
   两种投放方式：
   a) **（推荐）RS 自己挂** `/.well-known/oauth-protected-resource`（我们给 JSON，RS 静态托管即可，零运维耦合）；
   b) 由本系统的 CloudFront 以 RS 的自定义域名（CNAME）托管——**注意这不是"零代码"，而是把 RS 的数据路径与 TLS 责任交给我们**（**主要是【SaaS】形态的能力**；**【自部署】** 下 AS 与 RS 常同属一个组织,信任边界内,方式 a 足矣,方式 b 可不做):
      - **租户隔离【SaaS】**：按 `Host` 头映射到对应 RS 的 PRM，且 Host→租户绑定必须防伪造（校验该域名确经控制面登记归属该租户，拒绝未登记 Host），防止**跨租户**伪造 Host 头窃取他人 PRM；
      - **TLS 生命周期**：谁申领/续期该自定义域名的 ACM 证书、DNS 校验记录由谁维护、到期轮换责任划分，须写进 onboarding；
      - 若该 CNAME 同时代理 `/mcp` 数据面，则**全部 RS 流量过我们的 distribution**（可用性/延迟责任转移），需明确回源与 SLA。
2. **RS 校验 SDK**（TypeScript + Python 中间件）：
   - JWKS 缓存 + **遇未知 `kid` 立即重取 JWKS**（对用本 SDK 的 RS **降低**缓存旧 JWKS 拒掉新 key 签 token 的概率;⚠️ **但系统级优雅轮换仍 MUST 保留 publish-ahead ≥ JWKS `max-age`**,§8/C10.11b/DEPLOYMENT §2——不能因 SDK 有兜底就省掉 publish-ahead,因为第三方 RS 未必用本 SDK。**只有封闭部署、且能证明所有 RS 都做未知 kid 重取时,才可把跳过 publish-ahead 作为显式例外**）+ `aud` 强校验 + `sub_type` 策略（SDK 解出命名空间字段,per-user 路由声明 `require: sub_type=user`，
     M2M token 自动 403 并返回可读错误——把坑 1.6 的防线做成一行配置）；
     ⚠️ **未知 kid 重取要防放大攻击**:攻击者用随机 `kid` 的伪造 token 可诱导 RS 高频重取 JWKS、放大打 AS——重取须**限流 + 负缓存**(记住"这个 kid 查无、短期内不再重取")。
   - **按 `kid` 强制 `alg` 匹配**：ES256+RS256 双算法长期共存于同一 JWKS(§2/§8),token header 的 `alg` **必须与该 `kid` 对应公钥自身的算法类型一致,不一致即拒**——多算法 JWKS 比单算法多一个算法混淆攻击面,不能隐含依赖库的默认行为;当然 `alg: none` 一律拒;
   - **scope hierarchy 必须显式建模**:MCP operation 授权判断必须考虑"broader scope 可满足 narrower scope",但 SDK **不得**按冒号、前缀或命名习惯猜关系。默认只有精确相等;部署可声明 `broader -> narrower[]` 的传递关系或注入等价 resolver;循环声明启动即拒。TS/Python 分别使用 `scopeImplications`/`scope_implications`,语义必须一致。
   - **执行 `authorization_details`(RAR)——否则细粒度授权是空承诺**:token 里带 `authorization_details`(§2),RS SDK **必须把它暴露给 RS 策略并执行**("只能读 2026 年文档"要在 RS 真正拦下越界读,不能只在 consent 展示)。
     ⚠️ **P2/P3 分界靠"SDK 内建约束词汇表"钉死**(否则"简单 vs 复杂"含糊、易把该 P2 的推成 P3):RFC 9396 的 `type` 语义是部署自定义的,故 SDK **先定义一组标准化、可通用识别执行的声明式约束字段**——如 `valid_from`/`valid_to`(时间范围)、`resource_subset`(资源子集白名单)、`max_records` 等。**词汇表内的约束 = C8.5a 简单执行、P2 交付**;词汇表外/需策略引擎(Cedar)判定的 = C8.5b、P3。词汇表本身是 §6 SDK 的一份最小规范。
     走 introspection 的 RS 则从 introspection 响应拿 `authorization_details`(见下)。
     ⚠️ **JWT 体积预算(RAR + 多级 act 链会撑大 access token,MCP 走 header 传)**:命名空间 claim(固定小)+ `authorization_details` + 多跳 `act` 链叠起来可能把 access token 顶到 **HTTP header 体积上限**(常见 8 KB;各网关/RS 阈值不一)——过大的 JWT 每请求都付带宽/解析开销。规则:**复杂/大体量 RAR 约束优先靠 introspection 携带、不全塞进 JWT**——JWT 里只放**执行必需的最小 RAR 摘要**(词汇表内的声明式约束,见本节上文 SDK 约束词汇表),完整策略集走 introspection 取。**为 JWT 设一个软上限**(如 access token 目标 < 4 KB、硬拒 > 7 KB 的签发请求并要求收窄 RAR/走 introspection),`act` 链深度已受 `max_act_chain` 限(§5)顺带压体积。P0 单 resource + 无 RAR 无委托时 token 很小,此约束主要作用于 P2/P3(conformance C8.10)。
   - 401 时自动带标准 `WWW-Authenticate: Bearer resource_metadata="..."`，
     mcp-remote 零配置发现链路一次走通。**规范强度分开记**:缺/无效 token 的
     `401`、无效 token 的 `error="invalid_token"`、以及 `resource_metadata` 是本 SDK
     的 MUST;MCP 对首次 `401` 附当前 operation 完整 `scope` 是 SHOULD。权限不足时
     返回 `403`,并按 MCP SHOULD 在**同一个** Bearer challenge 中给
     `error="insufficient_scope"`、完整 required scope 集与 `resource_metadata`,供客户端
     step-up。scope-token 与 URL 在进 header 前必须拒绝控制字符、引号、反斜杠和非法空白，
     不回显 token 校验细节；
   - `act` 链深度/成员策略校验；
   - **DPoP RS 侧校验(P3,与 §2 `cnf.jkt` 配套)**：校验 `Authorization: DPoP`、proof 的 jkt 匹配 token 的 `cnf.jkt`、`htu`/`htm`、可选 nonce——**sender-constraint 的强制点在 RS,只在 AS 签发端做等于没做**,故 P3 上 DPoP 时 RS SDK 的 DPoP 校验是并列交付项。
3. **`resource` 参数强制**：client 请求时必须声明目标 RS，token 换发即 audience 绑定。
   - **RS 调 `/introspect` 的认证(RFC 7662 要求保护该端点)**：RS 在控制面注册时**顺带领一份 RS introspection 凭证**(登记为一类具备 introspect 权限的受限 client,可用 `client_secret` 或 endpoint-bound `private_key_jwt`),调 `/introspect` 时出示——不是匿名 token 探针。
     ⚠️ **必须按 `aud` 做跨 RS 隔离(否则 RS-A 的凭证能窥探 aud=RS-B 的 token)**:AS 校验**发起方 RS 身份 ∈ token 的 `aud`**,不匹配返回 `active: false`(标准做法,不泄露存在性)——这与 PRM Host 绑定、cookie host-only、逐租户 CMK 是同一类"防跨边界越界读"。
     **introspection 响应须回带命名空间 `.../c`(`sub_type`/`auth_grant`/`actor_types`)+ `act`(P1,C8.7a);`authorization_details`(P2、随 RAR 绑 Grant 才产生,C8.7a');`cnf`(DPoP,P3,C8.7b)**,否则走 introspection 的 RS 拿不到委托信息/RAR 约束/DPoP 绑定、与本 SDK(离线校验)的能力不对等。
     > **"零配置"的边界**:零配置指 RS **被连接**的发现 + DCR 链路(客户端侧);**introspection 是 RS 的可选升级路径**(离线 JWT 校验的 RS 根本不需要它),需领凭证、有一份密钥管理负担——不属于"零代码接入"承诺,读者别预期落差。
   - **scope 随 audience 下采样**：既然一个 token 只绑一个 `resource`(§1),签发的 `scope` 也**只保留该 resource 的子集**——**权威来源是"授权记录"的按-resource 结构**,不是靠命名规约猜。⚠️ 该结构的载体随阶段变:**P0/P1 = refresh-family 记录里按 resource 组织的 scopes**、**P2 起 = Grant 的 `per_resource[]`**(§5.1 过渡期说明)。命名空间/前缀(`kb:read` vs `mail:read`)是**辅助可读性**,注册时**拒绝不符规约、或不属于任一声明 resource 的 scope 名**;真正的 scope↔resource 归属以结构为准。

零配置端到端链路（全部标准，无任何 facade）：

```text
MCP client → RS 401 + WWW-Authenticate(PRM)
          → GET PRM → 发现 AS → GET AS metadata（如实宣告）
          → POST /register（DCR）→ /authorize (PKCE, resource=RS)
          → 用户认证+consent → code → /token → audience 受限 at+jwt
          → 带 token 连 RS /mcp → 校验 SDK 放行
```

### 6.1 · RS 命名空间用户属性 + aud-self-scoped 读取端点（RS 把自身授权语义托管给 AS）

**动机**：RS 常需判定"这个已认证用户在我这里是什么角色"（EK 的 `admin`、别的 RS 的 `editor`/`billing-admin`）。这类**授权语义是 RS 私有的、AS 不该懂**——但若让每个 RS 各自持一份白名单，授权数据散落、无法统一治理。故 AS 提供一层**通用、按 RS 命名空间隔离的用户属性**存储 + 读取通道：RS 把语义存进来，AS 只做隔离存储与下发、**绝不解释 value 含义**。

**为什么不进 token（与 §2 封闭 schema 一致）**：命名空间 claim 是封闭三键 schema（`sub_type`/`auth_grant`/`actor_types`，公理 1 + `validate_shape` 拒未知键）。属性是**每个 RS 各不同的私有数据**，塞进全局 access token 既违反公理、又撑大 token（§6 SDK 体积预算）。故属性**不进 access token**，经独立 HTTP 端点按需读取。

> **⚠️ 信任模型（AS admin 权力边界）**：AS admin 经 `PUT /admin/users/{id}/attributes?namespace=<uri>` 能写**任意 RS 命名空间**的属性——即 **AS admin 是超级权限，可间接获得任意 RS 的角色/权限**。RS 调 `GET /rs/attributes` 并据返回属性做授权判定 = **RS 信任 AS admin 不滥用写入权**。AS admin 本就是超级权限（能改密码、吊销 token、删用户），写属性只是其能力子集。故本能力面向**信任 AS 治理的首方 RS**（把授权语义统一托管到 AS）；**不信任 AS admin 的第三方 RS 不应使用本能力、应自持白名单**。这是设计假设、非缺陷。
>
> **⚠️ 范围**：本能力**仅 SelfHosted 形态的人类用户**，覆盖本地 email、SCIM canonical 与联邦 `user:fed:*` 身份；SaaS 恒 404，待属性隔离与 RBAC 合同另行接受后再开放。SelfHosted 默认 `public` subject type（`sub` 恒定），但读取端点**仍按 `jti` 稳健解析 user_id**（见下），以防 pairwise opt-in。

- **存储**：用户属性挂在**内部持久身份**上（用户目录记录，§7），形如 `attributes[<canonical_namespace>][key]=value`（value 为字符串，AS 不解释）。每个 key 另有不对 RS 暴露的 ownership/provenance；旧记录缺 owner 时按 admin-owned 兼容。默认 `<canonical_namespace>` = 已验签 token 的精确 `aud`；若 tenant admin 显式登记了 exact-audience 绑定，则多个逐字节精确的 audience URI 可解析到同一稳定 canonical namespace。canonical namespace 与每个 audience 都 MUST 为 RFC 8707 绝对 URI（无 fragment、UTF-8 最多 1024 bytes；非 URI、通配符、模板或模式语义拒绝）。持久身份**不挂 TTL**（C10.5）；**逐租户隔离**（tenant 分区，DEPLOYMENT §0）；为防属性无界膨胀拖垮身份读路径（设计意图，非 DynamoDB 400KB item 上限），**单用户全部 namespace 的 values + provenance 序列化后总大小 MUST ≤ 4096 字节**，超限 fail-closed 拒 **413**（不截断、不部分写）。
  - **删除级联（GDPR）**：`DELETE /admin/users/{id}` / 用户自主删号时,`attributes` MUST 随之清空（不留孤儿个人数据）。
- **精确 audience → canonical namespace 注册表**：
  - 注册表逐租户隔离、canonical 标识不可原地改名，变更经 revision CAS；同一 tenant 内一个 exact audience 最多绑定一个 canonical namespace，同 URI 在不同 tenant 互不影响。
  - 数据面只做一次 `(tenant, verified_aud)` 精确键查询；禁止 regex/glob/prefix/host-suffix/URI-template、运行时扫描或猜测。未曾受管的 audience 查无绑定时保持兼容：canonical namespace = 原始 `aud`。
  - audience 行是自包含的运行时权威，状态为 `Active`、`Blocked` 或 `Retired`。`Blocked` 与 store 故障均 fail-closed；曾经激活的 audience 删除/移除后持久保留 `Retired` 墓碑，禁止“查无行 → raw aud fallback”重新暴露旧数据。canonical URI 若未显式列入 exact audiences，也保留阻断行，不能因它恰好等于属性键而隐式成为 audience。
  - 变更最多包含 32 个 exact audiences；每个 canonical/audience URI 最多 1024 bytes，逐字节比较，大小写、尾斜杠、端口和 path 均敏感。实现可用 URI 字节 SHA-256 构造 Dynamo 键，但读取后 MUST 再比较原始 URI，不能只信摘要。
- **别名迁移（fail-closed、可恢复）**：
  - 创建/替换前先在一个 Dynamo 事务中把受影响 canonical、旧 audiences、新 audiences、移除 audiences 与 rebind target 全部置 `Blocked`，并持久化不可变请求、旧配置、operation id、phase、cursor、计数与 bounded conflict sample。阻断完成前不得改任何用户属性。
  - 迁移分为全量 `validate` 与 `migrate` 两遍，按用户分页、每页完成后才推进 cursor。不同 source/canonical 非空值为 conflict，绝不合并、覆盖或扩大权限；逐字节相同的重复值可原子去重；唯一 source 值可原子搬到 canonical；清空留下的空 KV revision tombstone 仍必须结构化迁移并保持 revision 单调。
  - 每个用户记录维护内部 `attributes_generation`。普通 namespace 写与迁移都 MUST CAS 并递增该 generation；迁移用一个条件写替换完整 attributes map，从而同时保护所有 source namespace，并修复不同 namespace 并发写绕过 4096 字节总量检查的问题。
  - 任一 conflict 阻止进入 `migrate`。两遍用户枚举均强一致。operation id 绑定含 expected registration revision 的完整不可变请求，并写永久只增 marker，取消/激活终态后及后续 operation 完成后仍不得复用。每个 migrate 页先成功读取用户页，再持久化不可逆 mutation intent；intent 前可取消并原子恢复旧 active 配置，intent 后禁止取消、只能按 operation id 幂等续跑至完成。每个计划处理的用户先持久化 `inflight_user_id`；`Migrated`、`Noop`、`NotFound` 或 `Tombstoned` 均把该 marker 收敛为一次 completed 进度并清除，故 `users_completed` 表示已收敛处理数而非物理写次数。激活只有在全量 scan 到终点、inflight 已清、全部用户处理收敛、conflict=0 且 operation/registration revision 仍匹配时才允许。
  - 激活事务发布新 `Active` 行并把移除项置 `Retired`。删除 registration 同样写 `Retired`，不物理删曾激活 audience。实现不加进程缓存；移除/重绑必须由强一致点查立即反映。
- **联邦 verified-claim → RS 属性映射**：
  - mapping 配置按 `(tenant, upstream_idp_id)` 隔离并经 revision CAS；只支持 `copy_string`（顶层 string claim 原样复制）与 `exact_membership`（顶层 string 精确相等或 string-array 精确成员命中后写固定 string）。不支持脚本、JSONPath、正则、模板、网络 lookup 或任意转换。
  - `mapping_id` 由服务端随机签发，在同一 tenant 内永久不得复用；每次 create/update/enable/disable/delete/target change 均推进单调 revision。删除保留永久高水位墓碑，re-enable 使用新 revision，故任何旧 provenance 都不能因 ABA 再次生效。
  - 每个 IdP 最多 32 mappings、最多 32 个 unique target namespaces，canonical registry snapshot 的 UTF-8 canonical JSON 最多 65536 bytes。目标只能是 #212 已登记且 `Active` 的 canonical namespace + 非空 key。同 tenant 的 `(canonical_namespace, key)` 同时最多归一个**启用** mapping；target ownership 用 tenant-scoped 精确索引条件认领，enable/create/target change 与 release/claim 在同一事务。配置拒重复 target、保留的身份/会话/assurance/platform-role/protocol 字段、空或超长 claim/key/value、未知 canonical namespace 与超界 mapping 数/总大小。
  - mapping authority 使用独立持久表的 registry、target-owner 与永久 mapping-marker 行；现有 FederationConfig connection/secret payload 保持不变。mapping mutation 与 IdP config mutation 在 Dynamo 中双向 condition-check 对方 exact snapshot 后同事务提交，Memory 共用同一 authority lock；IdP 仍有任何 mapping（含 disabled）时，删除 IdP 或改变 `upstream_issuer` 返回 409，避免并发产生指向已删除/换 issuer trust authority 的 live mapping。最后一条 mapping 删除后的空 registry 可在 first-create 时原子绑定到重建 IdP 的新 issuer并继续 revision；mapping CRUD 的事务响应不明确时仅在强读 exact registry、target owner/release 与永久 marker 全部命中目标状态后恢复成功。
  - federation-owned key 的 provenance 至少绑定 tenant、upstream IdP、mapping id、mapping revision、target namespace/key。admin-owned 与 federation-owned 值不得静默覆盖；普通 admin 全量替换若修改或删除 federation-owned key 返回 ownership conflict。v1 不提供隐式 takeover，未来显式 takeover 必须独立授权并审计。
  - `GET /rs/attributes` 只返回 provenance 仍精确命中**当前启用 mapping revision 与 target**的 federation-owned 值；mapping update、disable、delete 或 target 变化提交后，任何在该 commit 后开始 authority evaluation 的读取都立即看不到旧 revision，即使尚未物理清理。mapping authority 读取失败时整个请求 503，不得部分返回或把 managed value 当 admin-owned 回退。响应强制 `Cache-Control: no-store`；namespace revision 不是 federation-filtered 输出的 cache validator。
  - 普通 admin 不得替换 active 或 stale federation owner。为避免永不登录用户的 stale provenance 永久占用 4096-byte quota，管理面可通过 `DELETE /admin/users/{id}/attributes/federation-owner?namespace=&key=` + `If-Match` 显式、审计地 purge 一个**已失效** owner：只有同一事务强读证明 exact owner revision 已 disabled/deleted/mismatched 时才可删除；purge 请求无 body，不得同时把同 key 写成 admin-owned。active owner 永不允许 purge。
  - 联邦 callback 只能消费已通过既有 signature/alg/issuer/audience/nonce/exp/nbf/iat/flow 校验的 ID-token claims。用户稳定身份派生不变，email/mapped claim 不参与 linking。SelfHosted 创建或强读 Active `UserRecord` 后，必须在创建 session、发 code 或下游 redirect **之前**调用独立 `FederationAttributeReconciler`：其 Dynamo adapter 在一个 `TransactWriteItems` 中 condition-check immutable mapping snapshot、每个 relevant `Active` canonical namespace、用户 status/`attributes_generation`，条件更新完整 attributes + provenance，并写 flow-derived reconciliation operation marker。事务最多 35 项（1 mapping snapshot + 32 namespaces + 1 user + 1 marker），低于 Dynamo 100 项上限。
  - reconciliation operation id 由已消费 federation flow state 域分离派生，并同时作为 Dynamo client token/持久短命 marker。事务响应不明确时，强读 marker 与完整 installed provenance 调和；确认已提交不得重复推进 generation/revision。session 创建仍严格位于确认后的 reconciliation 之后；session 失败可要求重新登录，但下次相同 desired state 必须 no-op。
  - reconciliation 删除当前 IdP 已拥有但本次不再产生的 key，写入本次 desired keys，并保留其它 IdP 与 admin-owned keys。冲突、超 4096 字节、store/CAS/authority 故障均 fail-closed，零 session、零 code、零成功 redirect、零部分属性更新。
  - 缺 claim、错误类型或 `exact_membership` 不命中，只移除该 mapping 先前拥有的值；Disabled、Tombstoned、suppressed、跨 tenant/issuer 或其它被拒用户不发生 mapped-attribute mutation。配置 CRUD 与每次 reconciliation 记录结构化审计；flow operation reference 和 old/new value summary 使用 server-secret、域分离、长度分帧的 HMAC-SHA256 base64url，不记录原始 flow state、ID token、未选 claims 或属性明文。
  - SaaS mapping CRUD 在 extractor/auth/store 前返回 404；SaaS federation callback 完全跳过 mapping subsystem，保持既有 federation 行为，直到属性隔离与 RBAC 合同另行接受。
  - mapping authority 表纳入 PITR、AWS Backup、durable replication、standby import、tenant export/inventory 与 fenced tenant deletion。restore/failover 时，在 Users、AttributeNamespaces 与 mapping revisions 一致性检查完成前 mapping authority 保持 fail-closed。
- **写入（管理面，超级权限）**：`PUT /admin/users/{id}/attributes?namespace=<uri>` —— 整个 namespace **全量替换**。仅 admin token 可写；RS 自身**不能写**（RS 只读）。AS 对 value 语义无知。
  - **语义精确**：body=JSON object（值为字符串，非字符串拒 400）；body=`{}` 表示清空该 namespace，但保留递增 revision 的空 tombstone，防清空后 revision 回到 0 的 ABA；**零长度 HTTP body = 400**（区别于 `{}`）。整命名空间幂等替换。
  - **并发安全（乐观锁，防丢更新）**：属性写按 **per-namespace `revision`** 条件写（仿 Grant `put_conditional`）：`GET` 回带 `revision`（作 ETag），`PUT` 带 `If-Match`，`revision` 不符返回 **409/412**；**4KB 体积检查 MUST 在同一原子条件写内**（防不同 namespace 并发各基于旧总大小通过预检后共同超限）。
  - **用户状态生命周期**：`{id}` 不存在 → 404；`Tombstoned` 用户写 → **409**（存储层条件写堵并发复活）；`Disabled` 用户可否预配置由实现明确（默认允许 admin 预置）。
  - **ownership**：历史/显式 admin-owned key 可按现有 RMW 契约改写；请求若改变或移除 federation-owned key，MUST 返回 409 ownership conflict 且整个 namespace 零 mutation。管理面详情应标出 federation-managed key 与其 IdP/mapping id/revision 摘要，不回显 source claim value。
  - **审计**：每次属性写 MUST 记结构化审计（actor admin 指纹、tenant、user_id、namespace、旧/新摘要、结果、request-id）。
  - **namespace 解析**：admin 可提交 canonical URI 或 active exact audience；服务端 MUST 精确解析到 canonical 后再读写，不能把 UI 当安全边界。受影响 registration 处于 `Blocked` 时写返回 409；`Retired` audience 不回退 raw key。
  - **admin 控制台（`web/` SPA）**：user 管理页的用户详情里内建属性编辑区 —— 以 canonical namespace 分组，展示其 bound exact audiences；admin 在 canonical 下**增/改/删单个属性 key**。单 key 的增删改在前端做 **read-modify-write**（读出整 namespace → 本地改 → 整体 PUT 回），复用上面的全量替换端点，**不为单 key 增删改另加 PATCH 端点**（YAGNI）。另提供 tenant-admin namespace registration 列表/创建/替换/删除/迁移续跑面。
  - **admin 读属性**：`GET /admin/users/{id}` 的 `UserDetail` 响应 MUST 回带该用户全部 canonical namespace 属性、revision、bound exact audiences 与 registration state（管理面可见全部命名空间，与 RS 侧 `GET /rs/attributes` 的"只见自己 aud 所解析 canonical"不同——管理面是超级权限视图）。
- **读取（RS 侧，aud-self-scoped）**：新增 `GET /rs/attributes` —— 仅 SelfHosted 可用；用 `aud=<resource>` 的 access token 调，在现有验签、issuer、`jti` 与 active-user gate 全部通过后精确解析 canonical namespace，返回 `{sub, revision, attributes: <canonical namespace 下该用户的属性>}`。
  - 🔒 **命名空间键恒取自"已验签 token 的 `aud`"、绝不接受请求参数指定** —— RS-A 的 token 读不到 RS-B 的命名空间，隔离与 §1 的 audience 绑定同源、天然自洽。
  - 🔒 **user 主体经 `jti` 反查、绝不解 `sub`**：`sub` 在 pairwise 下 = `HMAC(secret, user_id‖sector)` **单向不可逆**（§2.8）、且随 sector 变，**不能当键查属性**。故本端点 MUST 取 token 的 `jti`、经 `JtiStore`（§5.2/C7.8，`jti→user_id`）反查内部 `user_id` 再读属性——与 token-exchange 同一机制。**映射缺失/过期/存储故障一律 fail-closed**（不回退用 `sub`）；因此所有可调本端点的用户 token 签发路径 MUST 可靠落 `jti` 映射（映射写失败应阻断签发，或改用持久 `(tenant,sub,sector)→user_id` 索引）。
  - 🔴 **入站 token 严格准入（闭合 C8.11 双向隔离）**：MUST 校验 header `typ==at+jwt` + `aud` 为**单元素数组**（拒裸字符串/多元素）+ `sub_type==user`（拒 2LO `agent`/`service`，它们无用户身份、无 `jti→user_id` 映射）+ `iss == 当前请求 Host 派生 issuer`（拒跨租户 token）。**显式拒 `aud==<issuer>/userinfo` 的 token**（userinfo token 不得当属性 namespace，与 `/userinfo` 互不搭便车）。
  - 🔴 **RS 读经 active-user gate**：解出 `user_id` 后 MUST 强一致读 `UserStatus`，`Disabled`/`Tombstoned`/不存在/状态故障一律 fail-closed（不返属性）。
  - 🔴 **federation provenance gate**：对 federation-owned key，必须以 tenant-scoped mapping authority 强一致校验 mapping 仍启用且 revision/IdP/target 完全匹配；不匹配立即隐藏，authority 故障不得回退为普通值。
  - 响应 MUST 带 `Cache-Control: no-store`；`revision` 只表示用户 namespace 持久 revision，不承诺在 mapping authority 改变时同步变化。
  - 🔴 **与 `/userinfo` 的 C2.11 不冲突**：`/userinfo` 保持纯 OIDC 语义（**当且仅当** `aud=<issuer>/userinfo` 可调，§2.8）；`GET /rs/attributes` 是**并列的 RS 侧读取面**，二者各自 aud 校验独立、互不搭便车。不改任何已冻结不变式。
  - 返回的 `sub` 与入参 access token 的 `sub` **逐字节一致**（不另派生，展示用）；查属性用 `jti` 解出的内部 `user_id`。
- **scope/consent**：命名空间隔离即足够，**不引入新 scope、不改 consent 页、不改 discovery**（协议表面最小）；用户对某 client 的 consent 已隐含它可读"为该 RS 写的、属于自己的"属性。若未来需要显式 scope，应作为独立的兼容性变更设计。
- **非目标**：不做隐式/模式化跨 RS 共享或全局属性（共享只能来自 tenant admin 显式 exact-audience 集合）；不改 token `aud`、签发、RS token 验证、PRM、introspection、Grant、refresh 或 `/userinfo`；不做属性变更事件/webhook（RS 每次即时读）；不做"RS 自助写自己命名空间"（需 RS 侧写鉴权模型，留后续增量）。

> 对应的可执行要求和证据见 CONFORMANCE C8.11/C8.12。

### 6.2 · Enterprise-Managed Authorization（Stable MCP opt-in profile）

Agent Auth 可作为 MCP Enterprise-Managed Authorization (EMA) 的 **Resource
Authorization Server**：企业 MCP client 先从企业 IdP 取得 Identity Assertion JWT
Authorization Grant (ID-JAG)，再向本 AS 提交 RFC 7523 JWT bearer grant，换取只面向
一个 MCP resource 的 access token。该 profile 是可选扩展，默认关闭；不是 core MCP
`2026-07-28` 的无条件能力，也不是本系统现有的普通 upstream login federation、workload
`client_assertion` 或 RFC 8693 delegation/token-exchange。外部规范固定为
[Stable EMA commit `fb374c7`](https://github.com/modelcontextprotocol/ext-auth/blob/fb374c7db2b34f18ca9183882e0beecdf661892b/specification/stable/enterprise-managed-authorization.mdx)。

**协议边界**：

- `/token` 请求使用
  `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`，ID-JAG 放在独立
  `assertion` 参数；`client_assertion` 仍只承载 MCP client 自身认证，二者不得复用。
- MCP client 必须是预注册 confidential client，并按其非 `none` 的
  `token_endpoint_auth_method` 独立认证；public client 不受理 EMA。v1 不依赖 CIMD；
  #41 的 CIMD confidential client 是可选后续 registration mode，不改变 ID-JAG 处理。
- 开启且完整依赖可用时，OIDC 与 OAuth 两份 AS metadata 同时宣告
  `authorization_grant_profiles_supported=["urn:ietf:params:oauth:grant-profile:id-jag"]`，
  且 `grant_types_supported` 增加 JWT bearer grant；关闭时 metadata 与现状逐字节兼容，
  `/token` 返回 `unsupported_grant_type`。“完整依赖可用”指 policy/replay/JWKS fetcher
  已配置、构造和启动校验通过，不要求 discovery 请求同步探测外部 IdP/JWKS 健康。

**tenant trust 与验证**：EMA 只接受 operator 配置的 tenant-scoped policy。每条 policy
固定精确 IdP issuer、可选的精确 `issuer_tenant`、HTTPS JWKS URI、允许算法（v1
`RS256`/`ES256`）、已认证 Agent Auth client id 到 ID-JAG `client_id` 的显式映射、MCP
resource 与 scope；断言中的 `iss`/`tenant`/`kid`/`jku` 或其它 claim 绝不能选择信任锚或
任意网络 endpoint。`issuer_tenant=None` 明确表示单租户 issuer，此时 assertion 不得带
`tenant`；配置了 `issuer_tenant` 即表示多租户 issuer，assertion 必须带完全相等的
`tenant`。client 映射和 policy lookup 均以
`(Agent Auth tenant, trusted issuer, issuer_tenant, authenticated client)` 为键。

验签必须使用 policy 固定的 JWKS，校 header `typ=oauth-id-jag+jwt`、算法 pin 与签名。
header 有 `kid` 时只能命中恰好一把同算法 signing key；无 `kid` 时仅当固定 JWKS 中恰好
一把同算法 signing key 才接受，多把或零把均拒绝。unknown `kid` 必须对同一固定 URI
强刷一次后再判失败。必需 claims 为
`iss/sub/aud/client_id/scope/exp/iat/jti`（`nbf`/`resource` if present）；`aud` 只接受
精确 issuer 字符串或仅含该 issuer 的单元素数组，`client_id` 必须匹配上述显式映射，时间
必须在 skew 内且 assertion 寿命有界。

请求必须显式带 canonical MCP `resource`。ID-JAG 的 `resource` 可为单 URI 或 URI 数组；
存在时必须含请求 resource 的逐字节精确值，其余值不进入最终 token。缺失仅在 policy
显式允许且该 client 恰有一个 registered target 时可补该唯一值。请求 scope 必须非空，
并同时是 ID-JAG scope 与
`(Agent Auth tenant, trusted issuer, issuer_tenant, client, resource)` policy scope 的
子集；不从 client default、AS default 或 scope 命名规约推导额外权限。该
`legacy_missing_resource` 是 Issue #43 要求的 Agent Auth 兼容扩展；严格 Stable EMA mode
和 live standards evidence 必须关闭它并要求 ID-JAG 明确携带 resource。

v1 不静默剥离授权语义：token request 直接携带 `authorization_details` 参数时返回
`invalid_authorization_details`；ID-JAG 内该 claim 存在时必须先按 RFC 9396 解析，
畸形则 `invalid_grant`，空数组等同未提供，well-formed 非空数组由 v1 local policy
明确判定为不授予并以 `invalid_grant` 拒绝。任意 `act` claim 直接拒绝；
`cnf.jkt` 存在时必须校验当前请求的 DPoP proof 且 thumbprint 完全相等，再把同一
`cnf.jkt` 写入 access token，缺 proof 或不匹配均 `invalid_grant`。无 `cnf` 时仍沿用
既有“有有效 DPoP proof 即绑定、无 proof 签 bearer”的 client/resource policy。
`sub_id`、`aud_sub`、email、`auth_time`、`acr`、`amr` 不用于 v1 subject resolution 或
权限提升；`aud_tenant` 存在时必须精确等于当前 Agent Auth tenant。

**replay 与身份**：`jti` 以
`(Agent Auth tenant, trusted issuer, issuer_tenant, jti)` domain-separated HMAC key
在现有 replay store 中原子消费至 assertion `exp + allowed_clock_skew`，覆盖 assertion 的
完整接受窗，并发请求至多一个成功。固定 JWKS URI 的读取沿用现有 SSRF 防线、单飞、限速、
负缓存、key 数与响应体上限。

企业用户稳定键由
`(Agent Auth tenant, trusted issuer, issuer_tenant, sub)` 派生；email 不参与认证或自动
linking，也不得把同 email 的本地/其它 federation 身份静默重连。v1 采用受控 JIT：仅在
校验成功后，先只读稳定键：已有 Active federated 记录可继续，Disabled/Tombstoned 或绑定
本地 email/其它 identity 的冲突记录在消费前拒绝；记录不存在只形成 JIT plan，不产生写入。
随后原子消费 replay；仅消费成功的请求才按 plan `create-or-get` 一个 email 为空的 Active
federated UserRecord，并在签发前强读复核 canonical record、Active 状态与 tenant issuer
guard。这样 replay 请求不会创建用户，消费后的 JIT/store/复核或 signer 故障则保持 assertion
已消费，client 必须取得新 ID-JAG。迁移/关联必须走未来显式流程；re-enable 后只能凭当时
仍在有效窗且未消费的 ID-JAG 或新 ID-JAG 再请求。

**签发与撤销边界**：成功只签既有 RFC 9068 `at+jwt`，单元素 `aud` 为 approved MCP
resource，`scope` 为交集结果，`client_id` 为已认证 client，`sub` 从稳定企业 user id 按
§2.8 当前 subject-mode/sector 派生；token response 同时回带获准的单个 `resource` 与
`scope`。既有 ES256/KMS、JWT size、DPoP、user lifecycle、tenant isolation 与 RS verifier
不变量全部保留。v1 不签 refresh token 或 ID token；
离线 ID-JAG 无法被 IdP 即时召回，最坏 ID-JAG 使用窗到其 `exp`，已签 access token 的
下游撤销延迟到其 `exp`（或 RS online introspection/其它既有吊销信号生效），产品文档
不得宣称“IdP 即时撤销”。

成功和错误响应均 `Cache-Control: no-store`。请求 resource 缺失、畸形、未知或未获 policy
批准使用 `invalid_target` + HTTP 400；token request RAR 使用
`invalid_authorization_details` + HTTP 400；ID-JAG 内 resource 缺失/冲突使用
`invalid_grant`。
`unsupported_grant_type`、`invalid_request`、`invalid_grant`、`invalid_scope` 为
HTTP 400；client authentication 失败为
`invalid_client` + HTTP 401，HTTP Basic 场景同时带 `WWW-Authenticate: Basic`；
ID-JAG `cnf` 绑定缺失/不匹配归 `invalid_grant`，无 `cnf` 时 client 主动提交的畸形 DPoP
proof 沿用 `invalid_dpop_proof` + HTTP 400。可重试依赖故障使用
`temporarily_unavailable` + HTTP 503 + `Retry-After`，不可恢复内部故障使用
`server_error` + HTTP 500。日志、trace、audit、metrics 与 OAuth error 不得包含 ID-JAG、
access token、email 或原始 claims。落地与验收由
spec `031-enterprise-managed-authorization.md` / C13 承接。

**实现与测试边界**：纯协议判定放在零 AWS 依赖的 `agent-auth-ema` crate；HTTP 层复用
现有固定 URI `JwksFetcher`、`ReplayStore`、`UsersStore`、tenant issuer guard 与 access
token signer。v1 policy 由 operator deployment config 提供，只支持预注册 client；CIMD
registration mode 在 #41 后独立接入。client authentication、签名/claim、policy、
resource/scope、DPoP 与 user lifecycle 等全部不消费校验成功后、签名前原子消费 replay；
任一无效 client/scope/resource/lifecycle 请求不得烧掉本可用的 ID-JAG。若消费后签名依赖
失败，client 必须向 IdP 取得新 ID-JAG，不能重用已消费 assertion。
测试 seam 固定为：两份 discovery 完整 JSON、`POST /token`、tenant trust/replay 边界和最终
access-token claims；真机另验固定 HTTPS JWKS、Dynamo replay、CloudFront Host→tenant、
KMS Sign 与外部 IdP acquisition。v1 不实现 EMA refresh/ID token、browser consent、企业
IdP token-exchange endpoint、assertion 驱动 trust discovery、email/cross-tenant linking。
live evidence 必须关闭 `legacy_missing_resource`，固定并记录 Agent Auth 完整 commit、
部署 issuer/tenant、执行 UTC 时间、仓库脚本 commit、真实 IdP 产品/版本、ID-JAG grant
profile 配置、client 版本、结果摘要与脱敏 wire transcript；仓库脚本从该外部 IdP 实际取得
ID-JAG，本地自签 fixture 不能替代。

---

## 7 · 用户认证层：Cognito 降级为可选上游

本系统是 **AS（授权服务器）**，用户认证（authn）设计为可插拔：

下表的优先级为**认证子路线图**，与 §10 的协议面 roadmap 相互独立（§10 已在 P0/P1 分别纳入 magic-link 登录与上游 IdP 联邦）。

| 认证方式 | 实现 | 优先级 |
|---|---|---|
| Email magic link / OTP | SES 发信 | **P0，先落地**（登录仪式最轻，撑起 P0 验收） |
| **Passkeys / WebAuthn** | 凭证存 DynamoDB，无密码 | P0.5/P1（前端注册+认证仪式非 2-3 周能做扎实，后移收窄 P0） |
| **上游 IdP 联邦**（OIDC / SAML） | 企业 Entra/Okta/**现有 Cognito pool** 作上游。**OIDC=AS 直接作 RP（已真机验证）；SAML=经 bridge**（见下） | P1（在 §10 P1 显式列为工作项） |
| 本地 email / 密码 | Admin 预置本地用户与临时密码；Argon2id 凭证独立存储；首登强制改密 | P1（受控置备，不开放终端用户自注册） |
| Admin 一次性用户邀请 | Admin show-once URL；独立 verifier-only store；接受后建 `amr=["invite"]` session并只进 `/account` | P1（受控置备，不复用 magic-link） |
| TOTP 二次因子 | | P2 |

> **SAML 上游 = SAML-to-OIDC bridge**:AS **不在进程内自实现 XML-dsig/C14N**。改由 **broker(Cognito User Pool)作 SAML SP 完成 XML 验签**,再以标准 OIDC 把身份桥接给本 AS(AS 作 OIDC RP,复用既有路径,零新 XML 代码)。拓扑:`企业 SAML IdP →(SAML)→ Cognito(SAML SP+OIDC OP)→(OIDC)→ 本 AS`。AS 内建 SAML SP 若未来确需,必须先解决 XSW/C14N golden vectors、算法与 transforms pinning、XXE 硬化、WebSSO bearer 断言校验、证书约束和重放防护。运维配置见 [`SAML-BRIDGE.md`](./SAML-BRIDGE.md)。
>
> **形态差异**:**【自部署】** 主线通常是**联邦到企业既有 IdP**(Entra/Okta/Cognito)——平台自带的无密码登录多为兜底,故上游联邦对自部署优先级更高。**【SaaS】** 每租户各配自己的上游 IdP(逐租户联邦配置隔离),平台托管的无密码登录是开箱默认;联邦配置属**逐租户**数据,绝不跨租户共享信任。
>
> **本地登录 UX 决策(受控密码 + invitation/passkey/magic-link 备选,不依赖 IdP)**:没有上游 IdP 的客户仍可完整使用 Agent Auth。Admin 先按 email 创建用户,并在临时密码与一次性邀请链接中严格二选一。临时密码用户首次登录必须先改密,改密成功前不得建立 AS 会话；邀请用户在独立浏览器接受后只进入 `/account` 自行配置凭据。登录页提供密码、passkey、magic-link 三种已配置因子,但任一种都只能登录**已由 Admin 预置的本地用户**;magic-link callback 不再 JIT 创建用户。直接登录进入 `/account` 后,未配置 passkey 的用户仍看到可跳过的注册动作;OAuth `/authorize → consent` 流程不得被改密以外的因子设置插页打断。
>
> **本地用户置备与密码安全边界**:
>
> - **默认关闭自注册**:本地 email 用户只能经 `/admin/users` 创建。对未知/禁用/墓碑用户请求 magic-link 返回与已登记用户相同的通用响应但不发信、不建 link;callback 只读查用户,绝不 upsert。联邦用户的 JIT 策略仍由联邦配置单独决定,不与本地自注册混淆。
> - **Magic-link identity binding**:link 发行时同时持久化当时由 email alias 解析出的 canonical `user_id`;兑现时 email 仍须映射到同一 canonical user。alias 已移动或被重分配时旧 link fail-closed,不得把发给旧 owner 的 link 兑现成新 owner 会话。
> - **凭证隔离**:密码哈希不进入 `UserRecord`、日志、OpenAPI 响应或审计内容;独立 tenant-scoped 持久凭证存储、无 TTL。只存 Argon2id PHC 字符串、`must_change`、单调 `version` 与更新时间;删除用户时级联删除。AWS 表、IAM、运行时容量等部署口径见 DEPLOYMENT §4。
> - **算法/策略**:Argon2id 参数基线 `m=19456 KiB,t=2,p=1`,每个密码独立随机 salt;密码 12–128 字节,不做会降低口令空间的静默 trim。只接受该算法/version 与受限参数 profile 的 PHC,避免恶意/损坏记录触发超预算计算;参数升级通过显式迁移版本完成。
> - **首登强制改密**:Admin create 写 `must_change=true`。正确初始密码只得到 `password_change_required`,不发 session cookie、不推进授权会话或产生任何认证工件;提交旧密码 + 合规新密码后以 credential `version` + `must_change=true` 条件写替换,并拒绝新旧密码相同。CAS 成功才建立 `amr=["pwd"]` 会话。临时密码未更改前不发送 magic-link,防止绕过首次改密。
> - **独立 invitation credential**:`POST /admin/users` 在 `initial_password` 与 `issue_invitation=true` 中严格二选一。邀请模式不建 PasswordCredential,使用独立 tenant-scoped InvitationStore/DynamoDB 表和端点,不复用 magic-link store、nonce、cooldown、quota 或 notifier。CSPRNG bearer 只在 `/invite#token=...` show-once URL 返回,持久层只存 verifier；每用户一条 active row,重新签发原子覆盖旧 verifier。接受事务同时校验未过期、Active local user、email/credential epoch、无 password,消费邀请并创建 host-only `amr=["invite"]` session；DynamoDB 事务使用幂等 request token,响应不明确时仅以强读精确 record/session 调和成功；固定跳转 `/account`,不接受 caller-controlled continuation。`invite` 不自动提升 assurance。
> - **运营观测时间**:`UserRecord.last_login_at` 记录 AS 最后一次成功建立该用户认证会话的 Unix 秒,覆盖 password、magic-link、invitation、passkey、联邦和恢复登录;失败认证、仅复用已有 session、临时密码 change-required 均不推进。`ClientRecord.last_used_day` 记录 AS 最后一次观测到 token 签发活动的 UTC 天级桶;它是用于运营与回收保护的保守信号,不是每次 KMS Sign 的完备账本。为保证密码 reset 竞态下最终 authority 复核是签发路径最后一个 await,极窄的“已签名但随后被复核抑制并吊销”可能已计入 client 活动。Admin API/UI 分别展示“最后登录”和“最后签发 Token”,空值明确为从未登录/从未使用。两者都只是 **AS 可观察边界**;client 值不保证 token 已交付,两者均不代表 access token 在下游 RS 的真实调用时间。需要下游使用时间必须由 RS 访问日志/遥测提供。观测写采用单调条件更新、失败可告警但不得反向让已成功认证/签发失败。
> - **防枚举/爆破/算力耗尽**:未知用户、未配置密码、密码错误、Disabled/Tombstoned 统一 `401 invalid credentials`,并对未知用户执行同参数 dummy Argon2id 校验。`/login/password` 与 `/login/password/change` 共用 tenant-scoped per-account + 可信源 IP + tenant/global 工作量桶。四级桶均在用户查找前检查；IP/tenant/global 工作量桶对每次尝试扣减，per-account 桶只在统一的 invalid-credentials 结果后扣减，成功认证、临时密码 change-required 与后续业务失败不得消耗账户失败预算。账户桶已超额时仍须在 Argon2 前拒绝，随机 email 洪水则由 IP/tenant/global 桶约束。限流存储缺失/故障时 fail-closed `503`,超额统一 `429`。Argon2 在 `spawn_blocking` 中运行并受进程内有界 semaphore 保护,队列满直接拒绝,不占满异步 runtime/Lambda 内存。
> - **Admin 生命周期**:`POST /admin/users` 同时接收且只接收一种 bootstrap:临时密码或 invitation。临时密码模式先按 email alias 解析稳定 canonical `user_id`(未命中才派生 legacy `user:{email}`),再以 `must_change=true`/`revocation_pending=true` 条件创建 fail-closed credential 与创建/读取 user,避免 user 已可登录而 credential 瞬断时绕过首次改密;只有 alias/canonical user 强读复核与旧 session 清理完成后才按 version CAS 清 pending。user 写失败或响应丢失后,同一临时密码可幂等续完,不同密码返回 409；credential 写入、条件删除或完成 CAS 的不明确结果必须用强读调和。若并发 SCIM alias move 使 email 不再归属该 user,按 credential version 条件删除本次 pending 凭据，且不得删除并发 reset/change 的新版本；清理持续不可用时 pending 本身保证该凭据即使 alias 回迁也不可登录或改密。创建后复核 Tombstoned 并清 credential,闭合 create/delete 竞态。`POST /admin/users/{id}/reset-password` 仅用于具合法 email alias 的非联邦 canonical user(legacy 本地 id 或 SCIM 随机 id):原子写入新的临时 Argon2id credential、置 `must_change=true`/`revocation_pending=true` 并递增版本,随后吊销既存 session、refresh family 与 grace cache并失效 pending invitation;全部完成后才按版本 CAS 清 pending,pending 期间改密 fail-closed,同一临时密码可重试续完吊销。authorization code、device/CIBA 批准记录及其 refresh family 为所有 password-capable canonical user 绑定批准时的 credential version,兑换/轮换/token-exchange 前后复核,所以 reset 前尚未兑换的授权工件在 reset 后完成改密也不能复活;并发变化时吊销刚创建的 Grant/family 且不返回 token。password-capable 用户历史工件若缺失 version 一律 fail-closed,不把 `None` 当通配符;联邦/机器主体不受密码版本绑定。Disabled 用户可预置但仍不能登录,Tombstoned/联邦用户拒绝。写后强读用户并在并发 delete 已获胜时清 credential,不允许墓碑残留密码。任何 API 只回密码状态摘要,永不回哈希或明文;已登录用户自助 change-after-login 留后续能力。
> - **Admin 列表可见性**:`GET /admin/users` 默认只返回 Active + Disabled,墓碑必须通过显式 `status=tombstoned|all` 查看。`status` 还支持 `non_deleted|active|disabled`;非法值在通过 Admin 可用性与认证门后返回 400。tenant、email/user_id 搜索与 lifecycle status 在分页完成和 cursor 判定前共同应用；Dynamo 必须跨被过滤物理页继续扫描，并只在确认后续仍有组合条件匹配记录时发 cursor，避免短页、遗漏、重复或确定为空的尾页。治理导出、namespace migration 等内部流程若需墓碑必须显式选择 all-status，不能继承 Admin 默认。
>
> ⚠️ **【SaaS】WebAuthn `rp_id` 的租户作用域(与 §8 cookie 隔离同一类威胁)**:子域租户模型下,`rp_id=saas.example.com` 会让 passkey **跨所有租户子域可用(越界)**;必须用 **`rp_id=t1.saas.example.com` 逐租户隔离**(代价:同一用户在多租户需各自注册 passkey)。BYOD 自带域名会进一步放大此问题,须一并定 `rp_id` 策略。这与已处理的 cookie `Domain` 隔离(§8)对称,不可只做一半。

**本地无密码方案的恢复边界与剩余事项**：

- **账户恢复(P0.5 硬门槛,已落一次性恢复码)**:passkey/magic-link 用户丢设备/邮箱 = **头号账户接管入口**。恢复码 show-once 下发、持久层只存 HMAC；验码受 per-user 锁定限制，成功恢复通知既有联系邮箱、推进 credential epoch/login-session generation、吊销旧认证工件并引导绑定新因子。消费、authority 推进、recovered session 与 60 秒 operation success-result 在同一事务提交。客户端为一次恢复生成 canonical 32-byte base64url `operation_id`；服务端只持久化 tenant-bound HMAC key，并把结果绑定到 code HMAC、lookup、user、epoch 与 session。成功响应丢失后仅同 operation+同码可找回仍权威的原 session；不同 operation/tenant/lookup/code、过期结果、session/authority/region ownership 变化均 fail closed，且重放不得延长 session。**一旦引入任何真实身份(含内测),该恢复流必须先到位**；联邦兜底仍可作为租户附加恢复因子。
- **登出 / 会话终止(P1 交付,与上游联邦同期,见 §10 路线图 + C9.6)**:目前无 RP-initiated logout、前/后通道登出。对 agent 场景次要,但一旦引入 Cognito/Entra 联邦(P1)就必须有——故已列入 P1 交付物(不再是"待补"游离项):最小落 **RP-initiated logout(清 AS 会话 cookie + 可选联动上游 IdP 登出)**;前/后通道登出留 post-P1 视需求。
- ⚠️ **magic-link 发信滥用(P0 就有的攻击面)**:攻击者对任意邮箱狂触发登录邮件 → 邮箱轰炸 + SES 信誉受损。P0 必须有 **per-email 冷却 + 全局发信配额**。另:**新 AWS 账号 SES 默认在 sandbox(只能发已验证地址),production access 审批要计入 P0 工期**。

**迁移路径**：现有 Cognito user pool 直接配置成上游 OIDC IdP——
用户无感、存量身份保留，而所有 OAuth/OIDC/MCP 协议面换成本系统。
等迁移完成，Cognito 可整体退役。

---

## 8 · AWS 架构：全 serverless、单域名、无状态

> **形态映射**:下图是**单部署栈**的拓扑,两形态复用同一套组件,区别在**实例化方式**——
> **【自部署】** 一个客户 = 一个此栈,跑在客户账号里,单 issuer、**单租户 key set**(不是"一把 key"——见下)、租户数=1；
> **【SaaS】** 我们运营 fleet,**按租户分区**:DynamoDB 按租户分区键隔离、**逐租户 KMS 签名 key set**、按 `Host` 路由到租户 issuer、配额/限流分级。多租户隔离是"可关闭的一等能力"(见 §0.5),自部署即其单租户特例。
>
> ⚠️ **"key set" 不是一把 key(CDK/runbook 别按单 key 写)**——一个 issuer(自部署=整栈;SaaS=每租户)的 key set 随签名模式而定:
>
> - **KMS-Sign 模式(SaaS 必用、自部署默认)**:**EC(ES256)+ RSA(RS256)两把非对称 signing CMK**——**两把从 P0 起都必需**:EC 签 access(P0–P2 恒 ES256)、**RSA 签默认 RS256 ID token(OIDC 动态注册未声明 alg 时的默认,§2,P0 必需)**。⚠️ **RSA CMK 的存在理由是 ID token,不是算法分流**(access 分流到 RSA 是 P3 可选,§8);别因"P0–P2 不分流"就误删 RSA CMK——那会签不了默认 RS256 ID token、破 OIDC 互操作。**稳态 2 把**;轮换重叠期每类临时双活(新旧并存),**峰值 ≤4 把**。JWKS 发布这些 CMK 的公钥。
> - **本地签名模式(仅【自部署】可选,§8)**:不用非对称 signing CMK,改用 **1 把独立的 symmetric wrapping CMK**(包裹 data key pair 的私钥密文,**不能从签名 CMK 派生**,§8)+ 持久化的 **data key pair(EC/RSA 各一,视是否仍要双算法)**。JWKS 发布 data key pair 的公钥。
> - 两模式的 JWKS/轮换/验收语义不同,**各写各的**(§8);"单 KMS key" 是错误简化。

```text
                        ┌─ Route53 + ACM ─┐
   https://<issuer>  (真实 AS issuer:issuer == 其 AS 端点、单 origin)
   ├─【自部署】客户配置域(auth.customer.example)          ← 是 issuer,承载全部 AS 端点
   └─【SaaS 租户】t{N}.saas.example.com(按 Host 路由,见 DEPLOYMENT §0)  ← 是 issuer
   —— 另:【SaaS 控制面】c.saas.example.com  ← **不是 issuer、不暴露 AS 端点**(只有控制面 API,见 §1/DEPLOYMENT §0),故不在上面 "issuer == endpoints" 之列
                        │
                   CloudFront  ←— WAF（IP/Host/ASN 粗兜底 + bot control；**按 client_id 限流在应用层**,WAF 抓不到 body,见 §3.2）
                   /    |     \
     consent SPA(静态托管|      PRM 托管（可选，按 RS 身份；【SaaS】多 CNAME，见 §6）
     +动态 API 驱动)     |
        (S3 + OAC)      |
                 API Gateway (HTTP API)
                        |
                 Lambda (单体 hexagonal handler，Rust 优先/Node22/TS 备选,P-1 spike 拍板见 §10)
                 ├── DynamoDB 单表（clients / sessions / codes / refresh_tokens
                 │        / grants / device_codes / users / passkeys / dpop_jti）
                 │        ⚠️ TTL 只作 GC(异步、非有效期,读写路径必校 expires_at,见 §2.1);加在
                 │        **短命记录**（sessions / codes / device_codes / dpop_jti / 宽限缓存 /
                 │        recovery operation success-result，
                 │        及 refresh-token 家族的显式到期）；users / passkeys / clients / grants
                 │        是**持久身份/授权记录，绝不能挂裸 TTL**（否则身份静默消失、留悬空引用），
                 │        其生命周期由显式吊销/回收流程管理(§3.2 client 回收=扫 last_used_at +
                 │        确认无 refresh family/code/session/Grant 后转 tombstone、延后硬删;
                 │        仅"从未激活、无任何关联"注册残渣可挂 TTL)；
                 │        code 单次使用靠条件删除保证原子性
                 ├── KMS 非对称密钥（ES256 主 + RS256 并存(§2 conformance)；各含轮换双活 key。
                 │        私钥不可导出，Sign API 签 JWT；【SaaS】每租户独立 key set(EC+RSA 两把)为基线，见 KMS 选型与 DEPLOYMENT §1）
                 ├── SES（magic link / consent 通知）
                 ├── Amazon Verified Permissions（Cedar）——scope/RAR/委托链策略判定
                 ├── EventBridge（授权会话状态投影）
                 └── tenant-scoped security-event 热账本（DynamoDB）
                          → DynamoDB Stream → S3 七年归档 → Athena（合规查询）
                          → CloudWatch（认证、基础设施、跨租户、积压与死信告警）
```

关键选型理由：

- **Lambda 而非 Fargate**：token 端点突发性强、天然无状态；P99 用 provisioned concurrency 兜底。
  ⚠️ **KMS 非对称 Sign 延迟别按 ~2-5ms 规划**——ES256 的 Sign（网络往返 + HSM 运算）**官方无权威基准,第三方实测跨度很大(常见几十 ms、个例 P99 到数百 ms),必须自行压测后再定**,别用一个乐观定值做 P99/provisioned-concurrency 成本规划;
  且是**每次调用计费、受 KMS RPS 配额限流**。而 token 端点的突发性（正是选 Lambda 的理由）恰恰会撞上 KMS 限流。
  ⚠️ **KMS 被 throttle 时 `/token` 的背压必须闭环(P0 运维正确性,非 P3)**:签发热路径前放**并发闸/请求节流**(令牌桶,与 §3.2 应用层限流同一套);KMS throttle 时 `/token` 返回 **`503` + `Retry-After`**(而非 500),两阶段 lease 释放、不消费 code;客户端按 `Retry-After` **带 jitter 退避**。**防"限流→重试→更严限流"正反馈**:节流闸放在 KMS 调用之前(先挡住多余并发,而不是都打到 KMS 再被拒),并对 `/token` 全局并发设上限 ≈ 该区 Sign 配额。
  ⚠️ **签名 RPS 配额的关键事实**:KMS 的密码学操作配额是**按账号+区域+密钥类型共享的一个池**(非 per-key),**同区域多开几把 CMK 并不提升签名吞吐**(它们抢同一个池)。配额是**可提额的软限**、且**可能随区域/时间变化**,**部署前按目标 region 用 Service Quotas 实查、别硬编码任何数字**(尤其自部署形态客户 region 不可控)。正确分摊维度:
  - **跨区域 / 跨账号**(每区各有独立配额——P3 多区域顺带缓解签名瓶颈);
  - **混用 key spec 做 access token 分流(P3 可选优化,不是 P0–P2 容量机制)**:RSA(RS256)与 ECC(ES256)各有**独立配额池**,故把**部分 access token 签发导流到 RS256**可把有效签名上限 ≈ 抬到**两池配额之和**。⚠️ **但此机制降级为 P3**:它引入多 alg JWKS 算法混淆面 + 第三方 RS 间歇拒签 + 峰值水位失衡风险,而 **P0–P2 的容量靠确定性的 TTL + 分片已足**(§2.1)。**仅当 P3 实测确需再抬单区上限时才启用**;启用后须覆盖主导负载(稳态 refresh 重签)否则杠杆落空。下述规则是 P3 启用时的设计:
    - **分流决策规则**:**仅对 access token 生效**(ID token 恒按 per-client `id_token_signed_response_alg` 签、不参与分流,§2)。签发某个 access token 时选算法的判据,**按当前池水位动态分配**——各池维护近窗口内的用量估计,新签发路由到**剩余配额占比更高的池**(加权随机或水位反馈,避免抖动);无压力时默认 ES256(体积/速度更优)。目标是**两池水位均衡**,把 `Sign` 吞吐上限从"单池 Q"抬到"ECC_Q + RSA_Q"。**不按 client、不按固定百分比写死**——固定比例在负载偏斜时仍会先打满一池;水位反馈才对突发稳健。
    - ⚠️ **水位估计必须是异步/本地缓存,绝不进签发热路径做同步跨实例查询**(与 AVP/Cedar 移出热路径、KMS 背压同一原则):池水位由**后台异步拉取**(CloudWatch Sign 指标 / 各实例本地计数周期上报聚合)刷新到**进程内短 TTL 本地缓存**,签发时**只读本地缓存的权重、零额外网络往返**。**决不能每次签名前同步查 DynamoDB 计数器/远程水位**——那会新造一个比 KMS 本身更早的热路径协调瓶颈。本地缓存过期/冷启动未预热时,**回退到默认 ES256**(安全兜底,最坏是分流不最优、不会阻塞签发)。分流是"尽力均衡"的软优化,不是每 token 的强一致决策。
    - RS 侧**若严格按规范实现**(RFC 9068:用 `kid` 从 JWKS 取公钥、按公钥自身 `alg` 验签)则对分流无感。⚠️ **但这与"第三方 RS 零配置"有真实张力,不能只说"无感"**:现实里不少现成中间件**默认写死单一 `alg`**(配置里钉 ES256),对这类 RS,同一逻辑 token 时而 ES256 时而 RS256 会造成**间歇性 ~50% 拒绝、且极难排查**。本系统的 RS SDK(C8.3 按 `kid` 强制匹配公钥 `alg`)没问题,但"零配置"针对的恰恰是**不接 SDK 的第三方 RS**。故:**PRM/接入文档必须显式声明"本 AS 的 access token 签名算法非固定(ES256/RS256 混发)、RS 必须按 JWKS 的 `kid` 派生 `alg`、不得硬编码单一算法"**;对无法保证这点的 RS,可按 client/RS 关闭分流(退化为固定 ES256)以换取兼容(牺牲该部分的两池容量)。见 §6 零配置边界说明。
  - AS **不调 Verify**(RS 用 JWKS 公钥本地验签,不打 KMS),故单密钥类型的配额 **≈ 单区域该算法的签发天花板**。**P0–P2:access 恒 ES256 只吃 ECC 池;ID token 按 per-client alg 落池(默认 RS256→RSA,少数注册 ES256 的客户端→ECC)**——容量按"ECC 池 = access(含稳态 refresh 主导量)+ 少量 ES256 ID"天花板规划;P3 若启用分流,才把 access 摊到两池。
  应对：签名结果不可缓存（每 token 唯一），**靠提额 + 跨区域/账号分摊,不靠同区多 key**;
  P99 与 provisioned concurrency 成本须**按实测 KMS 延迟**重估，而非先假设再设计。
  ⚠️ **语言选型(Rust vs Node22/TS)是 P0 开工 gate,须先定**——它决定冷启动策略(**Rust 二进制冷启动 ~5-15ms 基本免 provisioned concurrency;Node 冷启动几百 ms、要靠 PC 兜 P99**)。
  **倾向 Rust**:本系统画像(token 端点突发、冷启动敏感、有 JWT 签名/DER↔JOSE/信封加密等 CPU 活、安全关键、且要逐条掌控 conformance 而非依赖黑盒库默认)偏向 Rust——**免 PC 省成本、无 GC 抖动、类型系统防内存/并发 bug**。Lambda 官方支持 Rust(`provided.al2023` custom runtime + `aws-lambda-rust-runtime`/`cargo-lambda`;`aws-sdk-rust` 已 GA,KMS/DynamoDB/SES 全覆盖)。
  **代价**:OAuth/OIDC 的 Rust 库不如 Node 生态成熟(要自己拼 `jsonwebtoken`/`axum`/`lambda_http`,但对逐条 conformance 反而是"完全掌控"的优点);上手慢于 TS。
  **判据 + 验证**:目标"无 PC 也满足 P99 ≤ X ms(X 由 SLA 定,如 300ms)"→ Rust;团队 TS 熟练度优先、接受 PC 成本 → Node。**开工前先做一条薄纵切(`auth_code`+PKCE → KMS ES256 Sign → DER↔JOSE → discovery)用 Rust 实测冷启动 + KMS 延迟**,一次性拍板语言 + 量出容量模型缺的那个"实测 Q"(§2.1,别让架构判断悬在未测数据上)。
  ⚠️ **KMS ECDSA 签名是 DER 编码,JOSE ES256 要求裸 `r‖s`**——签名适配层必须做 **DER ↔ JOSE 格式转换**,且 JWT conformance 测试要覆盖它(易踩的实现陷阱)。
- **DynamoDB 单表 + TTL**：见上方架构图对 TTL 适用范围的约束（只限短命记录）；
  authorization code 的"单次使用"用带 lease-owner fencing 的条件 `UpdateItem` 原子实现。
  ⚠️ **code/refresh 兑换是两阶段 lease,不是"先签名再消费"一句能了(否则并发窗口漏签、或限流放大成重走浏览器)**:
  1. **原子条件更新为 `signing` lease 态**(短 TTL + 高熵 owner fencing token)——先抢占,`ConditionExpression` 保证同一 code/refresh 的并发请求**只有一个进入签名**(其余立即拿到"处理中/已用"而**不触发 KMS Sign**,避免并发放大配额);lease 到期重占会替换 owner，旧请求的 finalize/release 必须因 owner 不匹配而失败，不能覆盖或清除新请求的 lease;
  2. **KMS Sign**;
  3. **事务性 finalize**(标记 code 已消费 / 轮换 refresh family + 写宽限缓存),失败则**不返回任何 token**。
  - **三种失败,三种归属(别混,尤其第三种易误判为"已消费")**:
    - ① **签名前/签名中的瞬时 KMS 失败**(限流/`server_error`):**释放 lease、code/refresh 未消费、可安全重试**(本节上文 KMS throttle 背压的 503+Retry-After 走这条);
    - ② **已认证客户端的授权语义失败**(redirect URI/PKCE/资源参数错、账户或策略拒):
      落 §4 的 `exchange_failed`,**code 已消费、须重走授权**。客户端身份未认证、未知/
      已回收 client 或认证凭证错误属于认证前失败：释放 lease、**不消费 code**，防止
      未认证攻击者用截获的 code 拒绝服务。code 绑定授权会话时，finalize code 与会话迁
      `exchange_failed`（写 `last_error`、`sequence++`）MUST 在同一 DynamoDB
      `TransactWriteItems` 中提交，并同时条件校验 lease owner、code 未消费、session binding、
      会话当前态与 sequence；事务失败两条记录均不变化，返回可重试错误；
    - ③ **Sign 成功但 step-3 finalize 失败**(DynamoDB 事务冲突/限流):此时 **code 尚未标记消费,lease 停在 `signing` 态**——并发/重试请求会拿到"处理中"直到 **lease TTL 到期**才能重来。**这是可接受路径,但须写明:finalize 失败 = lease 到期后可重试、且 `不算 exchange_failed`**(语义上未拒绝,只是持久化未完成)。实现者**别把它误当"已消费"**而拒绝合法重试;client 侧表现为短暂 `503`/超时后按 `Retry-After` 重试成功。已签发但未 finalize 的那次 Sign 作废(token 未返回给 client),重试会重签——计入签名配额损耗,属可接受。
  ⚠️ **多区域不能简单靠 Global Tables**：Global Tables 是**最终一致、last-writer-wins**，
  而 code 单次使用、DPoP jti 重放检测、refresh 复用标记都依赖**强一致条件写**——
  在 A 区消费的 code/jti 可能在复制完成前于 B 区被**重放**。故这些**重放敏感项必须单区域属主**：
  在边缘（CloudFront/Lambda@Edge）做**区域亲和路由**，同一授权流的签发与兑换锁定同一区域；
  这不是"Global Tables + 粘性会话"一句话能覆盖的，故障切换瞬间的边界见 §11 开放问题。
  ⚠️ **"单表"与多区域有张力,多区域时倾向拆表**:一张 Global Tables 表**整表最终一致复制**,无法让身份项全局复制、重放项单区属主。区域亲和路由能让它逻辑成立(重放项从不跨区操作,复制了也不冲突),但把正确性押在路由永不出错 + 故障切换真空(§11 #9)。更干净:**拆两类表——身份表(users/passkeys/clients/grants)用 Global Tables 全局复制;短命/重放表(code/jti/refresh 标记)按区域独立、不跨区复制**。P0 单区不受影响,多区域(P3)前定。(注:**"跨账号"来自本节 noisy-neighbor 那条——为绕签名配额硬顶,fleet 可能把大租户分片到独立 AWS 账号**;届时 DynamoDB 新的 multi-region strong consistency **不支持跨账号**、对这种分片无解,故区域亲和路由仍必要。若 fleet 始终单账号,此注不适用。)
  ⚠️ **access pattern + GSI 表是 P0 必交成果物**(主打"单表"就得先把查询模式列全)。至少覆盖:
    - **user by email**(magic-link 登录定位 user——P0 就需要,易漏);
    - `GET /sessions?client_id=me`(按 client_id)、`GET /grants`(按 user_id)、refresh family 查找(按 family_id)、client 回收扫描(按 last_used_at);
    - **token-exchange 的 subject 解析(pairwise 必需,§5.2)**:**`jti → {user_id, sector}` 映射**(签发时落、随 token TTL 过期),token-exchange 用入站 `subject_token` 的 `jti` 反查 `user_id`——**pairwise 下 `sub` 单向不可逆,这条不做则委托链在 SaaS 默认档断裂**(P2,但访问模式 P0 就该列进单表设计,免得 P2 回头改表);
    - **introspect/revoke 时按 token/family 定位**、**`/register/{id}` 按 `registration_access_token` 校验归属**;
    每条对应 PK/SK 或 GSI 设计,P0 开工前定,别边写边补。
- **签名架构:按形态分策略(不是所有形态都每 token 调 KMS Sign)**:
  - **【SaaS】KMS Sign(每 token 调)**:私钥从不出 KMS 是多租户下的正当前提——逐租户 CMK 要密码学隔离,若走本地签名就得在内存持有 N 把租户私钥、与隔离主旨冲突。接受 per-token 的 RPS/延迟约束(上面的容量模型)。
  - **【自部署】可选 data-key 本地签名**:单租户(租户数=1)的 key set 小、可控,用 `GenerateDataKeyPair` 拿到**签名密钥对集**(仍是 EC/RSA 各一对以支撑双算法,私钥密文 + 公钥)、Lambda 冷启动时解密私钥驻留内存、**本地签名**,KMS 只在冷启动解密一次——per-token 的 RPS 天花板与几十~数百 ms 延迟**直接消失**,吞吐/成本差一个数量级。代价是"私钥进入 ephemeral compute 内存",单租户、key set 小时这个代价可接受且好评估。**自部署默认可开此模式**;要不要开留作部署参数。
    ⚠️ **需要一把独立的 symmetric wrapping CMK(不能从签名 CMK 派生)**:`GenerateDataKeyPair` 生成的私钥密文是用**对称 KMS key 包裹**的,**不能从 ES256/RS256 非对称 signing CMK 派生**——本地签名模式因此不用签名 CMK,而是"symmetric wrapping CMK + data key pair"这套独立 key material。这与 SaaS 的"非对称 signing CMK + KMS Sign"是**两套不同的密钥体系**,JWKS/轮换/验收各写各的(下方 KMS-Sign 细节只覆盖 SaaS)。
    ⚠️ **加密私钥只生成一次、持久化共享(否则 N 实例 = N 把 key,JWKS 前提崩)**:`GenerateDataKeyPair` 每次调用返回**全新**密钥对,故**绝不能每个 Lambda 各调一次**。做法:生成一次 → 把 **wrapping CMK 加密的私钥密文放进持久存储**(SSM Parameter Store / Secrets Manager / DynamoDB 单项),**所有 cold start 解密同一份密文**;轮换=写入新密文版本、老版本保留到 retire。这条要落进自部署 runbook。
    ⚠️ **JWKS/轮换语义(与下方 KMS-Sign 路径不同)**:JWKS 发布**数据密钥对的公钥**(非 CMK 的 `GetPublicKey`);轮换 = 新密钥对密文入库 → 新公钥 publish-ahead 进 JWKS → warm 实例靠版本标记/主动失效换用新私钥 → 旧公钥 retire。"切签名"在**每个实例内**发生,新旧实例并存期两把私钥都在签——JWKS 同含两公钥即覆盖。
- **KMS 签名(SaaS 路径)细节**：JWKS 由 KMS 公钥生成；
  轮换有**两相,两个重叠期都要覆盖**(否则部分 RS 因缓存拒 token):
  1. **publish-ahead(前)**:新 key 先进 JWKS,**且必须早于开始用它签名 ≥ `/jwks.json` 的 `Cache-Control: max-age`(§2.1 冻结为默认 5min)**——否则缓存了旧 JWKS、又不做"未知 kid 重取"的 RS 会拒掉新 key 签的 token;
  2. 切签名 → **retire 重叠期(后)= max(access, ID token) TTL(§2.1)** → 旧 key 退出。
  兜底:§6 的 RS SDK 强制"**遇未知 `kid` 立即重取 JWKS**",对用本 SDK 的 RS **降低** publish-ahead 未覆盖时的失败概率;⚠️ **但系统级 publish-ahead ≥ JWKS `max-age` 仍是 MUST 保留**(第三方 RS 未必用本 SDK,§6);**只有封闭部署且所有 RS 都证明做未知 kid 重取,才可作为显式例外跳过等待**。移除旧 key 还要留 clock-skew 余量。
  ⚠️ **区分"优雅轮换"与"紧急吊销"两条流程**:上面是优雅轮换(旧 key 保留 retire 重叠期)。**怀疑密钥泄露时走紧急吊销:重叠期=0,立即从 JWKS 移除旧 key、牺牲在途 token**(离线校验 RS 不再接受旧 key 签的 token)。事故响应必须有这条独立路径——否则密钥泄露时离线 RS 会一直接受伪造 token 直到 TTL 到期。紧急吊销后受影响用户需重新获取 token。
  ⚠️ **【自部署】本地签名模式的紧急吊销**:移除 JWKS 公钥已能让 RS 拒 token,但 warm 实例内存里还持有明文私钥——还须**轮换加密私钥密文 + 强制 warm 实例回收/主动失效**,否则泄露的密钥材料仍在被在用实例签发。落自部署 runbook。
  （多区域时使用 **KMS multi-Region 非对称 key**：primary 与各区 replica 共享 key material、key ID、
  公钥和 `kid`，JWKS/issuer 不按区域分叉；运行时使用本区 replica，旧单区域 key 在非原区域必须
  fail closed。复制、探针、轮换和清理编排见 DEPLOYMENT §1。）
  ⚠️ **【SaaS】每租户独立 key set 是第一天基线(此处"第一天"= SaaS 上线首日、即项目 P2/P3,非项目 P0;EC+RSA 两把 signing CMK,轮换期 ≤4;详见 DEPLOYMENT §1)**:其 JWKS 只含本租户公钥,让"用租户 A 的 key 冒充 B 的 issuer 必败"在**密码学上成立**;onboarding 的 `CreateKey` **同步返回**(非编排),没有理由推迟。**成本/配额按 DEPLOYMENT §1 的"每租户一套 key set(稳态 2 把 / 轮换期 ≤4 把)"口径算**——即 ~$2/租户/月、单区租户天花板 ~5 万、置备速率减半,别按"每租户一把"直觉估;**成本随租户线性放大不改变基线**,压力先靠提额/分片消化。
  - **不存在"派生子密钥"中间档**:KMS 非对称 key 不能派生、非对称 Sign 无可验签的 signing context。
  - 🔴 **头号规模/架构风险:签名吞吐是"每区域硬顶、与租户数无关"**(不是注脚,是决定 fleet 拓扑的前置约束)。所有租户所有 CMK 按**密钥类型共享区域配额池**——**ECC 一池、RSA 一池**(非单一全局池;逐租户 CMK 给密码学隔离、**不给吞吐**)。**P0–P2:access 恒 ES256 只吃 ECC 池;ID token 按 per-client alg 落池(默认 RS256→RSA,注册 ES256→ECC)**;结合 §2.1 稳态公式(每会话 ≈ 1/access_TTL 次 ECC 签名),**单区域可装的活跃会话 ≈ ECC 池配额 × access_TTL**(稳态 refresh 主导;默认 ID 全在 RSA 池、不占 ECC)。⚠️ **主容量靠拉长 TTL + 跨区分片(都确定性)**;**access 分流到 RSA 池是 P3 可选优化**(启用后上限可抬到两池之和,但不是 P0–P2 的规划依据,§2.1)——规划天花板一律**按单 ECC 池 + TTL + 分片**算,别把 SaaS 天花板押在 P3 分流上。
    - **noisy-neighbor**:一个吵闹租户可耗尽某池、throttle 同账号其他租户;§3.2 的"按租户限流"须**兼作签名配额公平闸**(逐租户 Sign 速率封顶)。
    - **量化的跨区分片触发阈值**:**P0–P2 盯 ECC 池的稳态 Sign 速率**(access 全走这里);当 access 签发速率(∑活跃会话 / access_TTL)持续 > **ECC 池配额的 ~70%** 时,启动**跨账号/区域分片新租户**(留 30% 给突发登录尖峰)。RSA 池单独盯(承 ID token,负载低)。⚠️ **P3 若启用分流**,触发判据才改为"可用于 access 的两池合计容量 `(ECC + RSA − ID token 对 RSA 的占用)`",届时两池水位 + 合计余量都进容量看板。**P0–P2 别把 RSA 池算进 access 可用容量**(access 不往那分流)。跨区分片反过来前置决定 issuer/路由/CMK 拓扑(§11 #9)。
  - **claims 级的档位定义(统一口径,消除前后矛盾)**:共享 key + `iss`/`tenant_id` 区分,是**应用层隔离、非密钥边界**。定为**一个正式的"低保障档"SKU**:默认关、需租户**显式 opt-in 并签署风险披露**(承认防伪造靠 AS 代码正确性、非密码学),**不作 CMK 成本的常规逃生口**——即"不是给随便哪个成本敏感租户默认降级",而是"知情接受风险者的例外档"。其升级到 CMK 的在线迁移见 DEPLOYMENT §2 B。(DEPLOYMENT §1 措辞与此一致。)
    ⚠️ **共享 key 的紧急吊销爆炸半径**:上面的"紧急吊销(重叠期=0)"针对逐租户 CMK 时只炸单租户;**共享 key 泄露则全组同罪**——吊销/轮换同时命中所有共享该 key 的低保障租户(集体重签、在途 token 集体作废)。故**共享 key 必须分组(每组 N 租户一把,非单一全局 key)以限爆炸半径**,组大小是显式旋钮;风险披露须明说"与同组租户共享密钥边界、任一同组泄露触发全组轮换"。详见 DEPLOYMENT §1。
  **【自部署】** 单组织**单租户 key set**(租户数=1;KMS-Sign 模式=EC+RSA signing CMK 各含双活,本地签名模式=wrapping CMK + data key pair set,见上"key set 不是一把 key"),无跨租户吞吐争抢约束。
- **Verified Permissions（Cedar）**：AWS 原生策略引擎，适合
  "这个 agent 的这条委托链能否拿这个 scope 访问这个 resource"的判定，策略即代码、可审计。
  ⚠️ **但别放在 token 签发的同步热路径上**：AVP 增加尾延迟 + 硬外部依赖 + 请求配额，
  与上面的 P99/provisioned-concurrency 叙事叠加会放大 tail latency。
  ⚠️ **按"能否在签发前预判"切分策略,别用统一的'预判缓存'话术**(否则与请求时上下文约束自相矛盾):
  - **静态可预判**(scope/resource 白名单、委托链深、RAR 细粒度约束) → **Grant 创建/更新时** Cedar 判定一次、结果**写进 Grant 字段**,`/token` 只**读字段 + 比对白名单**(§5.2),不在签发路径同步调 AVP;
  - **依赖请求时上下文**(`ip`/`vpc` 等) → **无法在 Grant 创建时预判**,做成**签发路径上的轻量内联比对**(Grant 里存静态 allowlist,请求时比对来源 IP/VPC)——这不是 Cedar 调用、开销小,但确实在热路径;
  - **不跨请求缓存 Cedar 决策**:缓存会与 §5.1"introspection 即时感知吊销"冲突(把吊销窗口再拉长)。
  - ⚠️ **策略变更的失效语义(写死为异步重算,不在签发时同步算)**:Grant 存 **`policy_version`**,Cedar 策略更新即 bump 全局版本并触发**后台重算任务**扫描 stale Grant、更新其预判字段(或直接吊销不再合规的)。**签发路径永不同步调 AVP**——否则"策略刚收紧、大量 Grant 同时 stale"正是最坏时刻把 AVP 尾延迟+惊群引回 `/token`。**重算完成前 stale Grant 的签发按 fail-safe 处理**(拒绝或按更严的旧∩新交集),重算是滞后但有界的。⚠️ **广播式策略收紧会让大量 Grant 同时 stale → fail-safe 期间短时可用性抖动**;须定**重算 SLA/有界延迟目标**(如"全量重算 ≤N 分钟内收敛"),并对 fail-safe 是"拒绝"还是"旧∩新交集"按敏感度选(高敏拒、一般降级)。(这就把此前"二选一"闭合成一种语义。)
- **consent UI 是"静态托管的 SPA + 动态 API 驱动",不是纯静态资产**:S3 托管 SPA 外壳,运行时调 API 取 consent 详情(含 §11 #8 的 **RAR 结构化渲染**)+ **per-request CSRF token**,再 POST 回。纯静态给不出 per-request token、也渲染不了 RAR,故"静态"仅指资产托管方式。
- **CSRF 防护（两处别混）**：
  - **`GET /authorize` 靠 `state`**——那是**客户端↔AS 的 CSRF**,由客户端生成校验(客户端职责,RFC 6749/OAuth 2.1);⚠️ **但 AS 侧有一条对称硬要求(对照 `nonce` 的 MUST echo)**:**授权响应必须原样回填客户端传入的 `state`(存在即 MUST echo、逐字节不变)**——AS 不生成/不校验 `state` 语义,但绝不能吞掉或改写它,否则客户端的 CSRF 校验无从做起。补进 conformance(C1.7)。
  - **consent 表单 POST 靠 AS 下发的 per-request anti-CSRF token**——这才是 **AS↔浏览器的 CSRF**、AS 职责(consent 走 cookie 会话);
  - PAR 只保护请求提交那一跳,**保护不到 consent 表单提交**,必须单独加。
- **点击劫持防护(consent 页必做,per-request CSRF token 挡不住)**:consent/登录页是 clickjacking 典型标的(透明 iframe 诱导点"同意")。所有交互页面下发 **`Content-Security-Policy: frame-ancestors 'none'`**(+ 兼容旧浏览器的 `X-Frame-Options: DENY`)——禁止被任何页面 iframe 嵌套。CSP 由 SPA 的响应头下发,与 §8 的 SPA+API 架构天然契合。
- **login-CSRF(§7 的补充)**:防诱导受害者点攻击者的登录链接、把浏览器登进攻击者账号——magic-link/登录链接须与发起浏览器会话绑定(link↔session nonce),异浏览器打开即拒。
- **【SaaS】登录/consent cookie 的租户作用域隔离(与逐租户 CMK 同层威胁的另一半)**:每租户独立子域 issuer(`t1.saas.example.com`)。登录/consent 会话 cookie **绝不能设 `Domain=.saas.example.com`**——否则浏览器会把 t1 的登录态自动带到 t2 子域,用户在 t1 登录后访问 t2 的 `/authorize` 被当已认证 = **跨租户会话越界**。要求:cookie **严格 host-only 绑定到租户子域**,优先用 **`__Host-` 前缀**(强制 host-only + `Secure` + `Path=/`,无 `Domain`)。密钥侧(CMK/JWKS)已隔离,这里补上浏览器会话侧。
- **CORS（浏览器内 MCP 客户端需要）**：`同源公理`收拢的是**自家端点彼此同源**,但**浏览器里的 MCP 客户端**(如 MCP Inspector)的 origin 与 AS 不同,访问 `/token`、`/register`、discovery 都要 CORS 头。按端点性质分三类:
  - **公开 GET(discovery/JWKS/PRM)** → **放开** `Access-Control-Allow-Origin: *`(本就公开,无凭证);
  - **`POST /register`(DCR)的鸡生蛋** → 首次注册时客户端**还没注册、allowlist 里没有它的 origin**,若按 allowlist 会把浏览器内零配置客户端(正是本节要服务的 MCP Inspector)挡死在 preflight。故:**`open` 档的 `/register` 是无凭证公开端点,明确允许 `Access-Control-Allow-Origin: *`**(不带 cookie,不违反"`*` 不得与 `Allow-Credentials: true` 并用"的规范);**`initial_access_token`/`software_statement` 档**则可把允许的 origin 绑进票据/声明,或走租户级 allowlist;
  - **带凭证/敏感端点(`/token` 等)** → **按注册的客户端 origin allowlist**(客户端注册后 origin 可从 `redirect_uris` 推导),**不用 `*`**;preflight `OPTIONS` 正确处理。
  - 命令行客户端(mcp-remote 是 Node 进程)不受 CORS 约束,此策略只为浏览器内客户端。
- **同源公理落地**：CloudFront 一个 distribution 收拢 **AS 自身端点**（API + consent UI），
  **`issuer` 与所有 AS 端点严格同 origin**（坑 2.3 消失）。
  ⚠️ **PRM 托管不属于"AS 同源"这条**——PRM 是**RS 的**资源元数据,发布在 **RS origin 或 RS 的 CNAME vhost** 上(§6),其 origin 就是该 RS、不是 AS 的 issuer origin;CloudFront 只是可代为托管这些 **RS vhost**,与 issuer 同源无关。
- IaC 全 CDK（TypeScript），环境（dev/staging/prod）参数化；跑 cdk-nag 合规检查。
- **交付打包(形态分叉的核心落点)**:
  - **【自部署】** CDK app 是**可分发、可版本化的制品**:客户 `cdk deploy` 进自己账号即得完整栈;
    必须随附 **schema 迁移脚本、KMS key 轮换 runbook、跨版本升级/回滚指引、cdk-nag 合规基线**——
    这些在 SaaS 下由我们内部 CD 消化,自部署则交到客户手里(见 §10 增补验收)。参数化到"单租户"默认。
  - **【SaaS】** 同一 CDK 栈 + **控制面/租户编排层**(租户 onboarding、逐租户 KMS key 置备、
    按 Host 的 issuer 路由、计费与限流分级);多租户隔离参数默认开启。

安全纵深：WAF 限流 → DCR 配额 + 未验证客户端标识 → public/CIMD PKCE 强制 / registered confidential PKCE 或 token 端强认证 → CSRF 防护（authorize/consent）+ clickjacking 防护（`frame-ancestors 'none'`）→
redirect 规范化匹配 → refresh rotation + 复用检测（含宽限窗）→ DPoP 可选 →
audience 强制 → 短 TTL + grant 吊销（含残留窗口说明）→ 全量审计事件。

---

## 9 · 与原文档坑位的逐条对账

| 原坑 | 本设计的消解点 |
|---|---|
| 1.1 CustomOauth2 需显式 complete | §4 状态机显式 `code_issued_awaiting_exchange`，语义自解释 |
| 1.2 IN_PROGRESS 黑盒 | §4 细分状态 + `last_error` 透传下游错误 |
| 1.3 sessionUri 复用暗坑 | §4 会话可发现且幂等查询(confidential 走 `GET /sessions?client_id=me`,public 凭 `session_token`),同一 session 幂等、不会"每次轮询开新会话" |
| 1.6 2LO/3LO 不可判别 | §2 命名空间 `sub_type` + `act` + `auth_grant` 显式声明；§6 SDK 一行策略 |
| 1.7 无 public provider 出口 | §3.1 public+PKCE 是默认；confidential 共存 |
| 2.1 无 DCR | §1/§3.2 原生 RFC 7591/7592，三档策略 + 配额 + 显式回收（非裸 TTL） |
| 2.2 discovery 不宣告 PKCE | 公理 1：元数据永远如实 |
| 2.3 issuer 跨域 | §8 CloudFront 单 origin |
| 2.4 callback 精确匹配 | §3.3 受控 prefix 匹配 + loopback |
| 2.5 public/confidential 混用 | §3 按 client 记录 auth method 逐一校验 |
| 2.6 全量替换静默降级 | §3.2 PUT 保留 + PATCH 部分更新扩展 + 降级需显式确认（单调性判定） |
| 3.1/3.2/3.5 Gateway 3LO 死结 | §5.2 为**直连**路径的异步授权提供服务端原语（CIBA/device/consent URL + elicitation）。⚠️ 死结的另一半在客户端侧（Gateway 的 service-linked WL + 协议版本无 elicitation），本 AS 提供原语**不能让 Gateway 那条路复活**，只是让不经 Gateway 的直连方案成立 |

---

## 10 · 实施路线图

> **口径澄清(避免验收冲突)**:下表 P0-P3 是**项目 P0/P1…**(协议内核的阶段),默认以【自部署】单租户栈为交付目标。**【SaaS】形态有自己的一套"形态里程碑"**(多租户上线、控制面、逐租户 CMK、计费),挂在项目 P2/P3 上,**不要把"SaaS 多租户"读进项目 P0 的验收**——两套编号分开(§0.5 表格"租户模型"行已标注)。
> ⚠️ **差异化能力(workload/2LO/token-exchange/Grant)全在 P2**:P0/P1 实质是"标准 OAuth 2.1/OIDC + MCP AS",与普通 AS 看不出区别——这是合理的风险排序(先把协议内核跑成活体 conformance),但**对上/对外沟通要说清"P0/P1 阶段还看不出 agent 差异化"**,别让人按"agent 一等公民"的卖点期待 P0 产出。

| 阶段 | 内容 | 验收 |
|---|---|---|
| **P-1 薄纵切 spike**（P0 开工 gate,~数天） | 一条端到端最薄链:`authorize`(PKCE) → `/token` → **KMS ES256 Sign** → **DER↔JOSE 转换** → discovery 打通。**用 Rust 实现**(§8 倾向) | **实测冷启动 + KMS Sign 延迟/吞吐(那个"实测 Q",§2.1)**;据此**拍板语言(Rust/Node)+ 是否要 provisioned concurrency + 跨区分片阈值 + 重估 P0 工期**(Rust 生态不成熟叠加全套 conformance,spike 的实际速度是 8-12 周估计的输入,别拍完语言仍按原估走)——这些不能悬在未测数据上进 P0 |
| **P0 骨架**（**~8-12 周**：dual discovery + KMS 双算法 JWKS(**含多公钥并存的双活结构**,完整两相轮换编排属 P3) + refresh rotation + 复用检测 + 宽限窗信封加密 + 7591/7592+PATCH + magic-link + 单表 access-pattern/GSI + **应用层限流(WAF 扛不了 client_id,§3.2)** + **SES production access 审批(账号出 sandbox)** + CDK + 自动化 conformance,小团队按此量级。⚠️ **收窄范围的退路不能砍 P0 conformance 契约项**——PATCH 降级确认(C4.7 P0 MUST)、宽限窗信封加密 + 复用检测(C3 P0 MUST)都在 P0 契约内,砍了 P0 就过不了自己的 conformance。真要压范围只能动**非 P0 契约的宽度**:magic-link 之外的登录方式(passkey 本就已后移 P0.5/P1)、把多 RS/PRM/SDK 留在 P1(本就如此)、或与相关方**显式重议 conformance 基线并同步改 CONFORMANCE 阶段标注**,而不是留一个静默违背契约的逃生口） | discovery(**OIDC + OAuth 两份、含 RFC 9207 `iss`**) + JWKS(KMS，**ES256 + RS256 双算法**,§2) + authorize(PKCE) + token(code/refresh rotation **含复用检测 + 宽限窗**) + **`/userinfo`**(默认 audience 指向它,§1) + DCR(RFC 7591/7592 **含 PATCH 降级确认**) + **magic-link 登录**（passkey 后移 P0.5/P1 以收窄范围）+ DynamoDB 单表 + CDK 部署。**P0 支持单 `resource` + 绑定 code/token 的 audience-bound MCP token(MCP 硬要求,不推迟);多 `resource` 下采样 + PRM/SDK 完备属 P1(见 §1)** | **`oauth2c` 跑通 code+PKCE**；mcp-remote 对 **mock RS / 手工配置** 跑通(真正的**零配置 MCP** 依赖 PRM/resource/SDK,落 P1;**P0 用旧版 MCP fallback——RS origin 即 AS,或测试 RS 与 AS 同域**发现,见此说明)；**discovery/9068 claim 形状/7592 客户端管理/redirect exact-match 模糊测试(C4.4a,P0 MUST——`%2e%2e`/双斜杠/尾斜杠/query 精确,别漏)的自动化 conformance 已就位** |
| **P0.5 关口(硬 gate)** | **账户恢复流(恢复码/联邦兜底二选一,§7)** | **引入任何真实身份(含内测)前必须先过**——否则邮箱失陷即永久锁死。P0 纯 conformance 假用户可不触发此 gate。(注:magic-link **发信防滥用**是 **P0 MUST**、跟 magic-link 一起交付,不在此 gate) |
| **P1 MCP 与企业身份完备** | PRM 托管（按 RS 身份）+ `resource` 强制（含默认/例外）+ introspect(**含调用方 RS 认证**)/revoke + RS 校验 SDK(TS/Py) + **授权会话状态 API(`GET /sessions?client_id=me` 列表 + 按 id 查询；confidential P1 即可用,public 依赖 device(P2)/PAR(P3),见 §4)** + **用户 login session 管理(`GET/DELETE /account/sessions` + 按 opaque handle 单删；与 AuthzSession 分域)** + **用户凭据管理(`GET /account/credentials`、passkey 命名/防锁死删除、本地密码首次设置/轮换、恢复材料 show-once 轮换；全部写操作要求近期重认证并推进 credential authority)** + **上游 IdP 联邦(含 canonical `acr` 映射、`amr` 观测 + `prompt`/`max_age` 语义,§11 #10/C12.4)** + **RP-initiated logout / 会话终止(§7:与联邦同期,联邦引入即需要)** + **tenant-scoped SCIM 2.0 Users(ServiceProviderConfig、POST/GET/filter/PUT/PATCH、逐租户独立凭据、canonical lifecycle 级联吊销)** + **tenant-scoped security-event 热账本、retry/DLQ、告警与长期 S3/Athena 归档，以及逐 tenant SSF/CAEP push transmitter(C12.6)** | Claude Code / mcp-remote 对一个真实 MCP RS **零配置连通(`open` 档;SaaS 收紧档为"发现零配置 + 注册需票据",见 §3.2)**；AgentCore CustomOauth2 provider 接通（confidential 路径）；**PRM 资源标识匹配、redirect URI 模糊测试、logout 会话失效自动化通过**；**SCIM Dev/SaaS 跨租户协议矩阵通过，并由一个真实 Entra 或 Okta job 完成 provision/deprovision/re-provision；SSF Dev/SaaS t1/t2 KMS/HTTPS interoperability、timeout/retry/dedupe 与 revoke-before-lease 通过** |
| **P2 委托** | token exchange（含 subject/actor token type + may_act 校验）+ Grant 对象(含 `authorization_details`)与 `/grants` API + **RS SDK 执行简单 RAR(时间范围/资源子集,C8.5a——与 Grant 同期,不留"存不执行"空窗)** + workload 客户端（**先落 OIDC/SVID 自校验路径**，SigV4/STS 兜底）+ device flow + **异步 consent（先 CIBA poll 模式，ping/push 推 P3；需先确认真实 CIBA 需求，否则先做最小异步 consent）** + **opt-in MCP EMA/ID-JAG Resource Authorization Server profile（§6.2/C13，默认关闭）** | agent 用 workload 身份静默换取委托 token；用户可查/吊销 grant；EMA client 用 tenant-scoped enterprise IdP ID-JAG 换取单 resource access token；**token-exchange 委托校验、refresh 复用检测、grant 吊销、简单 RAR 越界拦截与 EMA feature-off/trust/replay/最终 claims 有自动化测试**;🔴 **两个易漏的 P2 MUST 必须点名进验收(否则复现 §10 想防的"最后才发现漏项")**:C7.8(pairwise 委托链的 subject 解析——`jti→user_id` 反查、绝不解 `sub`)、C10.17(Cedar/AVP 移出签发热路径 + `policy_version` 异步重算 + fail-safe) |
| **P3 硬化** | DPoP + PAR + **复杂/策略型 RAR(Cedar,C8.5b)** + 审计跨区域/数据驻留硬化 + 多区域（区域亲和 + 重放敏感项单区属主）+ 完整 CIBA(ping/push) + **ES256/RS256 两池分流(可选容量优化,仅实测确需再抬单区上限时启用,C10.15;配套 PRM alg-非固定声明 + 逐 RS 关分流开关)** + **BYOD 里程碑(自带域名证书/路由 + §6 PRM CNAME 托管,C8.1b;post-freeze 待定、评估 CloudFront SaaS Manager,§11 #3/DEPLOYMENT §1)** | **OIDC Basic OP profile(仅 code flow)通过**——遵 OAuth 2.1 BCP,故**不做 implicit/hybrid response types(`id_token`/`token id_token`)**,不跑 hybrid profile(测试选型别踩) |

> 🔴 **P0 "8–12 周" 是乐观下限、高概率超期项(明确标注,非脚注)**:P0 塞进双 discovery、KMS 双算法 JWKS、refresh rotation + 复用检测 + 信封加密宽限窗、7591/7592+PATCH、magic-link、单表 access-pattern/GSI、应用层限流、SES production access、CDK、自动化 conformance,**还叠加 P-1 的 Rust spike**。对**小团队 + 安全关键 + Rust OAuth 生态要自己拼(本文自认)**的前提,这个区间相当激进。P-1 spike 的实测速度是 8–12 周的**输入**,**大概率上修**——排期时按此预期,别把 8–12 周当承诺。收窄退路见 P0 骨架行(但不得砍 P0 conformance 契约项)。

**两种交付形态的排期（§0.5）**：

- **P0-P2 以【自部署】单租户栈为先**——协议内核 + 可 `cdk deploy` 的单栈,最快拿到"活体 conformance"验证,也是最小可用制品。多租户隔离**代码从 P0 就按"可关闭的一等能力"写**(租户维度贯穿 DynamoDB 分区键、KMS key 选择、Host 路由),但默认关(=单租户)。
- **【SaaS】多租户 + 控制面在 P2/P3 单列为工作项**:逐租户 KMS key 置备、按 Host 的 issuer 路由、租户 onboarding、配额/限流分级、计费。**先跑通自部署单租户,再把租户数从 1 放开**,避免过早背上多租户运维复杂度。
- **【自部署】的交付制品化**(schema 迁移、KMS 轮换 runbook、升级/回滚、cdk-nag 基线)在 **P1 完成前**成型——因为自部署客户拿到的第一个版本就必须能安全升级。

**conformance 前移（不等到 P3）**：以下应在对应阶段就有自动化测试，别攒到最后——
discovery 元数据、RFC 9068 claim 形状、RFC 7592 客户端管理、RFC 9728 PRM 资源标识匹配、
redirect URI 模糊测试、token-exchange 委托校验、refresh 复用检测、grant 吊销行为。
**外加多租户隔离测试**(【SaaS】):跨租户数据访问、Host 路由隔离、**跨租户 token 伪造"用租户 A 的 key 冒充 B 的 issuer 必败"(密码学保证,基于逐租户 CMK 基线)**必测;若某租户被显式配成 claims 级(低保障),额外测"控制面拒绝其签他人 `iss`"(应用层保证)。

测试策略：以 **oauth2c、mcp-remote、Claude Code、AgentCore CustomOauth2** 四个真实客户端
作为持续集成的"活体 conformance 测试"——原文档三天血泪的每一关都固化为 e2e 用例；
上述协议正确性项以**规范级自动化测试**在集成真实客户端**之前**先兜住。

---

## 11 · 开放问题（下一轮头脑风暴）

1. **Token vault 要不要做？** AgentCore 的 vault（存下游第三方 token）是否属于本系统边界，
   还是只做"发 token 的 AS"？倾向：P2 后评估一个轻量 broker（KMS 信封加密 + DynamoDB）。
2. **Cedar 策略的暴露粒度**：开放到什么程度（托管策略模板 vs 自由编写）？
   **【自部署】** 客户在自己账号里,可给到自由编写;**【SaaS】** 需防止一个租户的策略影响他人,倾向受限模板 + 逐租户命名空间。
3. **多租户 issuer 模型（仅【SaaS】相关，post-freeze）**：✅ **已定=每租户独立子域 issuer**（`t1.saas.example.com`，CloudFront 泛域名 + 按 Host 路由）——全文的 cookie 隔离(§8)、RFC 9207、逐租户 CMK 都据此设计。**post-freeze 待定(明确切到实现文档)**:BYOD 自带域名的证书/路由——**首选评估 CloudFront SaaS Manager 多租户 distribution**(DEPLOYMENT §1 第 3 步),它可能免去标准 distribution 的单证书约束与 ACM DNS 编排。
4. **agent 身份注册表**是否要对齐 SPIFFE ID 命名（`spiffe://trust-domain/agent/...`），
   为跨云 workload 联邦留门。
5. OIDC conformance 认证与 MCP 官方测试套件的时点。
6. **合规与数据驻留**：passkey 凭据、用户身份、审计湖 PII 落在 DynamoDB/S3。
   **【自部署】** 数据全在客户自己账号/region,驻留天然满足,合规责任在客户;
   **【SaaS】** 平台须提供 region pinning、逐租户数据隔离、GDPR "被遗忘权"删除,否则现有 security-event 归档在跨区域硬化时可能推翻重做。
   审计事件建议**只落 `jti`/哈希，不落 token 本体**。
7. **两形态的代码/配置边界怎么划?** 目标是**单一协议内核**,差异收敛到部署参数 + 控制面(§0.5)。
   ✅ **多租户隔离是纯配置还是独立编排服务——已定推荐路径(DEPLOYMENT §1)**:数据平面永远纯运行时配置(`tenant_id` 贯穿数据/密钥/路由);
   逐租户 key set 只是 onboarding 的**EC+RSA 两次同步 `CreateKey` 步骤,不算异步编排**;**唯一需要异步编排服务的是 BYOD 自带域名的 ACM/DNS 慢确认**,且仅 SaaS 一侧。
   ✅ **跨形态共用一套 migration + 共享 key→逐租户 key set 在线迁移——已定方案(DEPLOYMENT §2)**:两者都用 expand-contract,
   迁移引擎随制品走、幂等、懒迁移 + 可回滚;换 key 复用 §8 的 `kid`+JWKS 多公钥双活轮换,`kid` 用公钥指纹以跨密钥类型稳定。
   ✅ **SaaS 密钥基线已定**:**第一天就用逐租户独立 key set**(EC+RSA 两把 signing CMK,两次 `CreateKey` 同步返回、非编排;成本/配额按 key set 口径,DEPLOYMENT §1)——密码学隔离,满足 §8"防跨租户伪造"与 §10 密码学 conformance。claims 级共享 key 仅低保障可选。
   **仍待定**:`min_reader_version`(DEPLOYMENT §2 A)的受支持升级窗口跨度定多大?自部署"超窗跳版"的逐级过渡工具是否需要单独交付?
8. **RAR-aware 的 consent UI 渲染**：consent UI 已定为 SPA+API(§8)、RS SDK 已执行 `authorization_details`(§6),但**结构化 RAR 如何渲染成用户看得懂的授权提示**尚未设计——若只显示 scope 字符串,§5.1 的细粒度授权(“只能读 2026 年文档”)这个卖点就打折。**建议冻结时给最小渲染方案**(把 RAR 的 `type`+关键约束映射成一句人话),而非全推 post-freeze。
9. **✅ 已定=多区域 KMS 不分叉 issuer/JWKS**：使用 **KMS multi-Region 非对称 key**。各区
   replica 共享 key material、key ID、公钥与 `kid`，Sign 使用请求所在 region 的 replica 并按该区计
   配额。新 generation 必须先复制并通过全部配置区的真实签名探针才能发布；运行时只对 `mrk-*` 做
   区域 ARN 重绑定，旧单区域 generation 在备用区 fail closed，直到完成一次 MRK rotation。
   ⚠️ **故障切换瞬间的重放边界(P3 前须写出降级语义)**:区域亲和路由在切换瞬间,故障区里**未复制完成的 code/jti/refresh 标记归属是真空**——降级语义定为**切换期间这些流一律失败、重走授权**,别留给运行时发现。
   ⚠️ **多区域下 Grant 吊销传播(§5.1 的"立即失效"在多区域的边界,此前未列)**:身份表(含 Grant)走 Global Tables 异步复制,而 refresh 标记按区本地(§8 拆表)。故 **refresh 校验必须联查身份表里 Grant 的最新 `status`**(而非只看本地 refresh 表的 active 标记),否则吊销跨区传播延迟内旧区仍能续期。须明确可接受复制延迟窗口。
10. **✅ 已定并实现=OIDC 认证上下文与 assurance step-up 进 P1**(acr / amr / prompt / max_age):
    - 处理 `prompt=none/login`、`max_age`；定义 `urn:agent-auth:assurance:{baseline,strong}` canonical class，本地仅验证 passkey、上游仅逐 tenant/IdP exact `acr` allowlist 可 strong，未知 `acr` 与所有 `amr` 不提级；
    - `/authorize` 执行 `acr_values` 与 freshness，`transfer` RAR 在 authorize/consent 双闸，Admin `access.manage` 以 RFC 9470 challenge 触发上游 step-up；上游 `auth_time` 允许最多 60 秒正向时钟偏差，偏差范围内钳制为 callback 时间、超限 fail closed；token/refresh/delegation/introspection 保留 canonical `acr` 和该规范化 `auth_time`。规范见 [`ASSURANCE_STEP_UP.md`](./ASSURANCE_STEP_UP.md) / C12.4。
11. **规范性抽取 + 文档拆分**:✅ **已执行**——① normative MUST/SHOULD + 测试项清单见 **[`CONFORMANCE.md`](./CONFORMANCE.md)**(与 §10 conformance 前移配合);② 多租户置备/在线迁移等实现细节已切到 **[`DEPLOYMENT.md`](./DEPLOYMENT.md)**,§0.5 只留语义/信任对照。**私有 claim 命名亦已定死**(命名空间对象 `https://a-auth.com/c`,见 §2 命名总纲)。
12. **✅ 已定=按形态选 subject_types(【SaaS】默认 pairwise、【自部署】默认 public,均 P0 锁死)**:`sub` 一旦发布改不得(改则**已发 sub 全变、RS 侧 user 绑定全断**),故 P0 就锁。**两形态默认不同**,因为威胁与需求相反:
    - **【SaaS】= pairwise(默认,可被企业租户 opt-in 覆盖为 public)**:头号场景"agent 连**第三方 MCP RS**",public 会让多个不合谋的第三方 RS 一对 `sub` 拼出用户全局身份;pairwise 是隐私默认(同 Apple "Sign in with Apple"、政务 eID),对齐 GDPR(#6)。⚠️ **可覆盖性(与自部署对称,消除"恒锁"歧义)**:SaaS 企业租户在语义上是"托管的自部署组织",其"自家多个首方 RS 要关联同一用户"需求与【自部署】public 同源。故**允许企业租户在 onboarding 显式 opt-in 到 public**——但**默认 pairwise、opt-in 需风险披露 + 声明"仅纯首方 RS 场景适用"**(一旦连第三方 RS,public 会泄露可关联 `sub`)。**该选择同样 P0 锁、写进该租户 issuer 的 discovery `subject_types_supported`、按租户独立**(不影响同 fleet 其他租户,租户 issuer 各自宣告)。onboarding 必问此项(DEPLOYMENT §0,与自部署对称)。
    - **【自部署】= public(默认,可选 pairwise)**:自部署单组织内 RS 多是**自家首方资产、常离线 JWT 校验**(拿不到 introspection、也不该依赖 AS 内部 `user_id`);pairwise-per-resource 会让**同组织多个 MCP server 无法关联同一用户**(统一审计、跨服务用户视图这类合理需求做不了)。故自部署默认 **public**(首方 RS 需要跨 RS 关联),要隐私可显式切 pairwise。
    - ⚠️ **后果知情(不可回改)**:选 public 则跨 RS 可关联、无隐私分区;选 pairwise 则首方 RS 跨 RS 关联不可用、只能靠 SDK/introspection。**发布前按形态拍死,写进该部署的 discovery `subject_types_supported`**。
    - ⚠️ **自部署 public 的陷阱须在 onboarding 前置提示**:自部署"多为首方 RS"≠全是——若客户起步纯首方选了 public、**日后扩展连第三方 MCP RS**,会 ① 把可跨 RS 关联的 `sub` 泄露给第三方、② 因 P0 锁死改不回 pairwise。**onboarding 指引须显式提示:"若未来可能接第三方 RS,起步就选 pairwise"**——别让它当成一个易忽略的默认(DEPLOYMENT 落此提示)。
    - **sector 键、`sub` 派生公式、ID/access/userinfo 的 sub 一致性规则:全部以 §2.8 为唯一权威定义**(MCP 按 resource、OIDC 按 sector identifier、多 host 强制 `sector_identifier_uri`、`sub=HMAC(secret,user_id‖sector)`、用户级关联靠内部 `user_id`)——此处不再重述,改动只在 §2.8 一处做,避免多处漂移。本条(§11 #12)只定**形态默认值**(SaaS pairwise / 自部署 public)这个决策本身。

> **冻结范围声明(消除 §11 里 ✅ 与"待定"混杂)**:标 ✅ 的(#3 issuer 模型、#7 隔离/迁移方案、密钥基线、#10 认证上下文与 assurance step-up、#11 拆分、**#12 subject_types 按形态默认(SaaS pairwise/自部署 public)+ sector 键**)是**冻结范围内已定**。
> 其余切到 post-freeze 实现文档:#3 BYOD 证书路由、#7 升级窗跨度、#8 RAR consent 渲染、#9 多区域。⚠️ 唯 **#8 RAR consent 渲染**与 §5.1 卖点直接相关,**建议冻结时就给最小渲染方案**。
>
> **范围提示(非问题,防未来失焦)**:§0.5 把系统从"发 token 的 AS"扩到"自部署 + 多租户 SaaS 平台"是一次实质加范围,已用"P0-P2 先做自部署单栈"止血。**若后续头脑风暴继续展开 SaaS 控制面细节(计费、限流分级、租户 onboarding、跨租户域名托管),应另开独立文档**,别让 DESIGN.md 承载两条产品线全部细节、稀释协议内核的可读性。

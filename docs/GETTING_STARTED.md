# Agent Auth — 入门(Getting Started)

> 5 分钟建立心智模型 + 本地零 AWS 跑通第一条授权流 + 按你的角色找到下一篇该读的文档。
> 这是**导览**,不重复实操细节:部署看 [`INSTALL_DEPLOY.md`](./INSTALL_DEPLOY.md),接入看 [`USER_GUIDE.md`](./USER_GUIDE.md),协议概念看 [`PROTOCOLS_101.md`](./PROTOCOLS_101.md)。

---

## 0 · 一句话

Agent Auth 是一个 **OAuth 2.1 / OIDC 授权服务器**,把"**哪个 agent 能代表哪个用户、访问哪个 MCP 资源服务器、在什么委托边界下行动**"做进服务器本体。它兼容传统 OAuth/OIDC 客户端,同时为 agent 场景补齐动态注册、public+PKCE、audience 绑定、可观测委托链、workload 机器身份、MCP RS 零配置接入。

不懂 OAuth/OIDC 术语?先读 [`PROTOCOLS_101.md`](./PROTOCOLS_101.md)(协议 101),再回来。

---

## 1 · 心智模型(先建立这几个概念,后面全通)

| 概念 | 一句话 | 在本系统 |
|---|---|---|
| **issuer** | 这个授权服务器的身份(一个 https 域名) | 自部署=你配的域;SaaS=每租户一个子域。**所有端点同 origin**,discovery 如实宣告 |
| **client** | 来要 token 的应用/agent/服务 | public(+PKCE)/ confidential(带密钥)/ workload(平台身份,无长期密钥) |
| **user** | 真人,通过 magic-link / passkey / 联邦 IdP 登录 | 登录后在 consent 页授权 |
| **resource(RS)** | 被访问的 MCP 资源服务器 | 每个 access token 只对一个 RS(`aud` 单元素);RS 用 SDK 校验 token |
| **access token** | 短命凭证,RFC 9068 JWT,ES256 签 | 带 `sub_type`(user/agent)、`aud`、可选 `act`(委托链) |
| **grant / 委托** | agent 代表用户行动的授权记录 | Grant 对象 + token-exchange 换发下游 token,权限恒 ⊆ 原授权 |

**三种"谁在要 token":**

- **用户在场**(浏览器)→ Authorization Code + PKCE(§1 下面就跑这个)
- **无浏览器/机器**(CI、agent runtime)→ workload 2LO(平台身份认证,§USER_GUIDE 4)
- **agent 代表用户**(已有用户授权)→ token-exchange(委托,§DESIGN 5)

---

## 2 · 本地 5 分钟跑通(零 AWS,内存 store)

本地 `agent-auth-server` 用内存后端(`AppState::dev`),不碰 AWS,最适合先感受协议。

### 2.1 前置

```bash
# Rust 工具链(rustup 装 stable);无需 AWS、无需 cargo-lambda
rustc --version    # 1.8x+
```

### 2.2 起服务

```bash
cargo run -p agent-auth-http --bin agent-auth-server
# 监听 127.0.0.1:8080;配置 host=localhost(dev 默认:自部署形态 + P1 阶段)
# dev 档已开:DCR open(免票据注册)+ login_user 占位(免真实邮箱,仅本地)
```

> ⚠️ **务必用 `http://localhost:8080`(而非 `http://127.0.0.1:8080`)访问**:issuer 按**入站 Host** 派生
> 且只认配置 host,`Host: 127.0.0.1` 与 `localhost` 不符会返 **400 bad host**(这正是 §1 心智模型里
> "issuer=Host 派生、所有端点同 origin"的体现,不是 bug)。下面全部用 `localhost`。

### 2.3 看 discovery(服务如实宣告自己)

```bash
curl -s http://localhost:8080/.well-known/openid-configuration | jq
# issuer=https://localhost / authorization_endpoint / token_endpoint / jwks_uri / 支持的 grant 与 auth 方法
# —— 未实现的能力不会出现在这里(公理:落地才宣告)
```

### 2.4 跑一条 Authorization Code + PKCE

```bash
B=http://localhost:8080   # 用 localhost(见上方 ⚠️)

# 1) 注册一个 public 客户端(dev open DCR);redirect_uri 用 127.0.0.1 回环合法(RFC 8252)
CLIENT=$(curl -s -X POST $B/register -H 'content-type: application/json' \
  -d '{"redirect_uris":["http://127.0.0.1/cb"]}' | python3 -c "import sys,json;print(json.load(sys.stdin)['client_id'])")
echo "client_id=$CLIENT"   # public,无 client_secret

# 2) 造 PKCE verifier/challenge
VERIFIER=0123456789012345678901234567890123456789abc
CHALLENGE=$(python3 -c "import hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256('$VERIFIER'.encode()).digest()).rstrip(b'=').decode())")

# 3) authorize(dev 用 login_user=alice 占位登录,省去 magic-link 往返)
#    → 302 到 redirect_uri?code=...(取 Location 里的 code)
LOC=$(curl -s -o /dev/null -w '%{redirect_url}' \
  "$B/authorize?response_type=code&client_id=$CLIENT&redirect_uri=http://127.0.0.1/cb&code_challenge=$CHALLENGE&code_challenge_method=S256&scope=openid&login_user=alice")
CODE=$(echo "$LOC" | sed 's/.*code=\([^&]*\).*/\1/')
echo "code=$CODE"

# 4) 用 code + verifier 换 token
curl -s -X POST $B/token -H 'content-type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code&code=$CODE&code_verifier=$VERIFIER&redirect_uri=http://127.0.0.1/cb&client_id=$CLIENT" | jq
#    → { access_token(ES256 JWT), refresh_token, id_token, token_type: "Bearer", ... }

# 5) 解 access_token 中段看 claims(iss=https://localhost / aud=[.../userinfo] / sub_type=user)
```

（本节命令已本地实跑验证:注册→authorize→token 全通,token 响应含 access/refresh/id_token。）

跑通后你已经历了一条完整的 OAuth 2.1 授权码流:**discovery → 注册 → authorize(PKCE)→ token**。想验签?`GET /jwks.json` 取公钥,用 `access_token` 的 `kid` 选 key(ES256)。

### 2.5 想看更多本地示例?

`e2e/` 下 70+ 个真机脚本每个头部都有用法;它们打的是部署后的 AWS 端点,但请求构造方式(authorize/token/refresh/introspect/…)对本地 server 同样适用,是最好的"活文档"。例:`e2e/code_flow.sh`(码流+refresh)、`e2e/mcp_introspect.sh`(RS 校验)、`e2e/id_token.sh`(OIDC id_token)。

---

## 3 · 按角色找路径

### 👨‍💻 我是 **OAuth/OIDC 客户端开发者**(接一个 App / agent)

1. [`PROTOCOLS_101.md`](./PROTOCOLS_101.md) — 补齐 code flow / PKCE / token / OIDC 概念
2. [`USER_GUIDE.md`](./USER_GUIDE.md) §1–§3 — public+PKCE / confidential / device flow 接入示例
3. 心里记住:**先读 discovery**,能力都在那如实宣告;access token 是 sender/audience 受限的,别当通用 bearer 到处用

### 🤖 我是 **workload / agent 运维**(CI、Lambda、K8s pod、agent runtime)

1. [`PROTOCOLS_101.md`](./PROTOCOLS_101.md) §workload — 平台身份联邦(OIDC-JWT / SigV4 / SPIFFE)
2. [`USER_GUIDE.md`](./USER_GUIDE.md) §4 — 2LO 换 token(无 client secret)
3. 委托(agent 代表用户)→ [`DESIGN.md`](./DESIGN.md) §5 token-exchange

### 🔌 我是 **MCP 资源服务器(RS)运维**

1. [`USER_GUIDE.md`](./USER_GUIDE.md) §5 — PRM 托管 + 用 RS SDK 校验 token
2. SDK:`sdk/python` / `sdk/ts`(RFC 9068 基线校验 + RAR 执行 + DPoP 校验)
3. 概念:[`PROTOCOLS_101.md`](./PROTOCOLS_101.md) §MCP(PRM / introspection / audience 隔离)

### 🚀 我要**部署**(自部署到自己 AWS,或运营 SaaS)

1. [`INSTALL_DEPLOY.md`](./INSTALL_DEPLOY.md) — 工具链、构建产物、`cdk deploy` 两形态、验证、故障速查
2. [`DEPLOYMENT.md`](./DEPLOYMENT.md) — 多租户/issuer/密钥/BYOD/迁移**原理**
3. 部署后:`e2e/` 脚本对着真机跑一遍验收

### 🧭 我要**理解设计 / 参与实现**

1. [`DESIGN.md`](./DESIGN.md) §0–§2 — 设计公理、端点、token 契约(最重要)
2. [`CONFORMANCE.md`](./CONFORMANCE.md) — 每条 MUST/SHOULD + 验收点(实现必对齐)
3. [`../specs/index.md`](../specs/index.md) — 按能力域的落地台账(哪些 done / 在建 / 外部前置)
4. [`CHANGELOG.md`](./CHANGELOG.md) — 公开版本的用户可见变更

### 👤 我是**最终用户 / 管理员**

[`USER_GUIDE.md`](./USER_GUIDE.md) §6(登录/授权管理/账户恢复)、§7(Admin 控制台)。

---

## 4 · 几条一开始就该知道的"红线"

- **只支持 Authorization Code + PKCE**,不支持 implicit / hybrid / ROPC(§0.1 非目标,永久排除)。
- **一个 access token 只对一个 RS**(`aud` 单元素);要访问另一个 RS 得另换一枚。
- **discovery 只宣告已落地能力**,别按"路线图应该有"去调用未实现的端点(会 404)。
- **token 里的 `sub` 可能是 pairwise**(SaaS 默认):RS **不要**反解 `sub`,按 claim 用。
- **workload 信任绑定走管理面登记,不走公开 DCR**(那三档 DCR 面向 public/confidential)。
- 自部署 vs SaaS 差异**只在** issuer 形态、密钥、租户隔离、默认隐私档;线协议一致。

---

## 5 · 目录速查

```text
docs/           决策真相源 + 手册(先看 DESIGN / 本文 / PROTOCOLS_101)
specs/          按能力域组织的公开能力索引(index.md)
crates/         Rust 协议逻辑(纯逻辑 crate + agent-auth-http 上 Lambda)
infra/          AWS CDK(TypeScript,只编排资源,不写业务)
sdk/{python,ts} RS 校验 SDK
web/            前端 SPA(登录/consent/账户/admin)
e2e/            70+ 个真机端到端脚本(也是活文档)
```

下一步:不熟协议 → [`PROTOCOLS_101.md`](./PROTOCOLS_101.md);要接入 → [`USER_GUIDE.md`](./USER_GUIDE.md);要部署 → [`INSTALL_DEPLOY.md`](./INSTALL_DEPLOY.md)。

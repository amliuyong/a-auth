# Agent Auth — 用户手册

> 面向 **接入方**:OAuth/OIDC 客户端开发者、MCP 资源服务器(RS)运维、workload/agent 运维、以及最终用户与管理员。
> 部署/运维见 [`INSTALL_DEPLOY.md`](./INSTALL_DEPLOY.md);协议契约见 [`DESIGN.md`](./DESIGN.md) 与 [`CONFORMANCE.md`](./CONFORMANCE.md)。
> 下文示例 issuer 用 `https://auth.example.com`(自部署)或 `https://t1.saas.example.com`(SaaS 租户);替换成你的实际 issuer。

---

## 0 · Agent Auth 是什么

面向 agent 时代的 OAuth 2.1 / OIDC 授权服务器,核心场景:**agent 代表用户访问第三方 MCP 资源服务器**,并让"哪个 agent、代表哪个用户、访问哪个 RS、在什么委托边界下"可表达、可校验、可观测。

**支持的能力**(以你的 issuer discovery 为准):

- Grant:`authorization_code`(+PKCE)、`refresh_token`、`client_credentials`、`token-exchange`、`device_code`、CIBA。
- 客户端认证:`none`(public+PKCE)、`client_secret_basic`、`client_secret_post`、`private_key_jwt`，以及 workload(`workload_oidc_jwt` / `aws_sigv4_caller_identity` / `spiffe_jwt_svid`;`spiffe_svid_mtls` 仅自部署+P3+开启时,经独立 mTLS 域名)。
- **不支持**:implicit、hybrid、ROPC(OAuth 2.1 基线)。
- PKCE:仅 `S256`。

**第一步永远是读 discovery**(所有端点、能力都在这里如实宣告,未实现的不会出现):

```bash
curl -s https://auth.example.com/.well-known/openid-configuration | jq .
curl -s https://auth.example.com/.well-known/oauth-authorization-server | jq .   # OAuth metadata(与 OIDC 分开)
```

---

## 1 · 快速上手(Authorization Code + PKCE,public client)

最常见的接入:公开客户端(SPA / CLI / 桌面 app / agent),用 PKCE,无 client secret。

### 1.1 确定 client_id(CIMD 优先,DCR fallback)

MCP `2026-07-28` 客户端在与 AS 无预注册关系时优先使用 Client ID Metadata Document。先读两份
discovery；仅当 `client_id_metadata_document_supported:true` 时,把公开 HTTPS metadata URL
直接作为 `client_id`。文档至少包含:

```json
{
  "client_id": "https://client.example.com/oauth/client.json",
  "client_name": "Example MCP Client",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "token_endpoint_auth_method": "none"
}
```

`client_id` 必须与文档 URL 完全相同，使用默认 HTTPS 443 端口，且托管 host 必须在该部署/租户的 allowlist 中。AS 在 authorize
时验证并快照文档，token/refresh 不会重新读取；不要在文档中放 client secret。confidential client
可使用 inline JWKS + `private_key_jwt`。

已有预注册 client 始终优先。CIMD 不可用或客户端不是 URL identity 时,使用保留的 DCR fallback:

```bash
curl -X POST https://auth.example.com/register \
  -H 'content-type: application/json' \
  -d '{
    "redirect_uris": ["https://myapp.example.com/callback"],
    "application_type": "web",
    "token_endpoint_auth_method": "none"
  }'
# → 201 { "client_id": "c_xxx", ... }   (public client 无 client_secret)
```

> 生产环境 DCR 通常凭票注册:请求头带 `Authorization: Bearer <initial_access_token>`(由 AS 运维发放)。若返回全拒,说明该部署要求票据,向运维索取。
> 管理已注册客户端用 RFC 7592:`GET/PUT/DELETE /register/{client_id}`,凭注册时返回的 `registration_access_token`。
> `application_type=web` 必须使用 HTTPS host，且拒绝 localhost 与私有/保留 IP 字面量；桌面/移动 native app 使用 `native`，redirect 仅允许 reverse-domain private-use scheme（如 `com.example.app:/callback`）或 HTTP loopback。

### 1.2 发起授权

生成 PKCE:`code_verifier`(43–128 随机串)→ `code_challenge = BASE64URL(SHA256(verifier))`。

```text
GET https://auth.example.com/authorize?
    response_type=code
  & client_id=c_xxx
  & redirect_uri=https://myapp.example.com/callback
  & scope=openid
  & code_challenge=<challenge>
  & code_challenge_method=S256
  & state=<随机 CSRF 值>
  & resource=https://mcp.example.com        # 可选:目标 MCP RS(RFC 8707),绑定 token audience
```

用户在浏览器完成登录(magic-link / passkey / 上游 IdP)+ consent 后,AS 回跳:

```text
https://myapp.example.com/callback?code=<code>&state=<同上>&iss=https://auth.example.com
```

- **必须校验 `state` 一致**(CSRF);**建议校验 `iss`**(RFC 9207,防混淆授权服务器)。

### 1.3 兑换 token

```bash
curl -X POST https://auth.example.com/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code \
  -d code=<code> \
  -d code_verifier=<verifier> \
  -d redirect_uri=https://myapp.example.com/callback \
  -d client_id=c_xxx
```

返回:

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<opaque>",
  "id_token": "<JWT>",
  "scope": "openid"
}
```

- **access token** = RFC 9068 JWT(`iss` = 你的 issuer,强制 `client_id`,`sub` = 用户,`aud` = 绑定的 `resource`)。
- **id_token** = OIDC(默认 RS256 签名;`aud` = 你的 `client_id`)。
- 用 `jwks.json` 验签:`GET https://auth.example.com/jwks.json`(建议缓存,遇未知 `kid` 再重取)。

### 1.4 刷新(refresh rotation)

```bash
curl -X POST https://auth.example.com/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=refresh_token \
  -d refresh_token=<opaque> \
  -d client_id=c_xxx
```

> refresh token **每次轮换**(旧的作废)。若检测到旧 token 复用,整个 family 被吊销 —— 客户端须始终保存最新返回的 refresh token。

---

## 2 · confidential client(带密钥)

Web 后端等能保密的客户端,注册时选认证方式:

- `client_secret_basic`:注册返回 `client_secret`,`/token` 用 HTTP Basic。按 RFC 6749
  §2.3.1，先分别用 `application/x-www-form-urlencoded` 编码 `client_id` 和
  `client_secret`，再对 `encoded_client_id:encoded_client_secret` 做 Base64。
- `client_secret_post`:注册返回 `client_secret`,`/token` 在 form body 中同时提交
  `client_id` 与 `client_secret`。仅在无法使用 HTTP Basic 的兼容场景选择此方式。
- `private_key_jwt`:客户端保管私钥，AS 只登记 public JWKS；适合避免长期共享 secret 的后端。

```bash
curl -X POST https://auth.example.com/token \
  -u 'c_xxx:<client_secret>' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code -d code=<code> -d code_verifier=<verifier> \
  -d redirect_uri=https://myapp.example.com/callback
```

### 2.1 `private_key_jwt`

注册时必须提供 inline `jwks` 或 `jwks_uri`，两者恰好一个，并把算法 pin 为 `RS256` 或 `ES256`：

```bash
curl -X POST https://auth.example.com/register \
  -H 'content-type: application/json' \
  -d '{
    "redirect_uris": ["https://myapp.example.com/callback"],
    "token_endpoint_auth_method": "private_key_jwt",
    "token_endpoint_auth_signing_alg": "ES256",
    "jwks": {
      "keys": [{
        "kid": "client-key-2026-07",
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "x": "<base64url-x>",
        "y": "<base64url-y>"
      }]
    }
  }'
```

远程模式把 `jwks` 替换为 `"jwks_uri":"https://client.example.com/jwks.json"`。该 URL 必须是
不超过 2048 byte 的 HTTPS 公网地址；服务端拒绝私网解析、代理、重定向、非 443 端口、超大响应、
过多 keys，以及声明 `use:"enc"` 或显式 `key_ops` 却不含 `verify` 的 key。RSA key 限
2048..8192 bit。

每次调用都生成新的 JWT client assertion：

- header:`alg` 等于注册 pin，`kid` 指向登记的 public key；
- claims:`iss` 和 `sub` 都等于 `client_id`；`aud` 精确等于当前端点 URL，例如
  `https://auth.example.com/token`、`https://auth.example.com/revoke` 或
  `https://auth.example.com/sessions/<session_id>`；
- 必须带 `iat`、`nbf`、`exp` 和唯一非空 `jti`；`exp - iat` 不得超过 300 秒；
- 同一个 `jti` 只能使用一次。token、refresh、revoke、introspect、PAR、CIBA、PRM 和 sessions
  之间也不能复用 assertion，因为 `aud` 与 replay 状态均绑定端点。

```bash
curl -X POST https://auth.example.com/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code \
  -d code=<code> \
  -d code_verifier=<verifier> \
  -d redirect_uri=https://myapp.example.com/callback \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=<signed-jwt>
```

轮换 inline JWKS 时先登记新旧两把 key，待所有实例切到新 `kid` 后再移除旧 key。`jwks_uri` 模式可在
远程集合中保持重叠；服务端遇到未知 `kid` 会受限强刷，但客户端仍应留足缓存传播时间。

> RFC 7592 降级(如把 `client_secret_basic` 改成 `none`)需显式确认,防误弱化。

---

## 3 · 无浏览器 / 输入受限设备(Device Flow)

CLI、TV、IoT 等:

```bash
# 1) 设备端拿 device_code + user_code
curl -X POST https://auth.example.com/device_authorization \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d client_id=c_xxx -d scope=openid
# → { device_code, user_code: "WDJB-MJHT", verification_uri, verification_uri_complete, interval, expires_in }

# 2) 提示用户在另一设备打开 verification_uri 输入 user_code(前端 /approve 页)

# 3) 设备端按 interval 轮询 /token(勿快于 interval,否则 slow_down)
curl -X POST https://auth.example.com/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code=<device_code> -d client_id=c_xxx
# pending → authorization_pending;批准后 → 正常 token 响应
```

**CIBA**(后端发起、带外批准)见 discovery 的 `backchannel_authentication_endpoint` 与 `/bc-authorize`;ping/push 部署要求见 [`DEPLOYMENT.md`](./DEPLOYMENT.md)。

---

## 4 · Workload / Service 身份(2LO,无用户)

机器身份(CI、服务、agent runtime)用 `client_credentials`。认证分两类:

1. **受管 workload / agent** 以平台身份认证，**无 client secret**:

- **OIDC-JWT**(如 GitHub Actions OIDC):`client_assertion` = 平台 OIDC token。
- **AWS SigV4**:以调用方 IAM 身份(caller ARN)认证。
- **SPIFFE JWT-SVID**:trust domain 签发的 JWT-SVID 作 `client_assertion`(信任锚 = SVID `sub` 解出的 trust domain)。
- **SPIFFE X.509-SVID / mTLS**:X.509-SVID 作 **mTLS 客户端证书**(不作 `client_assertion` —— 裸证书无 PoP,只走连接层)。经**独立 mTLS 自定义域名** `POST /token`,身份取自握手证书 SAN 的 SPIFFE ID。**仅自部署形态、Phase≥P3、显式开启**时可用(discovery 届时宣告 `spiffe_svid_mtls`);SaaS 逐租户 mTLS 待后续。

这些**信任绑定**由 AS 管理员在管理面登记(平台 issuer/trust domain + subject 模式 → 映射到本 AS 的 workload client_id),**不走 DCR**。登记后(前三种走下面的 `/token` `client_assertion`;X.509-mTLS 走 mTLS 域名、无 `client_assertion`、身份在证书里):

```bash
curl -X POST https://auth.example.com/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=<平台 OIDC/SPIFFE JWT> \
  -d resource=https://mcp.example.com
```

得到的 access token `sub_type=agent`。

1. **纯服务后端**使用 operator 预置 confidential client 的标准 token endpoint auth
   (`client_secret_basic` / `client_secret_post` / `private_key_jwt`)。该 client 必须在受控
   ClientStore 置备中显式配置 `allowed_resources` 2LO policy；公开 DCR 与当前 Admin client
   表单都会让该字段保持为空，因此不能启用此 grant:

```bash
curl -X POST https://auth.example.com/token \
  -u 'svc-backend:<client-secret>' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=client_credentials \
  -d resource=https://mcp.example.com \
  -d scope=kb:read
```

服务 token 的 `sub_type=service`；两类 2LO token 都令 `sub=client_id`、跨 RS 恒定且不做 pairwise。
**委托**(agent 代表用户,`act` 链、`auth_grant`、token-exchange 换发)见 `DESIGN.md §5`。

---

## 5 · MCP 资源服务器(RS)接入

你的 RS 要校验 Agent Auth 签发的 access token:

1. **发布 PRM**(Protected Resource Metadata,RFC 9728):告诉客户端"我信任哪个 AS"。可让 AS 代管:`GET https://auth.example.com/rs/prm?...`(或由 RS 自行发布)。
2. **校验每个入站 token**:
   - 签名:用 AS 的 `jwks.json`(按 `kid` 选公钥,缓存 + 未知 kid 重取)。
   - `iss` = 预期的 AS issuer;`aud` = **你自己的 resource 标识**(一个 token 只对应一个 audience —— 不接受为别的 RS 签的 token)。
   - `exp`/`nbf` 时间窗;需要时 `client_id`、`sub_type`、`act`(委托链)按你的策略断言。
3. **可选:introspection**(不透明校验或吊销状态):`POST /introspect`(需 RS 凭证)。

> 关键隔离不变量:**access token 受 `resource` 绑定,一个 token 只有一个 audience** —— 客户端为 RS-A 拿的 token 不能拿去访问 RS-B。

### 5.1 Enterprise-Managed Authorization (EMA,可选)

当两份 discovery 同时含
`authorization_grant_profiles_supported=["urn:ietf:params:oauth:grant-profile:id-jag"]`
与 JWT bearer grant 时，预注册的 confidential MCP client 可把企业 IdP 获取的 ID-JAG 放在
`assertion` 中换 token：

```bash
curl -X POST https://auth.example.com/token \
  -u 'ema-client:<client-secret>' \
  -H 'content-type: application/x-www-form-urlencoded' \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion='<ID-JAG>' \
  -d resource=https://mcp.example.com \
  -d scope='mcp:read'
```

成功响应只含 RFC 9068 access token，并回显批准的 `resource`/`scope`；不含 refresh token 或
ID token。client 凭据与 ID-JAG 是两个独立认证/授权输入，ID-JAG 不能放进
`client_assertion`。EMA 不会把 email 自动关联到本地账户，也不是上游 IdP 浏览器登录或 RFC 8693
`subject_token`/`actor_token` 委托。未宣告 EMA 时不要发送该 grant。

EMA v1 不提供 refresh token。ID-JAG 只能在其自身 `exp` 前兑换；已签发 access token 的
`expires_in` 当前固定为 900 秒。离线验签的 RS 无法获知之后发生的 ID-JAG、用户或策略撤销，
因此最坏情况下会继续接受该 access token 直至其 `exp`。当前 `/introspect` 对 EMA token
同样只按签名与 `exp` 判断有效性，尚未连接 EMA 用户或策略的在线撤销权威；不要把它当作缩短
这 900 秒窗口的机制。

---

## 6 · 最终用户

作为登录 Agent Auth 的人类用户,你会遇到:

- **magic-link 登录**:输入邮箱 → 收到一次性登录链接(短命、绑定发起浏览器,防 login-CSRF)→ 点击回到应用。
  - 同一浏览器打开才生效(异浏览器打开会被拒);链接 ≤10 分钟、一次性。
  - 本地用户默认禁止自注册。只有 Admin 已预置的邮箱才会实际收到链接;未知/禁用/已删除邮箱得到同样的通用响应,但系统不会发信或创建用户。
  - 内部用户 ID 为 `user:{归一化邮箱}`;SaaS 下用户按租户隔离,不会出现在其他租户的列表中。
- **passkey**(若部署开启):登录页与 magic-link 共用一个 email 输入框;日常登录优先使用设备生物识别 / 安全密钥(WebAuthn),也可改发邮箱登录链接。首次直接登录后若尚未配置 passkey,`/account` 会醒目提示添加,但可选择稍后设置。
- **上游 IdP 登录**(若部署开启联邦):用企业 IdP / 社交账号登录。
- **email / 密码**:Admin 创建用户时设置初始密码。首次密码登录必须先设置新密码,完成前不会建立登录会话;之后可用新密码登录。密码只以 Argon2id 哈希存储,管理面不会回显密码或哈希。
- **consent 同意页**:首次授权某客户端访问某资源时,你会看到"谁请求、访问什么、什么范围",确认后才签发。
- **账户恢复**:遗失登录方式时用恢复码(`/recovery/*`);恢复即触发通知(安全事件告知本人)。
- **管理自己的会话 / 授权**:见前端 `/account`(登录会话)与 `/grants`(授权记录,可自助吊销)。

> 前端页面(企业级、中英文 i18n、path 可 bookmark):`/login`、`/consent`、`/approve`(device/CIBA 批准)、`/account`、`/recover`,均可深链。

---

## 7 · 管理员(Admin 控制台)

管理面与用户会话**独立**(不同鉴权域),凭 **admin token**(bearer)访问 `/admin/*`:

```bash
# 取 admin token(从栈输出解析,不硬编码)
ADMIN=$(STACK=AgentAuthDev ./e2e/get-admin-token.sh)
curl -s https://auth.example.com/admin/overview -H "authorization: Bearer $ADMIN" | jq .
```

能力(前端 `/admin` 页 + API):

| 端点 | 用途 |
|---|---|
| `GET /admin/overview` | 概览:phase / issuer / 端点 / client_count / 活跃会话数 |
| `GET/DELETE/PATCH /admin/clients[/{id}]` | 客户端管理(按 client_id/redirect/resource 搜索;列表不回 secret;删除级联吊销 refresh) |
| `.../admin/users[...]` | 人类用户管理(按 email/user_id 搜索;默认列表隐藏已删除用户;可筛选未删除/正常/已禁用/已删除/全部;创建本地用户并设初始密码;为本地用户重置临时密码;查/禁用/删除本地与联邦用户;墓碑仍可在“已删除/全部”视图审计;本地用户不开放自注册) |
| `GET /admin/messages` | 发信 outbox 观测(magic-link / recovery,SES 未接前的模拟) |
| `POST /admin/workload-trust` · `GET /admin/workload-trust/{tenant_id}` | 登记/列 workload 信任绑定(§4) |
| `.../admin/federation[...]` | 上游 IdP 联邦配置(按 tenant 隔离) |

> **多租户注意**:SaaS 下 admin API 按**请求的租户子域**隔离 —— 在 `t1.<zone>` 上的 admin 操作只见 t1 的数据;控制面 Host `c.<zone>` 上调 AS/admin 端点会 400(它不是租户 issuer)。
>
> **可深链管理视图**:`/admin` 的 tab、搜索与用户状态筛选保存在 query 中,例如 `/admin?tab=users&user_q=alice`、`/admin?tab=users&user_status=tombstoned`、`/admin?tab=clients&client_q=mcp`;可 bookmark、刷新并使用浏览器前进/后退。省略 `user_status` 即默认“未删除”(Active + Disabled)。admin token 仍只放 `sessionStorage`,不会进入 URL。

---

## 8 · 常见问题

| 问题 | 解答 |
|---|---|
| 我该用哪个 issuer? | 自部署 = 你的域;SaaS = 你的租户子域 `t{N}.<zone>`。**永远以 discovery 的 `iss` 为准**,别硬编码平台域。 |
| `/authorize` 报 "未知 client" | client 是在**另一个 issuer/租户**注册的 —— 每个租户是独立分区,client_id 不跨租户共享。 |
| token 拿去访问 RS 被拒 401 | `aud` 不匹配:token 是为别的 `resource` 签的。发起授权时带正确的 `resource=`。 |
| refresh 后旧 token 报错 | 正常 —— refresh 每次轮换,只用最新那个;别并发用同一 refresh token。 |
| discovery 里没有某能力 | 该部署的 `AGENT_AUTH_PHASE` 未开到那一档,或功能开关未启;能力**如实宣告**,没宣告就是没启用。 |
| private claim 命名空间 | `https://a-auth.com/c`(云无关永久标识符,不随部署域名变);见 `DESIGN.md §2`。 |

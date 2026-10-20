# 场景接入指南

当前租户的 `/admin?tab=onboarding` 提供 MCP Server、Agent/CLI 和 workload
代表用户三条路径。页面用现有租户 Admin read 权限读取当前 issuer、phase、
注册客户端与实际 discovery；不新增管理 API 或授权协议。

## 配置已有对象

1. MCP Server：选择已绑定资源的 RS 注册，或填写实际 HTTPS 资源标识与 scope。
   独立示例提供 PRM、401 发现和受保护 MCP 工具；在线检查使用绑定该资源的
   `client_secret_basic` introspection 客户端。
2. Agent/CLI：选择 public、未要求 DPoP 的客户端。Code + PKCE 使用已注册
   loopback 回调；device flow 只有实际 discovery 宣告后才能选择。
3. workload：选择未要求 DPoP 的 actor-only workload，填写自己的租户 ID 并读取
   已有 OIDC 信任。其主体模式、平台 issuer 与映射 actor 必须来自实际平台。
   不根据 Host 猜测租户，也不把信任注册当作用户已批准委托。

配置只序列化所选公开字段；不会复制 Admin API 的完整对象、client secret、
cookie、token 或私钥。语言切换保留配置，重新加载失败会清除旧配置。能力、
必要注册或匹配的信任缺失时，不生成可运行配置。未支持的 DPoP 配方不会
通过去掉证明要求来“运行”。

## 执行完整路径

按照[独立示例](../examples/onboarding/README.md)复制项目、安装标准 MCP/OAuth
库与实际 RS SDK 产物，再将控制台配置写入本地 `config.json`。SDK registry
发布仍依赖 #79；公开安装为 NOT_RUN 时使用经过资格验证的本地 tarball，
不能把源码导入冒充独立安装。
当前示例选择 `agent_auth_rs@1.0.2`；安装前核对该版本的资格验证及 registry
回读记录。[1.0.2 发布记录](releases/rs-sdk-1.0.2.json)中的 Python wheel/sdist
公开安装已通过，但 npm 尚未发布；这个 Node.js 示例的公开安装仍为 NOT_RUN。
下方 1.0.1 记录是历史验收，不能替代 1.0.2 的发布结果。

MCP Server 的公网 resource 必须是实际 HTTPS 调用地址。内部 HTTP listener
置于 HTTPS 反向代理之后；PRM 与 MCP 路径均须映射正确。仅在 loopback 上用
HTTPS audience 做直接 HTTP 测试，是本地可控验证，不是公网 MCP 发现互操作。

AWS 部署一律禁用 Lambda Function URL，包括 `AWS_IAM` 模式。Lambda 的
受保护 HTTP 路径使用带鉴权的 API Gateway 或 ALB，或通过 AWS SDK Invoke；
第三方工具和模板也必须遵守这个约束。

若 API Gateway 的 stage 前缀改变了公开元数据路径，在示例配置中显式填写
`resource_metadata_url`，并将该 HTTPS 地址映射到 PRM。示例的 401 challenge
会宣告这个地址；PRM 中的 `resource` 仍须与实际受保护调用地址精确一致。
未指定时使用 RS SDK 的标准派生路径。issuer、resource 和元数据地址均拒绝
Lambda Function URL。

CLI 命令依次完成 discovery、code + PKCE 或已宣告 device flow、正常用户登录、
consent、公开客户端兑换、私密凭据保存和受保护 MCP 工具调用。它使用标准
oauth4webapi 和官方 MCP SDK，没有新增独立 client SDK。刷新仅由原客户端
执行，旋转凭据原子提交；响应不明时保留 UNKNOWN 并停止自动重试。
需要刷新时，CLI 应在首次授权前请求 `offline_access`（如 `read offline_access`），
并确认当前部署宣告 refresh grant、响应包含 refresh token；服务器自己的
业务 scope 配置仍可为 `read`。没有 refresh token 的会话须重新授权。

workload 路径必须先经真实 HTTP 注册、信任绑定与带 actor 的明确 consent。
新鲜平台 JWT 认证 workload，新鲜用户 token 提供 subject authority，随后进行
一级 exchange 和不缓存正结果的认证 introspection。没有编辑数据库、Grant、
JTI 或 refresh family 来获得委托权限的步骤。

## 判定与记录

首次接入的记录应覆盖：配置/注册、安装、启动与 PRM、授权与 consent、兑换、
调用和拒绝检查。命令输出阶段与实测秒数；记录总体开始到第一次成功工具调用
的耗时及失败点。成功的 listener、打包、code 兑换和业务调用各有自己的状态。

必须从最终安装 SDK/独立示例检查错误 issuer/audience、scope 不足、未授权
actor 和 Grant 吊销后的失败。篡改未签名的 JWT 只证明签名被拒，不代表独立
验证了 issuer/audience。用户在 `/account` 吊销自己的 Grant 后，刷新/exchange
与委托 token 在线检查失败；离线 JWT 可能到期前仍有效，业务取消由消费方负责。

证据绑定源 SHA、SDK 制品摘要、运行版本和日期，分别记录本地可控环境、AWS
可控集成与真实外部平台。未执行的分支保持 NOT_RUN；不把模拟 JWKS/平台身份
称为真实平台互操作，也不以 CI 豁免替代运行结果。

相关契约：[workload consent](WORKLOAD_CONSENT.md)、
[入门](GETTING_STARTED.md)、[RS SDK 分发 PR #94](https://github.com/amliuyong/a-auth/pull/94)、
[企业 OIDC 模板](FEDERATION_TEMPLATES.md)。

## 受控验收记录

2026-10-20 使用 `rs-sdk-v1.0.1` 对应的 `agent_auth_rs@1.0.1` 独立 tarball，
SDK 来源为 `0c461abca125893b3133bf82d2af1d138589b966`，
SHA-256 为 `898e0a76b2eec0aeb7344b30b2144a3a5fa8d421c158986faad3d44b86bc3212`。
MCP SDK 为 1.31.0，oauth4webapi 为 3.8.8，Node.js 为 22.23.3。
这份记录绑定当时的依赖版本。当前配方已升级 MCP SDK 至 1.32.0；历史 AWS
结果不能作为新版本的 AWS 验收，补丁验证见[依赖补丁记录](DEPENDENCY_PATCHES.md)。

| 层次 | 结果 | 覆盖及边界 |
| --- | --- | --- |
| 本地受控 TLS AS 与独立 MCP 示例 | 17 PASS | 同一受控签名密钥下的错误 issuer/audience、scope、proof-bound 拒绝、在线不可用及 metadata challenge |
| AWS API Gateway 与 JWT authorizer | PASS | Lambda 无 Function URL；两条业务方法有鉴权；调用策略仅限指定 API；公开 PRM 为静态响应 |
| AWS 真实 HTTP 授权与调用 | 66 项检查、11 次配方执行 PASS | 注册、密码登录、PKCE、device、刷新、actor consent/exchange、受保护调用及拒绝、吊销 |
| 吊销边界 | PASS | 同一已吊销且未过期 JWT：AWS 在线入口 401，本地回环离线 MCP 调用成功 |
| Web 生产包 | 131 PASS | 包含中英文、移动视图、复制、权限失败及既有登录/consent/账户回归 |
| npm 公开 registry 安装 | NOT_RUN | 等待 #79；上述独立安装使用资格验证的 tarball |
| 真实外部 workload/IdP 平台 | NOT_RUN | AWS 平台证明使用本次生成、HTTP 注册信任的受控签名身份 |

在 AS、网关和依赖已准备好的条件下，从本次真实注册开始到第一次成功受保护
调用的实测墙钟时间为 60.099 秒。该值不包含部署、安装或寻找配置的时间，
不是首次用户接入耗时的基准。每条配方另记阶段与耗时，原始失败记录保留。
开发服务器回归曾因浏览器 `ERR_NETWORK_CHANGED` 导致模块加载失败；生产包
完整回归通过。SSO 测试回调改为当前测试服务的 origin，避免验证另一个端口。

临时用户、客户端、HTTP 创建的信任、私密文件、AWS 测试栈与缓存均完成清理
回读。原始记录及最终源文件/SDK 制品摘要保留在交付证据目录，未提交实际
凭据或部署标识。

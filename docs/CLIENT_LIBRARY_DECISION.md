# Agent / CLI 客户端库决策

2026-10-20，针对 #88。当前选择 **(a) 保留配方**。不新增客户端包或公开
生命周期 API；(b) 通用 OAuth 库之上的薄扩展是后续候选，(c) 独立客户端库
目前不推进。本文件完成决策，不代表客户端库已可用。

## 决策输入

输入为 #80 的最终配方提交
[`1133a2d390cb34990accd0e690aefb14c402e7d5`](https://github.com/amliuyong/a-auth/tree/1133a2d390cb34990accd0e690aefb14c402e7d5/examples/onboarding)。
这是已审查的源文件，公开 npm 安装验收仍依赖 #79。运行使用 Node.js
22.23.3、oauth4webapi 3.8.8、官方 MCP SDK 1.31.0 和独立安装的
`agent_auth_rs@1.0.1` 资格验证 tarball。

下表统计物理行数，包含注释和空行，用于界定维护面；不把行数等同于安全
复杂度。CLI 五条命令合计 242 行，共用 61 行内部辅助代码。MCP server
107 行属于资源服务器侧，不计入新增客户端协议实现。

| 文件 | 行数 | 接入方仍负责的部分 | 已交给现有库的部分 |
| --- | ---: | --- | --- |
| `pkce.mjs` | 78 | 回环 listener、超时、用户 consent 提示、私密保存 | state 校验、S256 PKCE、discovery、code 兑换 |
| `device.mjs` | 42 | 轮询调度、`slow_down`、到期、私密保存 | device 请求与响应处理 |
| `exchange.mjs` | 46 | 平台证明输入、actor/resource/subject 参数、委托响应限制 | 标准 token HTTP 请求与响应处理 |
| `refresh.mjs` | 42 | 原客户端绑定、互斥锁、原子提交、UNKNOWN 停止 | refresh 请求与响应处理 |
| `call.mjs` | 34 | 选择私密凭据、检查受保护响应中的 actor | MCP 初始化、工具调用与连接关闭 |
| `runtime.mjs` | 61 | 公共配置、端点限制、私密文件、脱敏结果 | OAuth discovery 响应验证 |

配置、discovery、保存和错误输出已在示例内部集中。每条路径仍有一次命令
生命周期编排，但没有重复实现签名、JWT 校验或 OAuth 响应解析。平台 JWT
由实际平台提供，示例不签发 workload 身份。AWS SigV4、SPIFFE JWT-SVID、
mTLS 证明获取和客户端 DPoP 生成/nonce 重试不在这组配方中，均为 NOT_RUN；
不能由 bearer 路径成功推导它们已被客户端库支持。

受控 TLS 17 项 PASS；带鉴权 API Gateway 的真实 HTTP 授权和受保护 MCP
调用为 66 项检查、11 次配方 PASS。PKCE、device、刷新和显式 actor
consent/exchange 均有实际调用结果。平台签名身份是 HTTP 注册信任的受控
身份，真实外部 workload/IdP 为 NOT_RUN。离线与在线撤销边界另有实测：
同一已撤销且未过期 JWT，在线拒绝，离线可接受至到期。

观察到的失败点及责任如下：

| 失败点 | 记录与处理 | 对客户端库决策的影响 |
| --- | --- | --- |
| 网关 stage 改变 PRM 路径 | 受控测试先 404，配置实际 metadata URL 后通过 | 保持公开地址配置与 401 challenge 一致；不是新增 OAuth 协议 |
| 未请求 `offline_access` | 不应期待 refresh token；指南明确首次授权前请求 | 需要可操作提示，不能替客户端静默增加 consent |
| actor 未授权、错误 audience/scope | 实际 HTTP 拒绝；不发新凭据 | 展示失败阶段，不放宽 AS/RS 校验 |
| Grant 撤销 | 后续 exchange/refresh 和在线调用失败 | 不承诺离线即时撤销或取消业务动作 |
| 请求结果不明 | refresh 保留锁和 UNKNOWN，不自动重试旧 token | 当前锁只互斥，不是 singleflight 或跨进程恢复服务 |
| 浏览器开发服务器网络变化 | 保留失败记录；生产包完整浏览器回归 131 PASS | 属于引导 UI 验证，不能作为客户端协议缺陷证据 |

UNKNOWN 处理由代码审查确认；没有实际注入丢失 refresh 响应，也没有完成
并发轮换/宽限重放验证，相关客户端能力保持 NOT_RUN。

## 三种形态的比较

| 形态 | 维护面与 SemVer 承诺 | 安全责任 | 当前判断 |
| --- | --- | --- | --- |
| (a) 配方 | 固定依赖、可复制命令；不新增公开客户端 API | 调用方负责平台证明、部署秘密和生产存储；示例明确边界 | 当前采用，已覆盖三条目标路径 |
| (b) 薄扩展 | 少量公开 helper，但须维护 OAuth 库兼容、参数和错误类型 | 所有权绑定、证明重试、并发与日志合同仍需完整验证 | 候选；等待真实消费者和 #89 互操作缺口 |
| (c) 独立客户端库 | TS/Python 生命周期、适配器、存储和平台矩阵的长期 SemVer | 另承担凭据恢复、钥匙串、私钥生命周期和跨进程一致性 | 当前不推进；现有数据不足以支撑维护面 |

现有重复主要是示例编排，已通过内部 helper 收敛。提前公开这些 helper 会
产生 API 和安全合同，却不会自动补齐系统钥匙串、DPoP 或平台证明。先完成
Issue #89 的真实客户端测量，再以独立消费者需要复用的相同逻辑为依据重新评估。
本次不拆客户端实施 issue，不新增 AS 协议或修改 token/撤销语义。

## 重新评估时的实施门槛

若后续选择推进 (b) 或 (c)，必须先拆独立实施 issue，注明 TS/Python 范围、
维护者和与 #79 同等的来源/tag/制品/registry 安装发布路径。未经发布验收
不得宣告任何新客户端包可用。以下是未来必需合同，当前均未实现：

- 以 issuer、原 client、resource、refresh family 和 DPoP key 标识并发域；
  同进程调用合并为一次实际轮换，跨进程由持久锁和原子凭据提交协调。
  吊销或确定性拒绝不得回退到旧 token。
- 丢失响应须保持 UNKNOWN。只有 AS 已有、受限的完全相同请求宽限合同
  才允许恢复；超窗、换 client/resource/key 或重复旧凭据必须停止。
- 系统钥匙串作为显式存储适配器；文件存储须明确权限、原子替换与恢复
  合同。Token 与 DPoP 私钥不进入 URL、日志、错误正文或遥测。
- DPoP 私钥由调用方受控存储保管；nonce 按经过验证的 AS/RS 端点隔离。
  仅处理明确 nonce challenge 的有界重试，每次生成新 proof；不循环重发。
- 错误映射要区分用户拒绝、未授权 actor、超出 exchange 深度、配置不符、
  AS 不可用与 UNKNOWN，提供重新授权或修复配置等实际操作提示。
- 验收须覆盖并发只轮换一次、宽限内相同请求重放和超窗拒绝、DPoP nonce
  重试/私钥绑定、未授权 actor/超深度 exchange 拒绝、凭据不写日志。

现有 RS SDK 的 DPoP proof 校验器是资源服务器能力，不是客户端 proof
生成器。当前 `.session.json` 私密保存和 refresh 锁也不等于上述生产合同。

相关契约：[workload consent](WORKLOAD_CONSENT.md)、
[SDK 分发](https://github.com/amliuyong/a-auth/issues/79)、
[场景引导](https://github.com/amliuyong/a-auth/issues/80)、
[真实 MCP 互操作](https://github.com/amliuyong/a-auth/issues/89)。

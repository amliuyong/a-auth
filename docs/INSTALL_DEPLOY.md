# Agent Auth — 安装部署手册

> 面向**运维 / 部署工程师**的实操手册:如何把 Agent Auth 从源码构建、部署到 AWS,并验证。
> 决策/架构原理见 [`DESIGN.md`](./DESIGN.md) 与 [`DEPLOYMENT.md`](./DEPLOYMENT.md)(本文只讲**怎么做**,不复述**为什么**)。
> 面向终端用户 / 客户端接入方的操作见 [`USER_GUIDE.md`](./USER_GUIDE.md)。

---

## 0 · 部署形态一览

同一套代码,两种交付形态(由环境变量选择,不分叉):

| 形态 | issuer | 租户 | 典型栈名 | 关键 env |
|---|---|---|---|---|
| **自部署(单租户)** | 客户自有域(如 `https://auth.acme.com`) | 1 | `AgentAuthDev` | 默认(不设 `AGENT_AUTH_FORM`) |
| **SaaS(多租户)** | 每租户子域 `https://t{N}.<zone>` | N | `AgentAuthSaas` | `AGENT_AUTH_FORM=saas` + `AGENT_AUTH_ZONE` + `AGENT_AUTH_CONTROL_HOST` + `AGENT_AUTH_ENABLE_TENANT_PARTITIONING=1` |

- 自部署 = "租户数为 1 的特例",数据面租户前缀为空,行为与不分区**字节等价**。
- SaaS 控制面 `c.<zone>` **不是 issuer**——只承载控制面,不暴露 `/authorize`、`/token`、discovery(请求控制面 Host 的 AS 端点会 fail-closed 返回 400)。

---

## 1 · 前置条件

### 1.1 本机工具链

| 工具 | 版本(验证过) | 用途 |
|---|---|---|
| Rust | 1.96+ | 编译协议逻辑(`crates/`) |
| `cargo-lambda` | 最新 | 交叉编译 Lambda 产物(`provided.al2023` arm64) |
| `zig` | 0.17+ | `cargo-lambda` 的交叉链接后端 |
| Node.js | 22+ | CDK(TypeScript)+ 前端(Vite/React) |
| AWS CDK CLI | 2.11x+ | `npx cdk`(仓库 `infra/node_modules` 已带,无需全局装) |
| AWS CLI v2 | 最新 | 部署身份 / 取栈输出 / DynamoDB 播种 |

安装 cargo-lambda(若缺):

```bash
cargo install cargo-lambda        # 或 pip install cargo-lambda / brew install cargo-lambda
```

### 1.2 AWS 账号与身份

- 用 profile **`default`**(IAM user `work`),region **`us-east-1`**(所有资源都在此区)。
- 动手前确认身份:

```bash
aws sts get-caller-identity --profile default --region us-east-1
```

- **账号号绝不写进 repo**;需要时从上面命令取,或放本地 `.env`(已 gitignore)。

### 1.3 首次:CDK bootstrap(每账号/每区一次)

```bash
cd infra
npm ci                             # 装 CDK 依赖(首次)
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --profile default --query Account --output text)
export CDK_DEFAULT_REGION=us-east-1
npx cdk bootstrap aws://$CDK_DEFAULT_ACCOUNT/us-east-1 --profile default
```

### 1.4 ⚠️ 环境区域污染

若 shell 预置了 `AWS_REGION=us-west-2`(或别的区),会劫持部署区域。**每次开新 shell 都显式导出**:

```bash
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 CDK_DEFAULT_REGION=us-east-1
```

---

## 2 · 构建产物

### 2.1 Rust Lambda(主服务 + 后台任务)

```bash
cd <repo-root>
./scripts/build_lambda_artifacts.sh
```

八个产物落到 `target/lambda/<binary>/bootstrap`。凭据迁移、security-event archive、SSF
delivery、tenant-key provisioner 与 governance worker 产物是必需项；CDK 入口缺失时会直接失败，避免静默跳过历史
凭据迁移、部署一个无法归档的 security-event 表、宣告 SSF 却没有投递 worker，或让 SaaS tenant
永远停在未置备状态。reclaim/recompute 仍由对应 feature 配置决定是否创建调度任务。
脚本只接受干净 worktree，并为八个 bootstrap 分别写入绑定完整 Git commit 和对应二进制
SHA-256 的 `deployment-provenance.json`。所有 CDK 部署都会拒绝调用者 commit、Git HEAD、
任一待部署 manifest commit 或 bootstrap SHA-256 不一致的产物；stack 输出和运行时
`AGENT_AUTH_DEPLOYMENT_COMMIT` 只使用验证后的 manifest commit。部署后 live gate 还会独立核对
migration 与 governance worker 的 manifest。

凭据迁移会删除历史 plaintext，属于不可逆 contract 步骤。迁移 Lambda 对 Clients 表执行强一致全表扫描，因此也覆盖已从当前域名配置移除但仍保留数据的历史 tenant；结束前若任一行仍含 `client_secret` 或 `reg_token_hash`，Custom Resource 会失败。CDK 将迁移 Lambda 放在业务栈，但把触发它的 Custom Resource 放在独立 `AgentAuth*CredentialMigration` 栈。必须先等待业务栈 `UPDATE_COMPLETE`，再单独部署 migration 栈；不得用一次 `cdk deploy --all` 合并这两个阶段。

构建 migration 二进制只是为了让同一个 CDK app 能合成升级栈，不代表每次都要部署该栈。
**全新环境的 Clients 表没有历史 plaintext，不部署
`AgentAuthDevCredentialMigration`/`AgentAuthSaasCredentialMigration`。** 只有从旧版升级且
确认存在 `client_secret` 或 `reg_token_hash` 历史字段时，才在主栈稳定后单独部署对应
migration 栈；完成后日常主栈发布仍不得再次带上它。

client authority reference 是可回滚的 expand migration，但同样必须在业务栈稳定后单独执行。
所有 CDK app 部署现在都必须显式设置完整 40 位小写
`AGENT_AUTH_DEPLOYMENT_COMMIT`；不再接受 `unversioned`，否则不同发布或回滚会错误复用旧 coverage。
首次升级到 `client-authority-refs-v1` 时，对应 Region 的
`AgentAuth*AuthorityReferenceMigration` 会等待旧 Code/Refresh mutator 全部排空，强一致回填
Region-local reference 表，再发布 coverage marker。该 Custom Resource 使用可续跑的 async
provider：每次 invocation 只处理有界 page，并把 phase/cursor 以 CAS checkpoint 写入 reference
表；控制面重试不会从头扫描。marker 缺失期间 reclaim 会 fail closed，不会把 GSI 未命中误当成
“无活跃引用”。marker 同时绑定 schema 与完整 deployment commit；新 Reclaim、回滚版本或
serving/migration 分阶段窗口看到其他提交的 marker 时同样 fail closed。全新环境也必须运行该
migration 以发布空表 coverage。migration resource 绑定完整 deployment commit，因此每次部署新的
authority writer commit 后都必须单独部署对应 migration 栈；同一 ID 的控制面重试恢复既有
checkpoint/完成状态，不会撤 marker 或从头扫描。迁移 Lambda 每次调用还会读取自身当前 Lambda
控制面配置，并在首次异步控制面读取前记录 invocation 起始时间；状态切换以该单调起始序做 CAS，
因此回滚后迟到的旧 execution environment 无法重新撤销新 coverage。每个 CloudFormation
`RequestId` 还会与状态切换同事务写入不可复用 marker，at-least-once 重放只能恢复既有
checkpoint。合法 rollback 可以原子 supersede 与 CloudFormation predecessor 匹配的未完成
migration，避免超时 checkpoint 阻塞恢复。live gate 会强读 coverage、durable complete
checkpoint 和当前提交的 request marker。若只是重复部署同一 commit，CloudFormation 不会重复
执行。不要与业务栈放进同一次 `cdk deploy --all`。

### 2.1.1 C3.4 grace CMK 与 token runtime cutover

首次从旧单体 Auth Lambda 升级到独立 TokenFn/NonTokenFn 时，必须先生成绑定当前完整 commit
的八个 Lambda 产物，再执行不可逆 cutover：

```bash
export AWS_PROFILE=default
export REGION=us-east-1
export STANDBY_REGION=us-west-2
export EXPECTED_COMMIT="$(git rev-parse HEAD)"

./scripts/build_lambda_artifacts.sh
PREFLIGHT_ONLY=1 ./e2e/grace_kms_cutover.sh
./e2e/grace_kms_cutover.sh
```

正式 cutover 会识别 Dev、SaaS primary 与 standby 的旧 grace key 和 Grace/CIBA 表，禁用三地
legacy grace key，并等待所有仍依赖旧 key 的未过期密文连续稳定归零。它不删除协议数据，也绝不
重新启用旧 key。`prepared` state 默认写入 `/var/tmp` 并绑定 exact commit；此后旧单体模板的
`/token` 只能 fail closed。**不要通过重新启用 legacy key 回滚**，只能连续完成新 serving 与
authority-reference migration 部署，或修复后 roll forward。

三地必须依次完成 serving 栈与对应 Region-local authority-reference migration；SaaS standby
参数继续从 primary stack outputs 生成，不能猜物理资源名或重建已 offboard tenant 的 Secret。
所有栈达到 `UPDATE_COMPLETE` 后运行：

```bash
EXPECTED_COMMIT="$(git rev-parse HEAD)" ./e2e/grace_kms_isolation.sh
```

该 gate 会把 cutover state、三地实际部署包、Lambda scope、IAM simulation、legacy/current
KMS 状态、direct-invoke 路由隔离和一次真实 refresh grace replay 绑定到同一 commit。它还要求
GraceTable 只含审核过的密文字段，并在临时 client/user/Grant/refresh/grace 状态连续稳定缺席后
才发布脱敏 PASS evidence。

### 2.2 前端 SPA(可选,CDK 默认一并部署)

```bash
cd web
npm ci
npm run gen:api          # 从 openapi/openapi.json 生成 TS 类型(契约先行)
npm run build            # 产物落 web/dist/,CDK 上传到 S3+CloudFront
```

> 前端与 API 是**同源统一入口**:CloudFront default behavior → API Gateway,静态页(`/`、`/login`、`/consent`、`/account`、`/approve`、`/admin`、`/recover`、`/error`)→ S3。`__Host-` cookie / CSRF 因此天然正确。

### 2.3 本地验证(部署前,无需 AWS)

```bash
cargo test -p agent-auth-http                    # 默认套件(内存适配器,byte-identical 基线)
cargo test -p agent-auth-http --features aws --no-run   # 确认 AWS 适配器编译
cargo clippy -p agent-auth-http --features aws --all-targets
```

---

## 3 · 部署 A:自部署单租户栈(`AgentAuthDev`)

### 3.1 无自定义域名(最快,用 CloudFront 默认域)

```bash
cd infra
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --profile default --query Account --output text)
export CDK_DEFAULT_REGION=us-east-1
export WEB_BASE_URL=https://<cloudfront-domain>
npx cdk deploy AgentAuthDev --profile default --require-approval never
npx cdk deploy AgentAuthDevAuthorityReferenceMigration --exclusively \
  --profile default --require-approval never
# 仅旧 Clients 表仍有历史 plaintext 时执行：
npx cdk deploy AgentAuthDevCredentialMigration --exclusively \
  --profile default --require-approval never
```

部署输出含 `ApiUrl`(API Gateway)、`FrontendSpaUrl`(CloudFront 默认域 `*.cloudfront.net`)、
`AdminUrl`(可直接打开的管理台地址)与 `AdminTokenCommand`(可直接执行的 AWS CLI 取 token 命令)。
`AdminTokenCommand` 只包含 Secret ARN,不会把 token 明文写进 CloudFormation output。

`WEB_BASE_URL` 是必填的公开统一入口 origin,也是 SelfHosted issuer 的权威 host。magic-link callback、
Discovery、`/authorize`、`/token` 与发起登录时写入的 `__Host-agent_auth_login_nonce` cookie 必须同源；
裸 `*.execute-api.*.amazonaws.com` 会在 synth 和服务启动时被拒绝。API Gateway 只作为 CloudFront 回源,
不作为公开 issuer。

首次创建尚不知道 CloudFront 域名时,仍需用
`WEB_BASE_URL=https://bootstrap.invalid` 完成第一次部署,从栈输出取得 `FrontendSpaUrl` 后立即设置真实值
并第二次部署;不要在临时值下发起登录。`ApiUrl` 只用于调用/诊断,无需复制回环境变量。

### 3.2 带自定义域名(生产推荐)

前置:该域名的 Route53 hosted zone + **us-east-1 的 ACM 证书**(CloudFront 约束证书必须在 us-east-1)。

```bash
export CUSTOM_DOMAIN=auth.acme.com
export CUSTOM_DOMAIN_CERT_ARN=arn:aws:acm:us-east-1:<account>:certificate/<id>
export CUSTOM_DOMAIN_ZONE_ID=<Z...>
export CUSTOM_DOMAIN_ZONE_NAME=acme.com
export WEB_BASE_URL=https://auth.acme.com
npx cdk deploy AgentAuthDev --profile default --require-approval never
npx cdk deploy AgentAuthDevAuthorityReferenceMigration --exclusively \
  --profile default --require-approval never
# 仅旧 Clients 表仍有历史 plaintext 时执行：
npx cdk deploy AgentAuthDevCredentialMigration --exclusively \
  --profile default --require-approval never
```

CDK 会挂 CloudFront 别名 + Route53 A/AAAA alias 指向 distribution。

### 3.3 可选功能开关(env,默认关 = fail-closed)

| env | 作用 | 生产建议 |
|---|---|---|
| `AGENT_AUTH_PHASE` | 发布阶段 `p0`..`p3`(决定哪些端点/grant 可达 + discovery 如实宣告) | `p2`(缺省)或按上线范围 |
| `AGENT_AUTH_DCR_MODE=initial_access_token` | SelfHosted DCR 凭票注册；部署后从 Admin 控制台签发 tenant-scoped IAT | 公网生产建议；无可用 IAT 时注册 fail closed |
| `AGENT_AUTH_FEDERATION_ENABLED=1` | 上游 IdP 联邦(`/federation/callback` 可达) | 需真上游 IdP 时 |
| `AGENT_AUTH_PASSKEY_ENABLED=1` | passkey 5 端点可达(4 个仪式端点 + 会话鉴权状态端点) | 需 WebAuthn 时 |
| `AGENT_AUTH_CIMD_ENABLED=1` | 在 P1+ 启用 MCP Client ID Metadata Document resolution 与 discovery 宣告 | 仅与 `AGENT_AUTH_PHASE=p1\|p2\|p3` 及下述非空精确域名 allowlist 同批启用 |
| `AGENT_AUTH_CIMD_ALLOWED_DOMAINS=host1,host2` | SelfHosted/SaaS 部署级 CIMD host allowlist；不接受 scheme/path/端口/通配/IP | 只列受信客户端元数据托管域 |
| `AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS='{"t1":["host"]}'` | SaaS 逐租户 CIMD host allowlist；key 必须属于已配置租户 | 租户信任不同客户端域时使用 |
| `AGENT_AUTH_CIBA_PING_PUSH_ENABLED=1` | CIBA ping/push 投递 | 需时 |
| `AGENT_AUTH_EMA_ENABLED=1` | AgentAuthDev 开 Stable MCP EMA；须同时提供 policy file/JSON | 完成真实企业 IdP 验收后按租户启用 |
| `AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER=1` | ⚠️ **仅 dev/e2e**:`login_user` 占位登录 | **生产 MUST 不设** |

`AgentAuthDev` 的 DCR 档与占位登录彼此独立:默认可动态注册客户端,但不会因此放开
`login_user` 占位认证。`AgentAuthSaas` 不继承该 open DCR 默认,Stack 构造期禁止部署级 DCR
和占位登录配置；各租户通过自己的 Admin Host 签发 IAT。

CIMD 与 DCR 互不替代部署护栏:CIMD 属 P1 能力，P0/P0.5 不执行、不宣告且 CDK 拒绝启用；
预注册 client 最高优先；未知且 allowlisted 的 URL-form client ID
走 CIMD；其它客户端继续使用 DCR fallback。CIMD client URL 仅允许默认 HTTPS 443 端口；fetch 固定到
连接前验证的公网 DNS 地址，并限制 tenant+host 出站速率、进程内并发、重定向、总时限和 5 KiB 文档
大小，不应把 allowlist 配成开放 Internet。上线时先带 allowlist synth，
再打开 gate 部署，最后从两份 discovery 确认字段出现并跑 `e2e/cimd.sh`。默认 live fixture
托管在公开 GitHub gist 的 `gist.githubusercontent.com`；仓库内
`e2e/fixtures/cimd-client.json` 是其版本化 canonical copy，部署 allowlist 必须显式包含该 host。

IAT 不再从 Secrets Manager 明文集合加载。Admin 控制台的“初始访问票据”页签发后只回显一次
`iat_<id>.<secret>`；DynamoDB 台账只保存不可逆 verifier 与 owner/scope/expiry/rate-limit/one-time
元数据。轮换时先签发新票据并迁移调用方，再显式吊销旧票据，不需要重新部署 Lambda。

EMA 建议使用文件配置，避免 shell quoting：

```json
[
  {
    "tenant": "default",
    "policy": {
      "policy_id": "enterprise-idp",
      "trusted_issuer": "https://login.example.com/tenant/v2.0",
      "issuer_tenant": "tenant",
      "jwks_uri": "https://login.example.com/tenant/discovery/keys",
      "allowed_algorithms": ["RS256"],
      "authenticated_client_id": "ema-client",
      "assertion_client_id": "enterprise-mcp-client",
      "resources": [
        {
          "resource": "https://mcp.example.com",
          "scopes": ["mcp:read"]
        }
      ],
      "allow_legacy_missing_resource": false,
      "max_assertion_lifetime_secs": 300,
      "allowed_clock_skew_secs": 30
    }
  }
]
```

SelfHosted 的 `tenant` 固定为 `default`；SaaS policy 使用 `t1` 等已登记租户标签。先只设置
`AGENT_AUTH_EMA_POLICIES_FILE`（SaaS 用 `SAAS_EMA_POLICIES_FILE`）部署并验证配置，再设置
`AGENT_AUTH_EMA_ENABLED=1`（SaaS 用 `SAAS_EMA_ENABLED=1`）重部署。CDK/runtime 会拒绝空数组、
非法 policy、重复 lookup key、未知租户、`phase<p2` 或缺 replay/JTI 依赖。严格 Stable 与真实
IdP 验收必须保持 `allow_legacy_missing_resource=false`。CDK 会把 policy 规范化后写入专用
Secrets Manager 配置 Secret，Lambda 环境仅保存其 ARN，避免触发 4 KiB 环境变量上限。

真实外部验收对 Dev 与一个 SaaS tenant 各运行一次 `e2e/ema_external.sh`。所需环境变量与
IdP acquisition command/RS verifier 契约见脚本头部；client secret 只允许从
`EMA_CLIENT_SECRET_FILE` 读取。该 gate 使用无 `cnf` 的 Bearer profile，DPoP/cnf 组合由
进程内 C13.4 自动化覆盖。CDK 从当前 Git `HEAD` 派生完整 commit，写入 CloudFormation
`DeploymentCommit` output 与 Auth Lambda `AGENT_AUTH_DEPLOYMENT_COMMIT`；若显式提供
`AGENT_AUTH_DEPLOYMENT_COMMIT`，它必须与 `HEAD` 相等。开启 EMA 的 synth 还会拒绝 dirty
worktree，并核对构建 manifest 的 commit 与 bootstrap SHA-256。验收脚本直接从 CloudFormation
和 Lambda 读取部署包与配置 Secret，交叉验证 commit、AWS CodeSha256、bootstrap SHA-256、
active function 状态、EMA flag 与实际 policy，再生成非敏感 policy attestation 及其 SHA-256；
调用者不能自报这些证据。实际 policy 必须绑定
tenant/issuer/client/resource/scopes 并关闭 `allow_legacy_missing_resource`。RS 还须提供同一
resource 下的正向 route 与一个要求未授予 scope 的 403 route；同一正向请求在无 token 时须
返回 401。脚本只输出绑定部署、脚本 commit、UTC 与产品版本的脱敏 JSON。

若当前没有可用的第三方 ID-JAG issuer，可先部署透明模拟器完成可重复的全链自动化验收：

```bash
cd infra
set -a; source ../.env; set +a
npx cdk deploy AgentAuthEmaSimulator \
  --app "npx ts-node --prefer-ts-exts bin/ema-simulator.ts" \
  --profile default --require-approval never
```

该 app 从 `EMA_SIMULATOR_AGENT_AUTH_ISSUERS` 读取允许的 Dev/SaaS issuer；未显式设置时从
`WEB_BASE_URL` 和 `SAAS_ZONE` 派生 Dev 与 `t1`。它独立创建 Cognito User Pool、测试用户密码
Secret、broker Secret、ES256 KMS key、ID-JAG issuer API 和 bearer-protected RS API。
`e2e/ema_simulator_acquire.sh` 从 stack outputs/Secrets Manager 获取 Cognito ID token，再经
authenticated token exchange 取得一次性 ID-JAG。运行 `e2e/ema_external.sh` 时必须同时设置
`EMA_EVIDENCE_KIND=simulator` 与 `EMA_SIMULATOR_STACK=AgentAuthEmaSimulator`。该 evidence
只证明模拟链路，不能勾选真实第三方 IdP/client interoperability；用完可独立 `cdk destroy`，
不会删除 AgentAuthDev/AgentAuthSaas 数据。

> 密钥(签名 CMK、`SERVER_SECRET`、平台 admin credential-set target)由 CDK 自动创建。首次升级保留
> 旧 `AdminToken` source 不变并复制同一 bearer，保证旧模板可回滚。Admin bearer 明文不进入新
> Lambda env；运行时只按 target ARN 读取并以 30 秒 TTL 刷新。轮换见
> [`ADMIN_CREDENTIAL_ROTATION.md`](ADMIN_CREDENTIAL_ROTATION.md)。

---

## 4 · 部署 B:SaaS 多租户栈(`AgentAuthSaas`)

SaaS 栈是**独立栈**(全新表集,与自部署栈零共享),仅当设置 `SAAS_ZONE` 时才实例化 —— 纯自部署时不受影响。

### 4.1 通配证书(覆盖全部租户子域)

一张 `*.<zone>` 证书覆盖 t1/t2/…/c 及未来所有租户:

```bash
export AWS_REGION=us-east-1
# 1) 请求证书(DNS 验证)
ARN=$(aws acm request-certificate --domain-name '*.saas.example.com' \
  --validation-method DNS --profile default --region us-east-1 \
  --query CertificateArn --output text)
# 2) 取验证 CNAME 并写进 Route53(Name/Value 从 describe-certificate 拿)
aws acm describe-certificate --certificate-arn "$ARN" --profile default --region us-east-1 \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord'
#    → 用 aws route53 change-resource-record-sets UPSERT 该 CNAME
# 3) 轮询到 ISSUED
aws acm describe-certificate --certificate-arn "$ARN" --profile default --region us-east-1 \
  --query 'Certificate.Status' --output text     # 期望 ISSUED
```

### 4.2 部署 SaaS 栈

```bash
cd infra
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --profile default --query Account --output text)
export CDK_DEFAULT_REGION=us-east-1

export SAAS_ZONE=saas.example.com                       # 托管区
export SAAS_CONTROL_HOST=c.saas.example.com             # 控制面(非 issuer)
export SAAS_DOMAINS="t1.saas.example.com,t2.saas.example.com,t3.saas.example.com,c.saas.example.com"  # 保留已 offboard 的 t2 标签
export SAAS_CERT_ARN=$ARN                             # 上面的通配证书
export SAAS_ZONE_ID=<Z...>                            # hosted zone id
export SAAS_ZONE_NAME=saas.example.com
export SAAS_WEB_BASE_URL=https://c.saas.example.com
export SAAS_TENANT_ADMIN_SECRET_ARNS='{"t1":"<t1-admin-token-Secret-ARN>","t2":"<t2-admin-token-Secret-ARN>","t3":"<t3-admin-token-Secret-ARN>"}'
export SAAS_TENANT_SUBJECT_TYPES='{"t3":"public"}'          # 未列的 t1 使用 pairwise 隐私默认
export SAAS_REDIRECT_PREFIX_ALLOWED_HOSTS='{"t1":["callbacks.example.com"]}' # 可选；缺省/空值关闭 prefix
export SAAS_OFFBOARDED_TENANTS=t2                          # 不重置 t2；仅允许其已删除 target 被 migration 识别
export AGENT_AUTH_DEPLOYMENT_COMMIT=$(git -C .. rev-parse HEAD)

npx cdk deploy AgentAuthSaas --profile default --require-approval never
npx cdk deploy AgentAuthSaasAuthorityReferenceMigration --exclusively \
  --profile default --require-approval never
# 仅旧 Clients 表仍有历史 plaintext 时执行：
npx cdk deploy AgentAuthSaasCredentialMigration --exclusively \
  --profile default --require-approval never
```

第一条命令建全新表集 `AgentAuthSaas-*`、挂 3 子域到同一 CloudFront + Route53 alias、Lambda env 设 `FORM=saas`/`ENABLE_TENANT_PARTITIONING=1`。确认该栈 `UPDATE_COMPLETE` 后，第二条命令回填 Region-local active authority reference 并发布 coverage；第三条仅在旧 Clients 表仍有历史 plaintext 时执行不可逆凭据迁移。任一 migration 栈失败都不会把业务栈回滚到旧 Auth 代码。租户 issuer 由入站 Host 经 CloudFront `ForwardHost` Function 透传 `X-Forwarded-Host` 派生。SaaS 全路由在使用该值前验证 origin-request Lambda@Edge 从 Secrets Manager 读取并覆盖注入的双槽 credential；distribution 配置不保存 secret，裸 API Gateway 即使伪造有效租户 Host 也只返回 `403 untrusted_origin`。凭据轮换和 live 验收见 [`SAAS_ORIGIN_AUTH.md`](./SAAS_ORIGIN_AUTH.md)。

`SAAS_WEB_BASE_URL` 同样必填且必须是 CloudFront 自定义域 origin,不能填写裸 API Gateway URL。

`SAAS_TENANT_ADMIN_SECRET_ARNS` 必须为每个租户绑定**不同的 legacy source Secret ARN**，供首次升级
复制已有 bearer；栈会为每个 tenant 新建独立 owner-bound credential-set target。source 不改写，
target 承载 current/next/retired 并由 warm runtime 自动刷新。这些凭据仅能管理对应 Host。栈输出
`AdminSecretArn` 是 SaaS 平台控制面凭证,只用于 `c.<zone>/admin`,绝不能分发给租户管理员或用于
租户 Host；该 output 指向 target，不是 legacy source。

`SAAS_TENANT_SUBJECT_TYPES` 是逐租户 OIDC subject profile。只允许 `public` 或 `pairwise`；
未列出的 SaaS 租户使用隐私默认 `pairwise`。SelfHosted 不接受该映射，SaaS 也不接受旧的
fleet-wide `AGENT_AUTH_SUBJECT_TYPE`，避免配置看似生效却被逐租户 resolver 忽略。

`SAAS_REDIRECT_PREFIX_ALLOWED_HOSTS` 是逐租户、版本化的 redirect-prefix host allowlist。
值为 JSON object，key 必须属于 `SAAS_DOMAINS` 的租户标签，value 为精确 host 数组；
不接受 scheme、port、path、通配符、IP 字面量、重复规范化 host 或跨租户借用。
缺省或空 object 会关闭全部 `prefix` 注册。SelfHosted 使用
`AGENT_AUTH_REDIRECT_PREFIX_ALLOWED_HOSTS='["callbacks.example.com"]'`，其配置映射到
bootstrap 的 `default` profile。即使 host 已允许，client 仍须为 confidential web client，
redirect URI 仍须是无 query/fragment、以 `/*` 结尾的 HTTPS URL；DCR、Admin 与 RFC 7592
共享同一写入前校验，`exact` 改为 `prefix` 仍须 `confirm_downgrade:true`。

`SAAS_OFFBOARDED_TENANTS` 只列正式完成 offboarding、owner-bound admin/SCIM target Secret
已进入删除终态的租户。它必须是当前 `SAAS_DOMAINS` 租户集合的子集；migration 仅对这些
owner 的 Secrets Manager `Removed` 结果执行幂等跳过。`Unavailable`、活跃租户 target
缺失、平台凭证和 stage 漂移仍 fail closed。该配置不得用于取消删除、重建 target 或重新启用 issuer。

> **加租户**不是只加 DNS：在 `SAAS_DOMAINS` 增加单层标签
> (`t3.saas.example.com` 可，`a.t3.saas.example.com` 不可)，同时为该租户添加独立
> `SAAS_TENANT_ADMIN_SECRET_ARNS` source、`SAAS_TENANT_RESIDENCY` 和可选
> `SAAS_TENANT_SUBJECT_TYPES`；按 primary serving → primary authority migration →
> standby serving → standby authority migration 顺序部署，再经 tenant-key control API
> 执行 EC+RSA key ensure 并等待 JWKS ready。通配证书已覆盖时无需新证书。
> 当前 `t3` 是长期保留的 conformance tenant，用于 C1.1b/C9.4/C10.14 持续回归；
> 已永久 offboard 的 `t2` 不得重置或复用。

### 4.3 与自部署栈并存 / 回滚

`AgentAuthDev` 与 `AgentAuthSaas` 表集完全独立。client/DCR 与 authority-reference migration 栈通过 CloudFormation export
引用对应业务栈的 handler；销毁业务栈前先销毁同名 migration 栈。Admin source→target migration
位于业务栈内并先于 AuthFn，Delete 是 no-op，不改写 source 或把 target 解包回明文。例如：

```bash
npx cdk destroy AgentAuthSaasCredentialMigration --force --profile default
npx cdk destroy AgentAuthSaasAuthorityReferenceMigration --force --profile default
npx cdk destroy AgentAuthSaas --force --profile default
```

因此 SaaS 出问题仍可独立拆除，SelfHosted 栈不受影响(D6 回滚保证)。

---

## 5 · 部署后验证

### 5.1 discovery(逐 issuer 如实宣告)

```bash
# 自部署
curl -s https://auth.acme.com/.well-known/openid-configuration | jq .issuer
# SaaS 租户(各自 issuer 互异)
curl -s https://t1.saas.example.com/.well-known/openid-configuration | jq .issuer   # → https://t1.saas.example.com
curl -s https://t3.saas.example.com/.well-known/openid-configuration | jq '{issuer,subject_types_supported}'
# → issuer=https://t3.saas.example.com, subject_types_supported=["public"]
# SaaS 控制面 MUST 拒(非 issuer)
curl -s -o /dev/null -w '%{http_code}\n' https://c.saas.example.com/.well-known/openid-configuration  # → 400
```

### 5.2 端到端 e2e 脚本(沉淀在 `e2e/`,70+ 个)

```bash
# SaaS 多租户隔离(11 断言:逐子域 issuer + 跨租户 client/code 隔离 + 租户内 happy-path)
ZONE=saas.example.com AWS_PROFILE=default ./e2e/saas_multi_tenant.sh

# 单栈能力(示例;各脚本头部有用法与所需 env)
API_URL=https://auth.acme.com CLIENTS_TABLE=<cdk ClientsTableName> AWS_PROFILE=default ./e2e/code_flow.sh
```

### 5.3 取 Admin token(登录 `/admin` 或跑 admin e2e)

```bash
# 从栈输出解析 Secrets Manager ARN 再取明文(不硬编码 secret-id)
# SaaS 栈输出对应平台控制 token,只登录 https://c.<zone>/admin
STACK=AgentAuthSaas ./e2e/get-admin-token.sh
STACK=AgentAuthDev  ./e2e/get-admin-token.sh          # 自部署

# SaaS 租户 target ARN 从平台只读目录取得,只登录对应 https://tN.<zone>/admin
PLATFORM_TOKEN="$(STACK=AgentAuthSaas ./e2e/get-admin-token.sh)"
TENANT_TARGET_ARN="$(
  curl -fsS "https://$SAAS_CONTROL_HOST/admin/control/tenants" \
    -H "authorization: Bearer $PLATFORM_TOKEN" |
    jq -er '.tenants[] | select(.tenant_id == "t1") | .admin_secret_arn'
)"
aws secretsmanager get-secret-value \
  --secret-id "$TENANT_TARGET_ARN" \
  --query SecretString --output text | jq -er '.current.secret'
```

### 5.4 Data-governance live drill (Issue #30)

该演练只允许在 `configured-account/us-east-1` 的 `AgentAuthSaas` 上运行，并要求 clean local HEAD 与栈的
`DeploymentCommit`、恢复栈 commit 完全一致。它会 erase t1 的隔离用户，并永久 offboard 明确标记为
disposable 的 t2；不要对承载真实租户的栈运行。

首次执行默认在提交幂等 erasure retry 后以状态 `75` 主动中断。机器或 shell 重启后使用打印的
`RUN_ID` 续跑；状态默认保存在 `~/.agent-auth-data-governance-drills/<RUN_ID>/`。bearer 与
governance HMAC key 只进入进程级 `0600` 临时文件，不写日志或持久化 state。
运行该脚本的 profile 还必须有 `cloudtrail:LookupEvents`，用于把每个
product-managed Secret 的 `DescribeSecret.DeletedDate` 请求时间绑定到准确的
`DeleteSecret` 七天恢复窗口和响应 deadline。

```bash
AWS_PROFILE=default REGION=us-east-1 \
  CONFIRM_DISPOSABLE_TENANT=t2 \
  ./e2e/data_governance_drill.sh

RUN_ID=<first-run-id> AWS_PROFILE=default REGION=us-east-1 \
  CONFIRM_DISPOSABLE_TENANT=t2 \
  ./e2e/data_governance_drill.sh

# 续跑期间如双栈升级，先从新部署的 clean exact commit 显式记录过渡。
ACTION=adopt-deployment RUN_ID=<run-id> \
  DEPLOYMENT_TRANSITION_REASON='<change or incident reference>' \
  AWS_PROFILE=default REGION=us-east-1 \
  ./e2e/data_governance_drill.sh

# 只读查看进度；cleanup 也只操作该 RUN_ID 记录的 fixture。
ACTION=status RUN_ID=<run-id> AWS_PROFILE=default REGION=us-east-1 \
  ./e2e/data_governance_drill.sh
ACTION=cleanup RUN_ID=<run-id> AWS_PROFILE=default REGION=us-east-1 \
  ./e2e/data_governance_drill.sh
```

`adopt-deployment` 不改写初始 context。它只接受同一 StackId、主备 commit
一致、Git 祖先关系向前且除 commit 字段外输出完全不变的部署，并原子追加带原因和
前后 output hash 的 lineage 记录。旧 schema 的 standby 完整输出通过回填旧 commit
重算原 hash 来验证；不能重构时拒绝续跑。服务 evidence 的 commit 也必须位于初始和
当前 adopted commit 之间。

脚本对 DynamoDB、S3、AWS Backup、KMS、Secrets Manager、CloudWatch Logs、SQS、SSF
和 immutable evidence 的 Region/count/deadline 逐项 fail-closed。只有
`retention_pending`、缺少 recovery point、缺少服务 evidence 字段或云侧生命周期无法验证时都不会
产生成功 evidence。

---

## 6 · 运维备忘

- **cdk-nag**:栈已过 `AwsSolutionsChecks`(`cdk synth` 时跑);改基础设施后须保持通过再部署。
- **client 回收任务**(`ReclaimFn`,EventBridge 每日调度):默认 **dry-run**(只扫描报数);真启用须显式 `AGENT_AUTH_RECLAIM_ENABLED=1`。
- **审计**:授权会话状态迁移经 EventBridge 投影到 CloudWatch Logs(`AuthzAuditLog`,保留 6 个月)。
- **安全事件**:认证、用户状态、凭据、Admin、Grant、key/secret 与跨租户拒绝写
  `SecurityEventsTable`(热留存 400 天)；持续写失败时，worker 依据 SQS receive count 重试
  原消息，四次失败后写 FIFO terminal DLQ。DynamoDB Stream 从 `TRIM_HORIZON` 归档 S3
  2555 天，archive 对象和 Athena schema 同时保留事件及最终 delivery history，
  S3 四次失败后经 durable pending outbox 把完整记录写入不自动消费的 FIFO terminal DLQ；
  原生 Stream 重试耗尽的完整 invocation 另存 retained S3 并触发终态回填。
  Glue database/table 显式保留资源级 Lake Formation `IAM_ALLOWED_PRINCIPALS`
  `ALL`（`Super`）兼容授权且不带 grant option；实际 Athena API 与对象访问仍须同时满足
  调用方 IAM 与 archive bucket policy。
  `GET /admin/security-events` 按最新优先查询当前 tenant 的热数据和投递状态。完整契约见
  [`SECURITY_EVENTS.md`](SECURITY_EVENTS.md)。
- **发信**:当前 magic-link / recovery 通知落 DynamoDB `messages` 表模拟(`GET /admin/messages` 可观测),**未接真实 SES**(出 sandbox 需 AWS 审批,属手动前置)。
- **密钥**:签名走 KMS CMK(EC ES256 access + RSA RS256 id_token);`SERVER_SECRET` 与 admin
  credential sets 在 Secrets Manager。Admin 正常/泄露轮换、rollback 与 warm refresh 见
  [`ADMIN_CREDENTIAL_ROTATION.md`](ADMIN_CREDENTIAL_ROTATION.md)。
- **拆栈**:`npx cdk destroy <StackName> --profile default`。security-event 热表与归档桶明确
  `RETAIN`，即使 Dev 拆栈也不会自动删除；其余资源按各自 removal policy 处理。

---

## 7 · 故障速查

| 症状 | 可能原因 | 处理 |
|---|---|---|
| discovery/authorize 报 "bad host" | 栈仍是旧模板或自定义域配置不一致 | 确认 Lambda 的 `AGENT_AUTH_HOST` 来自当前 API endpoint/`CUSTOM_DOMAIN`,重新 synth + deploy |
| 资源部署到了错误区域 | shell 预置 `AWS_REGION` 污染 | 每次显式 `export AWS_REGION=us-east-1`(§1.4) |
| SaaS 租户 discovery 返 400 | 请求的是控制面 Host(`c.<zone>`)或非租户子域 | 控制面非 issuer;租户须用 `t{N}.<zone>` |
| SelfHosted DCR `/register` 全拒 | 已启用收紧档，但当前 tenant 没有有效 IAT，或票据已过期/吊销/消费 | 使用该 tenant 的 Admin 控制台签发新 IAT；无需重新部署 |
| SaaS DCR `/register` 全拒 | 对应 tenant 尚无有效 IAT，或请求误发到 control Host | 从该 tenant 的 Admin Host 签发 IAT，并向该 tenant issuer 的 `/register` 提交；不得使用跨租户共享票据 |
| ACM 证书一直 PENDING_VALIDATION | 验证 CNAME 未进 Route53 | 把 `describe-certificate` 给的 CNAME UPSERT 到 zone |
| `cdk deploy` 找不到 Lambda 产物 | 未先 `cargo lambda build` | 先执行 §2.1 |
| 部署 SaaS 却动了 dev 栈 | 只有 SAAS 栈应受 SaaS env 影响 | bin 已隔离;确认只 `cdk deploy AgentAuthSaas` |

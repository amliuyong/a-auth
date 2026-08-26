# Agent Auth — 部署与多租户实现说明

> 本文承载 **SaaS 多租户置备 / 密钥在线迁移 / 跨形态升级** 等**实现与运维细节**,从 `DESIGN.md` 抽出以保持协议内核的可读性(见 DESIGN.md §0.5 与 §11 #11)。
> 协议内核(端点/token/委托/MCP 集成)看 `DESIGN.md`;两形态的**语义/信任模型对照**看 DESIGN.md §0.5;本文只讲**怎么落地**。
> 引用约定:`§x` 指 DESIGN.md 的节。

---

## 0 · 部署域名(具体事实)

**issuer 是 per-deploy/per-tenant 配置,不是硬编码常量**(我们 SaaS 的 hosted zone **`saas.example.com` 已创建**,通配证书 `*.saas.example.com` + CloudFront 通配 alt name):

- **【自部署】issuer = 该栈的公开 AS 域名**。生产带自定义域时使用客户配置域(如 `https://auth.customer.example`),无自定义域时使用 CloudFront 默认域；两者都承载全部 AS 端点(单租户)。CDK 必须把已校验的 `WEB_BASE_URL` host 作为 `AGENT_AUTH_HOST` 注入所有运行时 Lambda；API Gateway 仅为 CloudFront 回源,不得成为公开 issuer,也不得回落 `localhost`。制品绝不硬编码我们的 `*.a-auth.com`。
- **【SaaS】`https://c.saas.example.com` = 我们的 control-plane / 文档示例 origin**(`c`=control)——**不是任何租户的 issuer,也不作为 AS 对外签发**:只承载控制面 API(租户开通/下线/计费/管理)与无租户上下文的落地页,**不暴露 OAuth/OIDC AS 端点**(无 `/authorize`、`/token`、AS discovery、签名 JWKS)。**刻意如此**——否则会冒出第三种"平台 issuer"形态(其 `subject_types`/签名 key/DCR 均无定义)。真正的签发只发生在两类 issuer:【SaaS】租户 issuer(`t{N}...`)或【自部署】客户域。文档里出现的 `c.saas.example.com` 仅作示例/落地 origin,不代表它是活的 AS。
- **【SaaS】租户 issuer = `https://t{N}.saas.example.com`(每租户子域)**(§0.5/§11 #3)。**discovery/JWKS/cookie 隔离/RFC 9207 `iss` 一律按"请求 Host 对应的租户 issuer"口径**——`iss`=`https://t{N}.saas.example.com`、JWKS 是该租户 CMK、cookie host-only 绑该子域。**绝不能把 `c.saas.example.com` 当某租户 issuer 校验**(会串租户)。
- **实现口径(写死,防 discovery/校验分叉)**:AS 按**入站 Host** 决定 issuer——【SaaS】Host=`t{N}.saas.example.com`→租户 issuer、Host=`c.saas.example.com`→控制面;【自部署】Host=客户配置域→该单栈 issuer。每个 issuer 的 discovery 只宣告自己那套。
- **【SaaS】DCR 当前部署护栏**:`AgentAuthSaas` Stack **MUST 拒绝**部署级 `dcrMode` 和 `login_user` 占位配置；数据面缺省进入 `initial_access_token` 档。每个租户只能由自己的 Admin Host 在线签发 tenant-scoped IAT，记录只保存带 pepper verifier、scope、固定过期、限速、一次性和吊销状态；没有可用票据时 `POST /register` fail closed。IAT 使用独立 ledger，不伪装成 current/next 集合：轮换先签发固定过期的 replacement，旧票据只在自身到期或显式吊销前并行有效；验证 replacement 失败时吊销 replacement 回滚，验证成功后吊销旧票据收口。不得恢复 fleet-wide 共享票据，否则任一泄露会扩大到所有租户。
- **CIMD 部署护栏**:CIMD 属 P1 能力，只有 `AGENT_AUTH_PHASE=p1|p2|p3` 时才可执行和宣告；CDK 会拒绝在 P0/P0.5 启用。`AGENT_AUTH_CIMD_ENABLED=1` 还要求 `AGENT_AUTH_CIMD_ALLOWED_DOMAINS` 或 `AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS` 至少含一个精确 host 才可 synth/启动；SaaS 还必须开启 tenant partitioning，tenant policy key 必须属于 `SAAS_TENANTS`。allowlist 不支持通配、IP、URL path 或端口。关闭 gate 时 discovery 字段缺失；配置策略但不打开 gate可用于分阶段上线。
- ⚠️ **与 claim 命名空间区分**:JWT 私有 claim 的命名空间是 **`https://a-auth.com/c`**(§2),是**云无关的永久标识符、不解析、不随部署域名变**——换云/换 issuer 域名它不变(否则所有已发 token + RS SDK 校验全断)。故命名空间**不**用任何 `*.saas.example.com`。
- 🔴 **onboarding 必问:`subject_types` 选 public 还是 pairwise(§11 #12,P0 锁、不可回改,两形态都要问)**:
  - **【自部署】默认 public**(首方 RS 跨 RS 关联);但**若未来可能连第三方 MCP RS,起步就选 pairwise**——否则 public 的可关联 `sub` 会泄露给第三方,且锁死改不回。
  - **【SaaS】默认 pairwise**(头号场景连第三方 RS,隐私默认);但**允许企业租户 opt-in 覆盖为 public**(自家多个首方 RS 要关联同一用户时)——opt-in 需风险披露且"仅纯首方 RS 场景适用",一旦连第三方 RS 就不该选 public。**按租户独立、写进该租户 issuer 的 discovery**,不影响 fleet 内其他租户。
  - 两形态**各有形态默认值**(自部署 public / SaaS pairwise,见上),但**"有默认值"不等于"可以靠默认蒙混"**:因为选择 **P0 锁死、不可回改**,此问必须在 onboarding **显式提出、让客户明确确认或改写默认**(即"不留隐式默认"——不是没有默认值,而是不允许在客户没意识到后果的情况下静默采用默认)。确认/改写后写进该部署(SaaS 为该租户)issuer 的 discovery `subject_types_supported`,与 token 签发口径一致。

---

## 1 · 多租户隔离怎么落地(已定的推荐路径)

隔离分**两个平面**,分开决策:

- **数据平面(每请求)**:请求进来 → 定位租户 → 用 `tenant_id` 去 scope 数据 / 选签名 key / 定 issuer。
- **控制平面(租户生命周期)**:开通/下线租户时置备或回收其所需资源。

**判据(一句话)**:数据平面**永远只读已提交运行时快照**;依赖外部副作用、慢确认或时间窗的控制面
必须异步编排。当前有两类:**逐租户 KMS key lifecycle**(EC+RSA 原子置备、readiness probe、失败补偿、
publish-ahead/overlap)与 **BYOD 自带域名的证书/DNS**。`CreateKey` 单次调用虽同步返回，但完整 key
set 生命周期绝不是一个请求内的同步事务。

**推荐路径(守住"单一内核不分叉")**:

1. **数据平面从 P0 就做成纯运行时配置**——`tenant_id` 贯穿 DynamoDB 分区键、签名 key 选择、issuer/Host 路由。
   这一步是**"【自部署】= 租户数为 1 的特例"能成立的物理保证**:同一套代码,自部署时配置里只有一个租户。
2. **SaaS 起步基线(onboarding 由 durable control-plane worker 编排)**:
   - 数据 → 逻辑分区(分区键前缀,非独立表/账号);
   - 密钥 → **每租户独立 key set(EC+RSA 两把 signing MRK primary,非一把;见下方⚠️为何是基线而非"可推迟档"、及成本/配额重算)**:onboarding 每租户执行两次 `CreateKey(multi_region=true)`，并在每个配置备用区执行 `ReplicateKey`；只有两种算法在 primary 和全部 replica 区都完成本区 `GetPublicKey`、真实 `Sign` 与本地 `Verify`，并由同一次 registry CAS 发布后，该 tenant 才 ready。该租户 JWKS 只含自己的公钥,跨租户伪造在**密码学上不可能**。任一算法或任一区域失败必须补偿已创建 primary/replica，且未完成的 tenant 对数据面保持 503，绝不发布半套 key set;
   - 路由 → **通配子域 + 通配证书**(`*.saas.example.com` 一张证书 + CloudFront 通配 alt name,新租户不新增 AWS 资源)。**已定为子域模型、非 path 多租户**——cookie host-only 隔离、WebAuthn `rp_id`、issuer=Host 路由都依赖子域;path 路由下这套隔离论证会整个塌(见 DESIGN §11 #3)。
     通配符只覆盖**一层标签**(`t1.saas.example.com` 可,`a.t1.saas.example.com` 不可)——扁平命名够用,但排除未来嵌套命名空间。
     **纯规模维度上通配方案可无限扩展**:`*.saas.example.com` 在 CloudFront 备用域名列表里**只占一个条目**,底下挂多少租户子域都不再消耗配额。规模从不是问题——只有租户**要求自带品牌域名(BYOD)**才逼出第 3 步。
   ⚠️ **为什么逐租户 CMK 就是基线,而非"先 claims 级、后升级"**:
   - **KMS 非对称 CMK 不能"派生子密钥"**——KMS 只有对固定 keypair 的 Sign/Verify 和"生成全新无关联 keypair"的 `GenerateDataKeyPair`;**非对称 Sign 也没有可被验签方核验的 signing context**(encryption context 只作用于 encrypt/decrypt)。故"一把根 key 派生逐租户子密钥 / 签名上下文带 `tenant_id`"**在 KMS 上根本不存在**,不是一个可选档。
   - 推迟 CMK 的理由也大多不成立:`CreateKey` 单次调用同步返回、CMK 配额充裕(**默认 10 万/region、可提额**)、成本低。生命周期仍须由下述 durable worker 编排，但**没有理由不从第一天(= SaaS 上线首日,项目 P2/P3)就给每租户一套 key set**。
     🔴 **规模/成本按"每租户一套 key set(不是一把 CMK)"重算(建模口径,独立于实查配额)**:每个租户 issuer 是 **EC(ES256)+ RSA(RS256)两把 signing CMK**——**两把从 P0 起都必需**(EC 签 access;**RSA 签默认 RS256 ID token,OIDC 默认、P0 必需**,DESIGN §2/§8;RSA 的理由是 ID token,不是算法分流——分流是 P3 可选,别误删 RSA),轮换重叠期临时到 **≤4 把**。故前面用"每租户 1 把"估的数**都要按 key set 大小(稳态 2× / 重叠期峰值 4×)重算**:
       - **成本**:~$1/key/月 × 2 = **~$2/租户/月**(轮换重叠期短暂 ~$4);1 万租户 ≈ **~$2 万/月** + Sign 调用费(非早前的 ~$1 万)。
       - **单区租户天花板**:region 的 CMK 数上限(默认 10 万)被 key set 摊薄——稳态 2 把/租户 ⇒ **~5 万活跃租户**即撞上限(轮换重叠期峰值更低,~2.5 万);不再是 ~10 万。
       - **置备速率**:onboarding 每租户要 **2 次 `CreateKey`**(EC+RSA),有效租户置备速率 = `CreateKey` 配额(~5/s)**减半到 ~2.5 租户/s**。
     ⚠️ **删除等待期不是"无害"**:CMK 删除有 7–30 天等待期,**pending-deletion 的 key 仍计入账号 key 配额**直到真正删除。高租户流失率(churn)下 offboarding 频繁翻动时,**churn × 删除窗口 × key set 大小(2–4 把/租户)** 的在途 key 会与下方三件套一起吃配额——**并入"硬天花板"一起算**(可选:offboard 用 schedule-deletion 最短 7 天,或复用/归档而非删)。
     ⚠️ 但仍是**硬天花板组合**:逼近上限时会同时撞上 **key 数上限(按 key set 摊薄)+ `CreateKey` 置备速率(按每租户 2 次减半)+ Sign 签名配额(ECC/RSA 两池,区域相关,§8/§2.1)**——SaaS 规模规划要三者按 key set 口径一起看。**结论不变(逐租户 CMK 仍是划算基线),但天花板/成本比"每租户一把"的直觉低/高一个 2–4× 因子。**
     ⚠️ 上述数字(10 万 key、~5/s CreateKey、Sign 配额)**须在 P0/P1 启动前用真实账号+目标区域核对**(AWS Service Quotas 控制台),别把网传/记忆值当冻结基线——AWS 配额会变(CMK 上限就从早年 1 万提到 10 万)。
   - **claims 级隔离(多个 opt-in 租户共用 key,仅靠 `iss`/`tenant_id` + 控制面校验区分)是一个正式的"低保障档"SKU**,不是推荐起步档:它是**应用层隔离**,防伪造全靠签发逻辑不出 bug、**不是密钥边界**,与 §8"防跨租户伪造"硬需求冲突;**默认关、需显式 opt-in + 风险披露**,不作 CMK 成本的常规逃生口(档位定义详见 §8)。
     ⚠️ **应急吊销的爆炸半径必须写进风险披露(否则 opt-in 披露不完整)**:§8 的"紧急密钥吊销(重叠期=0、立即移除旧 key、牺牲在途 token)"是**针对逐租户独立 CMK** 写的——单租户泄露只炸自己。**共享 key 一旦泄露,吊销/轮换会同时命中所有共享它的低保障档租户**(集体停发 + 集体重签),爆炸半径 = 整个共享组。故:
       - **共享 key 不做成单一全局 key,而是分组(每 N 个租户一把共享 key)以限爆炸半径**——组大小是"成本 vs 爆炸半径"的显式旋钮(N=1 即退化为逐租户 CMK);
       - onboarding 的低保障档风险披露**必须明说**:"你与同组其他租户共享密钥边界;任一同组租户密钥泄露事件会触发**全组**紧急轮换、期间你的在途 token 一并作废";
       - 升级到逐租户 CMK 是消除该共享爆炸半径的路径(§2 B 在线迁移)。
3. **自带域名(BYOD)类才需要 SaaS 专属置备**——**两处同源**:① auth 的租户 BYOD 域名(`auth.acme.com` CNAME 到我们);② §6 的 **PRM CNAME 托管**(RS 自带域名挂到我们 CloudFront),同一类能力共用。
   ⚠️ **标准 CloudFront distribution 只能挂一张 viewer 证书、所有 alt domain 须同证书覆盖**,故不能简单"每域名加 alt name"。可行路径:① 每租户独立 distribution(distribution 默认配额 200、可提额;运维重);② 巨型 SAN 证书每次重签(丑、脆);③ **CloudFront SaaS Manager 多租户 distribution(2025-04 GA)——共享模板 + 每租户独立域名/证书 + 托管证书自动签发续期(HTTP 校验),为此场景量身,首选**,还可能把 ACM DNS 校验编排直接消掉。(注:标准 distribution 的 alt domain 默认配额 100、可提额——这也是"每租户独立 distribution"路的天花板之一。数字部署前实查。)
   该置备**只活在 SaaS 一侧、叠在数据平面之上**;自部署因租户数=1、`cdk deploy` 本身即置备,**永不需要它**。**注**:§6 PRM CNAME(方式 b)同受此约束、**不在 P1 默认交付内**,随 BYOD 里程碑走;P1 默认走 §6 方式 a(RS 自挂)。§11 #3 评估 SaaS Manager。

> 一句话:**逐租户 key set(EC+RSA 两把 signing CMK)从第一天就是 SaaS 基线**(此处"第一天"=
> **SaaS 多租户上线首日,即项目 P2/P3**,不是项目 P0)。两把 key 的外部副作用、原子发布、补偿和
> 轮换时间窗由异步控制面处理；claims 级(共享 key)只是低保障可选项。第 2 节 B 因此从"必经迁移
> 路径"退化为"仅当某租户曾用 claims 级、事后要升级到 key set"的边缘情形。

### 1.1 · 逐租户 key control plane 与 runbook(issue #26)

`AgentAuthSaas` 使用以下资源闭合 key lifecycle；SelfHosted 继续使用 stack-scoped signer，不创建这套
控制面：

- `TenantKeysTable` 每 tenant 一条强一致 record。`revision` 条件写是唯一提交边界；
  `served_snapshot` 同时包含同 generation 的 EC/RSA active + published material，数据面从不读取
  未完成 candidate。
- `TenantKeyOperationsQueue` + retained DLQ 承接平台命令；`TenantKeyProvisionerFn` 以 SQS
  partial-batch failure 重试。分钟级 `TenantKeyReconcileSchedule` 只批量 fan-out 每 tenant 的
  reconcile 命令，由 SQS event source 并发接管超时 provisioning、失败补偿、abandoned publishing
  rollback、overlap retirement 和残留 deletion；不会在一个 schedule invocation 内串行执行全 fleet
  的 KMS 工作。
- provisioner 创建 key 时写
  `agent-auth-managed=true`、`agent-auth-deployment=<TenantKeysTable physical name>`、
  `agent-auth-tenant`、`agent-auth-operation`、`agent-auth-algorithm`、
  `agent-auth-generation` tags。deployment tag 将同账号/区域内的多个 SaaS stack 隔离；重试会先按
  完整 tag tuple 查找并接管
  `CreateKey` 已成功但 CAS 响应不确定的 orphan；同 tuple 出现多把 key 时 fail closed。因 tag
  查询最终一致，reconciler 还会按 tenant 精确查询所有 managed key，将迟到的未知 ARN 先写入
  registry 再补偿删除；已成功 schedule deletion 的 ARN 保留在历史中，避免重复接管或永久遗失。
- 从不含 `agent-auth-deployment` tag 的旧版本升级时必须使用 maintenance fence，不能边运行旧
  provisioner 边 backfill：
  1. 停止提交 key control 命令，先禁用 `TenantKeyReconcileSchedule`，等待 operations queue 的
     visible/in-flight 数都归零；再禁用 provisioner 的 SQS event-source mapping，确认其状态为
     `Disabled`，并至少等待一次 Lambda 五分钟 timeout，保证旧 invocation 已退出。
  2. 从当前 registry 的 `served_snapshot`、`operation`、`last_failure` 与
     `pending_deletion_arns` 收集仍受控的 primary ARN；再按当前 operation 的完整旧 tag tuple
     检查 CreateKey 成功、CAS 前崩溃的 key。枚举每把 MRK 的全部 replica，为可证明属于该 registry
     的 primary/replica 补
     `agent-auth-deployment=<当前 TenantKeysTable physical name>`。不得把另一个 registry 仅因
     tenant 名相同的 key 纳入 backfill；无法归属的 orphan 必须人工处置并保持 fence。
  3. backfill 后重新强一致扫描 registry 与 operations queue，逐 ARN 用 `ListResourceTags` 验证；
     只有两次 registry 集合一致、队列仍为空且全部受控资源 tag 正确，才能部署要求 deployment tag
     的 runtime/provisioner IAM。部署成功后先恢复 event-source mapping，再恢复 reconcile rule 与
     operator 命令。
  反序部署会让现有 key 立即失去 `Sign/GetPublicKey` 权限。回滚旧代码可保留新增 tag。
  若升级时已有跨夜 `active_overlap` checkpoint，必须在 maintenance fence 内先完成 backfill 与
  最终 SHA 部署，再恢复 worker 并运行 `forward-finish`；否则旧 binary 退休时不会写
  `last_completed_outcome`，最终 gate 必须失败。
- `SAAS_REPLICA_REGIONS` 是逗号分隔的备用区列表；生产 SaaS 默认必须精确设置为
  `us-west-2`，防止后续部署静默移除主区 admission fence。只有显式设置
  `SAAS_PRODUCTION_RECOVERY=0` 的 disposable test stack 可以使用空列表。CDK 将列表作为
  `TENANT_KEY_REPLICA_REGIONS` JSON 注入 provisioner。新 key 始终创建为 MRK primary；
  列表非空时，任一区域 replica 尚未创建、未可用、公钥不一致或真实签名探针失败都会阻止
  candidate 发布。`AlreadyExists` 只作为幂等重试继续探针，不能跳过验证。primary 从 key creation
  起算 300 秒；replica 从首次被 registry CAS 成功记录的 pending 起算独立 300 秒。任一已持久化
  窗口到期都 fail closed 并进入补偿，worker 重启不会重置窗口；若进程在 pending timestamp CAS
  前崩溃，下次重试重新记录起点，但仍不会在验证完成前发布 candidate。
- 首次创建 MRK 时 KMS 会建立
  `AWSServiceRoleForKeyManagementServiceMultiRegionKeys`。provisioner 仅获准对
  `mrk.kms.amazonaws.com` 创建这一条 service-linked role；`CreateKey`/`TagResource` 仅限主区与
  当前配置备用区。KMS 不为 `ReplicateKey` 提供 tag condition key，因此该 action 由 primary
  account/region ARN、`kms:CallerAccount` 和 `kms:ReplicaRegion` 收敛；provisioner 仍只从已校验
  primary 读取并精确复制完整 managed tag 集。
- registry 只保存 primary ARN。各区域 runtime 从本区 KMS client region 派生 replica ARN，但仅允许
  重绑定 `key/mrk-*`；单区域 ARN 只在其原区域可用，在备用区解析为 503。已有单区域 generation
  因此不会被伪装成可故障转移；须完成一次 MRK rotation 并激活新 generation 后备用区才可签名。
- SaaS Auth/SSF runtime 不注入 `SIGNING_KEY_ID`，且 KMS `Sign/GetPublicKey` IAM 只允许同时匹配
  `agent-auth-managed=true` 与当前 `TenantKeysTable` deployment tag 的 key。request-scoped
  resolver 按 Host/delivery tenant 选
  `served_snapshot`；不存在共享 signer fallback。未登记 tenant 返回 404，已登记但未 ready 返回
  503。
- retirement/rollback 先 CAS 把待删 ARN 移出 `served_snapshot`，再对全部 MRK replica、最后对
  primary 调用 `ScheduleKeyDeletion(7 days)`；因此并发请求不可能继续拿到正被删除的 active key，
  primary 也不会因仍有 replica 而永久卡在未清理状态。清理从 primary 的 MRK metadata 枚举历史
  replica 并动态建立区域 client，因此区域从当前复制配置移除后，既有 generation 仍可完整清理。

状态机与时间窗：

1. `ensure`: `unprovisioned -> provisioning -> ready`。只有 EC+RSA 都通过真实 KMS probe 后才原子
   发布 generation 1。
2. `rotate`: `ready -> provisioning -> publishing`。generation N 仍 active，N+1 的 EC+RSA 同时
   进入 JWKS；至少等待 600 秒(2× 默认 JWKS max-age)。若 operator 在 publish 后 3600 秒内未
   activate/rollback，reconciler 自动 rollback，避免无人接管的 generation 永久留在 JWKS。
3. `activate`: `publishing -> active_overlap`。EC+RSA 同时切到 N+1，N/N+1 继续发布至少
   86430 秒（SSF immutable SET 的 24 小时重试窗 + 30 秒时钟偏移；也覆盖 OAuth token TTL）。
4. `rollback`: publishing 阶段可直接恢复 N 并补偿 N+1；active-overlap 阶段进入
   `rollback_overlap`，立即恢复 N active、保留 N+1 验签至同一 86430 秒窗口结束。
5. `retire`: overlap 到期后先从快照移除被退役 generation，再异步 schedule deletion，最终回到
   `ready`。reconciler 也会自动完成到期 retirement；持久 completion outcome 区分 forward retire
   与 rollback retire，rollback 重试不得把已完成的 forward retire 误报为成功。

所有命令只允许 platform admin 在 control host 调用，新版本完成并记录 completion outcome 后，
`operation_id` 在同 lifecycle 内幂等。旧版本完成记录没有 outcome，无法区分 forward retire 与
rollback retire；升级后对此类歧义 rollback 重试返回 invalid state，不能以伪成功换取兼容：

```bash
CONTROL=https://c.saas.example.com
TENANT=t1
OP=rotate-t1-$(date +%s)
curl -X POST "$CONTROL/admin/control/tenants/$TENANT/keys/rotate" \
  -H "authorization: Bearer $PLATFORM_ADMIN_TOKEN" \
  -H 'content-type: application/json' -d "{\"operation_id\":\"$OP\"}"
curl "$CONTROL/admin/control/tenants/$TENANT/keys" \
  -H "authorization: Bearer $PLATFORM_ADMIN_TOKEN"
```

部署后先检查 `TenantKeyOperationsBacklog`、`TenantKeyOperationsDeadLetters` 与 provisioner error
alarm，再运行完整真机验收：

```bash
# Issue-closing gate: start forward rotation and persist a local checkpoint.
ROTATION_MODE=forward-start AWS_PROFILE=default ./e2e/saas_tenant_keys.sh

# Run after the checkpoint's retire_after, even from a new shell or rebooted host.
ROTATION_MODE=forward-finish AWS_PROFILE=default ./e2e/saas_tenant_keys.sh

# Then prove rollback.
AWS_PROFILE=default ./e2e/saas_tenant_keys.sh
```

Issue 关闭证据必须依次包含上面三个阶段。默认脚本使用真实 600 秒 publish-ahead，覆盖
onboarding、tenant-only JWKS、真实 ES256/RS256
签发、activate、rollback 后新旧 generation 继续验签、跨 tenant 双算法拒绝和无关 tenant 不受影响；
并断言服务端 `retire_after` 至少覆盖 86400 秒 SET 重试窗 + 30 秒 skew。该 rollback gate 约 11 分钟，
随后由 reconciler 在 deadline 自动退役候选。forward gate 不保持 24 小时本地进程：
`forward-start` 在 activate 前先耐久写 `prepared` checkpoint，完成激活和新旧 token 重叠断言后才
原子升级为 `active_overlap`。文件位于 Git 已忽略的 `_my/e2e/issue26-forward.json`，包含
account/stack/table、operation、deadline、ARN、`kid` 和 t2 registry revision，不含 credential、
token 或私钥。`forward-finish` 不把 `prepared` 当验收证据：若前一进程未完成安全交接，它先尝试
回滚并要求重跑；只有 `active_overlap` checkpoint 才能在 deadline 后幂等提交或观察 retirement，
并核对 Dynamo 完成记录、t2 revision 未变化、最终 JWKS、真实双算法签发、跨 tenant 拒绝与 KMS
删除/已删除状态。若 checkpoint 放在其他路径，两次命令均设置同一个 `CHECKPOINT_FILE`。
禁止用测试开关缩短生产窗口。普通中断由 trap 复核 rollback 的 HTTP 接受和收敛状态；断电绕过
trap 时由云端 publishing timeout/overlap reconciler 收敛，prepared checkpoint 会阻止后续误报通过。
安全交接后无需本地进程存活。

---

## 2 · 跨形态升级 与 密钥在线迁移(两条待决项的方案)

两条都用同一个模式解——**expand-contract(先扩展、后收缩)**:任一次发布只做**向后兼容的扩展**,把破坏性的"收缩"推迟到下一个发布,从而**任何一步都能安全回滚**。

### A · 两形态共用一套 migration

分叉风险来自:SaaS 由我们持续、可强制升级;【自部署】客户自控节奏、可能跨版本、可能回滚。对策:

1. **迁移逻辑随制品走,但结构性迁移不在请求路径上跑**:schema 版本记在 DynamoDB(`SCHEMA#version`)。⚠️ **不要在 Lambda 冷启动里跑结构性前向迁移**——冷启动是并发、不可控、在请求路径上,会造成启动抖动、多实例迁移争抢、迁移所需的扩大权限常驻。正确分工:
   - **结构性迁移**:由**部署钩子 / CloudFormation custom resource / 一次性 migration job** 触发(单次、受控、独立权限),`N→N+1→N+2` 线性幂等;
   - **冷启动只做**:①**版本兼容检查**(制品见 `min_reader_version` 比自己新则拒启动,见 4);②**懒迁移读路径**(读到旧版本 item 就地升级,见 2)。
   SaaS 与自部署**同一套迁移引擎、同一条代码路径**,只是触发者不同(我们的 CD vs 客户 `cdk deploy` 后的部署钩子)。
2. **懒迁移 + 后台回填**:单表数据项带版本标签,**读到即就地升级**(migrate-on-touch),冷数据由后台回填任务扫尾——**不做 big-bang 全表迁移**,租户数=1 或=N 行为一致。
3. **expand-contract 保证可回滚**:新版本先"扩展"(加新字段/新写路径,旧读者仍能读);删除旧字段的"收缩"**滞后一个发布**,等到确认无旧读者才做。因此 expand 阶段自部署**回滚到上一版安全**(上一版能读新数据)。
4. **护栏——用两个独立版本标记,别用一个(否则"可回滚"与"拒未知 schema"打架)**:
   - **`schema_version`**(数据当前形态,expand 时递增):制品**能读 ≥ 自己所知的形态**(扩展是向后兼容的),故**不因 `schema_version` 比自己新就拒启动**——这正是 #3 回滚能成立的前提;
   - **`min_reader_version`**(不可回滚下限,**只在 contract 阶段**、确认无旧读者后才提升):制品启动时若自身 < 数据的 `min_reader_version` 才拒绝(此时旧字段已删,旧制品真的读不了)。
   - 即:**expand 阶段可自由回滚;只有跨过 contract 才不可回滚**,而 contract 是滞后、可控的一步。另声明**受支持升级窗口**(超窗须逐级过渡,不跳版)。

### B · claims 级(共享 key)→ 逐租户独立 CMK 的在线迁移(边缘情形)

由于 SaaS 第一天即用逐租户 CMK(第 1 节),此迁移**只发生在一个曾被显式配成 claims 级的低保障租户事后要升级**时,不是常规路径。机制上它就是 §8"KMS 双活轮换"的一个特例(新旧 key 跨了"共享 key vs 专属 CMK"边界),靠 JWT header `kid` + JWKS 多公钥并存实现零停机。⚠️ **两个窗口不能混(严格照 §8/C10.11b 的两相轮换,别用单个"JWT 生命周期重叠期"一句带过)**:

1. **publish-ahead(切签名之前)**:置备专属 CMK → 新公钥以新 `kid` 进该租户 JWKS(旧公钥续留)→ **必须先等 ≥ `/jwks.json` 的 `Cache-Control: max-age`(§2.1 冻结默认 5min)才开始用新 key 签名**——否则缓存旧 JWKS、又不做"未知 kid 重取"的 RS 会拒掉新 key 签的 token。
2. **切签名**:到点后把签名从共享 key 切到专属 CMK。
3. **retire overlap(切签名之后)**:旧公钥**继续留在 JWKS ≥ max(access TTL, ID token TTL,
   SSF immutable SET 的 24 小时重试窗) + skew**，覆盖最后一个旧签名 OAuth token/SET 的有效期后
   才移除（refresh 的 90 天不在此窗口，见 §2.1）。
两相各有自己的时长(前者按 JWKS 缓存 TTL、后者按 JWT 最长寿命),切签名前后均可回滚。

- **唯一设计约束**:`kid` 必须跨"共享 key"与"专属 CMK"稳定——用 **`kid = 公钥指纹(JWK thumbprint)`,不要用 key ARN/别名**。
- ⚠️ 切签名完成前,该租户仍由共享 key 签,防伪造**仍是应用层的**;完全切到 CMK 后才获密码学隔离。共享 key 不因某租户升级而停用(其他 claims 级租户还在用)。
- 多区域下升级目标必须是 MRK generation；各区 replica 共享公钥与 `kid`，JWKS 不取并集也不按区
  分叉。旧共享单区域 key 只在原区域可签，备用区在新 MRK generation 激活前 fail closed。

## 3 · Cedar/AVP 授权引擎启用顺序(C10.17)

> 决策依据:DESIGN §8 / CONFORMANCE C10.17。授权引擎 **feature-flag `AGENT_AUTH_AUTHZ_ENABLED` 默认关 = 字节等价现网**;开启是**有顺序的运维动作**,乱序会导致签发路径 fail-closed 或热路径 503 风暴。

**为何有顺序**:签发热路径永不同步调 Cedar —— Grant 创建时预判 `effective`、`/token` 只读字段。启用涉及三件事必须按序发生:①GSI `policy_version-index` 就绪;②策略工件发布 + `current_pv` bump(单写者 = RecomputeFn);③存量 Grant 的 `effective_pv` 追平当前版本。任一缺失:

- 只开 flag、无策略 → `current_pv=0`,主 Lambda 创建路径对 `pv==0` 走 **no-op**(不塌方,已防呆);但一旦有 `current_pv≥1` 而工件缺失 → 创建路径 fail-closed 拒建 Grant。
- publish bump 了 `current_pv` 但存量 Grant 未追平 → 热路径对存量 refresh/token-exchange 全 **503 `temporarily_unavailable`** 直到 backfill 追平。

**安全启用顺序(照做,别跳步)**:

1. **先建 GSI(authz 仍关)**:`cdk deploy`(不设 `AGENT_AUTH_AUTHZ_ENABLED`)。给既有 GrantsTable 加 `policy_version-index` 会触发**异步回填**;`aws dynamodb describe-table` 确认该 GSI `IndexStatus=ACTIVE` 再进下一步(回填期 Query 结果不完整)。
2. **带策略集部署 authz**:`AGENT_AUTH_AUTHZ_ENABLED=1` + `AGENT_AUTH_POLICY_SET_FILE=<path/to/policy.cedar>`(或 `AGENT_AUTH_POLICY_SET`)`cdk deploy`。**synth 期已强制**:authz 开必须附策略集、策略须过括号/permit sanity(坏策略部署前挡下,补强 ⑨)。CDK 在 authz 开时自动给 RecomputeFn 注入 `AGENT_AUTH_RECOMPUTE_ENABLED=1`(否则常规 stale 处置停在 dry-run)。
3. **RecomputeFn 首跑 publish + backfill**:等 EventBridge 调度(每小时兜底)或手动 `aws lambda invoke --function-name <RecomputeFnName>`。首跑做:**publish-then-activate**(写不可变工件 v1 + bump `current_pv` 0→1,单写者)+ **seed backfill**(把存量 Grant 的 `effective_pv` 追平到 1,与 dry-run 解耦——发布固有语义)。查 CloudWatch 日志 `POLICY_PUBLISHED ... backfill_recomputed=N` 确认追平。
4. **验证**:`current_pv≥1` 且存量 Grant `effective_pv==current_pv` 后,热路径不再对存量 503;新建 Grant 经 Cedar 预判写 `effective`。

**回滚**:置 `AGENT_AUTH_AUTHZ_ENABLED` 未设(移除 env)重部署 → 主 Lambda 立即回到字节等价(签发读 `effective_view`,`effective` 空则回退授权 `per_resource`)。已发布的工件/版本无害留存;GSI 保留(下次启用免重建)。

**SaaS 多租户**:`AGENT_AUTH_RECOMPUTE_TENANTS`(逗号分隔租户标签)让 RecomputeFn 对每租户各 publish/backfill/重算;每租户 `current_pv` 独立(逐租户分区,补强 ②)。

**⚠️ 授权范围边界(必读,别误以为开 authz 就管住一切)**:P2 Cedar 是**资源级**授权,只管辖**有可评估单元**的 Grant(∃ resource 携带 ≥1 scope 或 ≥1 RAR)。**无可评估单元的 Grant**(resource-less:有 scope 无 RS 的纯 code-flow / login grant;或 resource 项 scopes 空+无 RAR)**不受策略版本约束**——重算对它们只保留(计入 `preserved` stat)、绝不吊销,**即便策略是 deny-all**。它们的治理靠 ①consent 上限(签发不超授权)②`require_active_user` gate(注:跳过联邦/非本地 principal)③显式 `DELETE /grants/{id}`(注:RFC 7009 `/revoke` 只吊 refresh family,不吊 Grant)。**若需用策略管住这类 Grant,须等 principal 级策略(P3,对无 resource 维度的 (principal, scope) 判定)**——当前 P2 做不到,启用前须知悉此边界。**⚠ 注**:`RecomputeFn` **dry-run**(`AGENT_AUTH_RECOMPUTE_ENABLED` 未设)**只报 `scanned`、不算 preserved/revoked 分档**(分档需 evaluate,在 dry-run 闸之后)——故无法用 dry-run 预览"哪些会被吊销"。启用前的安全预览 = **按 Grant 形状客户端分类**(有可评估单元[∃ resource 有 ≥1 scope 或 ≥1 RAR]= 会被策略收窄/吊销;无可评估单元 = 恒保留),见 `e2e/authz_enable_drill.sh`(只读预检 + 隔离租户机制演练 + 打印真启用命令,默认不真开)。

## 3A · MCP EMA operator policy 与启用顺序(C13)

- CDK CLI 可从
  `AGENT_AUTH_EMA_POLICIES_FILE`（Dev）或 `SAAS_EMA_POLICIES_FILE`（SaaS）加载。policy 只含
  issuer/JWKS/resource/scope/client 等公开信任配置，不含 client secret 或 IdP 私钥。CDK
  将规范化 JSON 写入专用 Secrets Manager 配置 Secret；API Lambda 启动时按环境中的精确 ARN
  读取，避免 tenant policy 挤占 Lambda 4 KiB environment 上限。
- policy 可先 staged，但 capability 只有在 `AGENT_AUTH_EMA_ENABLED=1`、Phase≥P2、policy 非空且
  `JTI_TABLE` 同时可用时激活。任一结构错误、重复
  `(Agent Auth tenant, issuer, issuer_tenant, authenticated_client_id)` lookup key 或部署形态
  tenant 不匹配均拒启动；discovery 不会宣告半配置能力。
- 固定 JWKS 走现有 HTTPS SSRF 防线、DNS 公网复查、响应/key 上限、正负缓存、单飞与强刷限速；
  无需额外 AWS IAM。ID-JAG replay 与 access-token JTI mapping 复用 `JTI_TABLE`，键前缀和 tenant/
  issuer/issuer-tenant 分区避免与现有记录碰撞。
- 上线顺序：staged policy 部署 → 用目标 IdP/client 取得真实 ID-JAG → 开 flag 部署 → 经 Dev 与
  SaaS public CloudFront `/token` 换取 token并由 RS 验 `aud/scope`。未取得该外部证据时不得把
  in-process fixture 记作 release gate，也不得启用 `allow_legacy_missing_resource` 参与严格验收。
  两种部署分别运行 `e2e/ema_external.sh`；脚本从 operator 提供的 `EMA_ID_JAG_COMMAND` 取
  一次性真实断言，独立验 access token 签名，并从 CloudFormation output 与 Auth Lambda
  environment 和其引用的配置 Secret 交叉验证 CDK 从 Git `HEAD` 绑定的 deployed commit、
  EMA flag 与实际 policy。
  脚本从该线上配置生成 attestation，确认 missing-resource fallback 已关闭；不接受调用者自报
  commit/policy。RS 正向、无 token 401 与未授予 scope 403 探针必须与 token resource 同
  origin/path，最终只输出不含断言、token、email/raw claims 的 evidence JSON。
- 无法取得第三方 ID-JAG issuer 时，可部署仓库内独立 `AgentAuthEmaSimulator` 做自动化
  Dev/SaaS 回归。它用 Cognito User Pool 作为身份源，由独立 KMS key 和 issuer Lambda 生成
  `oauth-id-jag+jwt`，再由独立 RS Lambda 验 Agent Auth access token。验收必须设置
  `EMA_EVIDENCE_KIND=simulator`；evidence 会记录 simulator stack/commit/Lambda
  `CodeSha256` 并明确 `transparent_non_third_party_evidence=true`。该结果可证明本仓库的完整
  public-endpoint 协议链和部署接线，但**不是第三方 interoperability evidence**，不得据此把
  C13.8 的真实 enterprise IdP/client 条目改成完成。

## 4 · 本地密码凭证部署(C9.7-C9.10)

- CDK 为密码凭证创建独立 `PasswordCredentialsTable`(`user_id` 分区键、按需计费、加密、PITR、无 TTL),并输出 `PasswordCredentialsTableName`。表项只允许 `user_id/password_hash/must_change/version/updated_at`;Users 表和任何 API schema 不存 PHC hash。
- 所有会处理用户生命周期或认证的运行时 Lambda 注入 `PASSWORD_CREDENTIALS_TABLE` 并授予该表读写权限。Admin create 先写 credential 后写 user;响应不确定时只允许同一临时密码幂等续完。delete/tombstone 级联删除 credential。
- Argon2id 单次操作约占 19 MiB。`AGENT_AUTH_PASSWORD_WORKERS` 是每实例有界并发槽,默认 2;Lambda 入口同时把 Tokio blocking worker 池限制为该值,防止暖实例为短时任务持续创建并保留 Argon2 allocator arena。主 `AuthFn` 配置 512 MiB,为实测约 241 MiB 的暖实例高水位保留一倍以上预算；后台 Reclaim/Recompute 不处理密码入口,仍为 256 MiB。部署者调整 worker 数时必须重新压测 Lambda memory 和保留并发预算,不得使用无界 `spawn_blocking` 队列或线程池。
- 密码入口的源 IP 只从 API Gateway v2 request context 注入,不读 `X-Forwarded-For`。account/IP/tenant/deployment-global 桶复用 `RATE_LIMIT_TABLE`;该表或条件写不可用时密码登录 fail-closed 503。

### 4.1 · Admin 一次性邀请(C9.11,Issue #34)

- CDK 创建独立 `InvitationsTable`(`locator` 分区键、按需计费、AWS managed encryption、PITR、
  `expires_at` TTL),并输出 `InvitationsTableName`。该表不得与 `MagicLinkTable` 合并;行只包含
  tenant-prefixed locator/user/email、secret verifier、credential epoch、`issued_at` 与
  `expires_at`,不得写明文 token。
- Auth Lambda 注入 `INVITATIONS_TABLE` 并只授予该表、Users/PasswordCredentials/Sessions 的邀请
  事务所需读写权限。`AGENT_AUTH_INVITATION_TTL_SECS` 默认 `86400`,允许 `300..604800`;越界值在
  CDK synth/runtime 初始化时 fail closed。DynamoDB TTL 仅异步清理,接受事务始终检查绝对到期时间。
- CloudFront 将精确静态路径 `/invite` 路由到 SPA/S3并重写 `/index.html`;`POST
  /login/invitation` 与 `POST /admin/users/{id}/invitation` 仍走 default API behavior。邀请 bearer
  位于 URL fragment,浏览器只通过 JSON body 发送给接受端点,不得出现在 CloudFront/API request URL。
- 部署验收必须经 CloudFront 执行 Admin invitation 创建、show-once copy、独立浏览器打开、接受后
  `/account`，再核对 DynamoDB 无明文与 CloudWatch 不含 URL/token。失败或丢失创建响应只能重新签发。
  AgentAuthDev 可用 `API_URL=https://<cloudfront-host> AWS_PROFILE=default ./e2e/invitation.sh`
  自动执行并留出上述断言。

## 5 · Admin break-glass credential source/target 升级与轮换(C12.1)

长期 admin bearer 的运行时契约和操作步骤见
[`ADMIN_CREDENTIAL_ROTATION.md`](ADMIN_CREDENTIAL_ROTATION.md)。部署层必须维持以下资源边界：

1. **legacy source 不变**：旧模板的 `AdminToken` Secret 和
   `SAAS_TENANT_ADMIN_SECRET_ARNS` 只作为升级复制源。首次升级不得原地把裸 `SecretString` 改成
   credential-set JSON。CloudFormation 不跟踪动态引用上次解析的 Secret 版本；回滚旧 Lambda 时会重新
   解析当前值，原地改写会让旧代码把 JSON 当 bearer。
2. **target 由当前栈管理**：平台和每个 tenant 分别创建独立 credential-set target Secret。Rust
   `AdminCredentialMigrationFn` 对 source 只有 `GetSecretValue`，对 target 才有
   `PutSecretValue` 及仅限 `AWSCURRENT`/`AGENTAUTH_VALIDATED` 的 stage 更新；迁移先创建候选版本，
   再以读取到的 placeholder VersionId 做 `RemoveFromVersionId` CAS，expected current 已变化时拒绝
   覆盖。`AuthFn` 显式依赖 migration Custom Resource。主区域 Auth/Reclaim/Recompute 通过
   `AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN` 读取 `RuntimeBootstrapConfig`，其中的平台及 tenant
   credential ARN 全部指向 target；standby 因使用区域副本 ARN，仍直接注入对应 target ARN。
   `AdminSecretArn` output 同样指向平台 target。同一规范化输入的短 SHA-256 摘要写入
   `AGENT_AUTH_BOOTSTRAP_REVISION`；即使 Secret ARN 不变，residency 或外部 source 配置变化也会
   更新 Auth、Governance Worker、Reclaim 与 Recompute 的环境变量并替换 warm execution
   environments，避免继续使用冷启动时缓存的旧文档。
3. **失败可回滚**：migration 先全量校验，再最多 4 路并发写 target。部分 target 写成功后可幂等重试；
   source 字节始终不变。栈回滚到旧模板后，旧 Lambda 仍从 source 接受原 bearer。Custom Resource
   `Delete` 是 no-op，不在删栈、资源替换或未来轮换后尝试把 target 解包回 source。
4. **运行时持久防回退**：每次刷新先以单次 `DescribeSecret` 固定 target 的完整 stage 映射，再按
   VersionId 并发读取 `AWSCURRENT`、`AWSPREVIOUS`、`AGENTAUTH_VALIDATED` 与 pending 文档，要求
   revision 严格增长、`retired[]` append-only，且任何 active id/值不得命中平台或其他 tenant 的
   retired id/hash。读取后、全局唯一性校验后和 checkpoint 后均重查全部完整 stage 映射；任一 owner
   变化即丢弃本轮，不缓存混合 registry。完整 registry 校验成功后，runtime 的
   `UpdateSecretVersionStage` 权限仅可管理 `AGENTAUTH_VALIDATED` 可信锚点和
   `AGENTAUTH_ROLLBACK_PENDING` 故障屏障。所有未验证 transition 都先附加 pending 以序列化
   checkpoint；保持屏障时以旧 validated VersionId 做 CAS 提交新 validated，核对
   current=validated=pending 后才清 pending 并再次核对。提交前中断不会建立信任；提交后中断仍由
   pending 阻止其他 current 被验证。Secrets Manager 单次 operation 最长 5 秒，deadline 前 30 秒为
   checkpoint 安全窗，pending 建立后为 validated 提交与清理各预留最坏 10 秒。进入门槛即拒绝提交
   rollback 并保留故障屏障。全部 target 推进成功才接受本轮凭据；可信 stage 缺失直接 fail closed，
   连续非法版本不能越过单代 `AWSPREVIOUS`。网络读取在独立
   refresh lock 下进行，不持有 cache lock；缓存 TTL 只限制后端读取，每次请求仍按当前时间检查全部
   owner 至少有一个 active credential，任一 owner 到期或配置/stage 推进错误统一 503。

SaaS 的逐租户 OIDC subject profile 与 Admin credential ARN、residency 一起保存在 versioned
runtime bootstrap Secret 中。`SAAS_TENANT_SUBJECT_TYPES` 只允许已配置租户映射到 `public` 或
`pairwise`；未列租户默认 `pairwise`。Discovery、DCR metadata 校验和所有 token issuance flow
必须通过同一个 tenant resolver，禁止在 handler 中回退到 fleet-wide subject type。新增长期
conformance tenant `t3` 时使用显式 `public`；`t1` 保持默认 `pairwise`，永久 offboard 的 `t2`
不得重新启用。

兼容窗口内 source 与 target 会保存同一 bearer。当前运行时角色对每个 source ARN 都有显式
`Deny GetSecretValue/DescribeSecret`，防止 source 名称与 federation 等其他 allow 前缀重叠；仅
migration role 可读。支持旧模板回滚的窗口结束后，先在 target 做一次正常轮换，把复制来的 legacy bearer 写入
`retired[]` 并验证 source bearer 在所有 Host 都返回 401，再在后续 contract release 移除平台 source
资源和 SaaS source 配置。不得先删 source 再宣告旧模板不可回滚。

## 6 · SCIM credential、identity claim 与 Groups 部署(C12.2/C12.3)

Users lifecycle 契约见 [`SCIM_USERS.md`](SCIM_USERS.md)，Groups/role mapping 契约见
[`SCIM_GROUPS.md`](SCIM_GROUPS.md)。部署层维持以下边界：

1. 每个启用租户有独立 SCIM source/target Secret。target 使用
   `owner=scim_tenant`、`usage=scim_provisioning` 的 credential-set；它与平台/tenant Admin
   target ARN 全部互异，但进入同一运行时 registry 做跨 domain 的 id/value/retired-hash
   唯一性校验。Lambda env 只保存 ARN map，不保存 bearer。
2. source 只供可回滚 migration Custom Resource 读取；运行时角色显式 Deny source，并只可
   Describe/Get target 与维护 validated/pending stage。SCIM 轮换沿用 C12.1 current/next
   checkpoint、expiry、retirement 和 rollback 规则。
3. canonical user、SCIM binding 与哈希 alias claim 位于同一 UsersTable transaction。claim
   主键必须 tenant-scoped；原始 `externalId` 不进入键或日志。UsersTable 启用 PITR、无 TTL。
4. `credential_epoch`、`revocation_pending` 与 SCIM binding 是持久身份字段。Session、Refresh
   和 Grant adapter 必须持久化创建 epoch；旧记录缺字段按 0 读取。部署不得先开启 SCIM 路由再
   上线全部 epoch 消费闸。
5. CloudFront default API behavior 必须不缓存、转发 Authorization/query，并允许 PUT/PATCH。
   Dev 与 SaaS 均须 synth/diff 后部署；SaaS 必须校验 SCIM Secret tenant 集合与 issuer Host
   注册表完全一致。
6. Group、externalId claim、成员反查与显式 role mapping 位于独立 `ScimGroupsTable`。
   canonical/claim/membership 变更必须在同一 DynamoDB transaction；表启用 PITR、无 TTL，并以
   sparse `tenant_kind-index` 列出租户 active Groups。Lambda env 只注入表名，runtime role
   只获得该表及其 index 的读写权限。
7. Group 最大 40 个成员，使最坏 replace/delete/mapping transaction 保持在 DynamoDB 100-item
   上限内。部署后必须等待 `tenant_kind-index=ACTIVE` 再执行
   [`e2e/scim_groups.sh`](../e2e/scim_groups.sh)；SaaS 同时跑 t1/t2 credential、id、member 和
   mapping 交叉矩阵。

## 7 · Tenant Admin OIDC SSO 与 RBAC 部署(C12.3)

完整身份映射、浏览器绑定、会话失效、RBAC、审计和回滚契约见
[`ADMIN_SSO.md`](ADMIN_SSO.md)。部署层必须维持以下边界：

1. `AdminAuthTable` 使用 `key` 分区键、按需计费、AWS managed encryption、PITR 和
   `expires_at` TTL。config row 不写 TTL；十分钟 flow 和十五分钟 session 依赖运行时到期检查，
   DynamoDB TTL 只负责异步回收。
2. 主 Auth Lambda 注入 `ADMIN_AUTH_TABLE` 并只对该表读写。`AdminAuthTableName` output 用于
   live 验收；Reclaim/Recompute/Migration Lambda 不获得 Admin session 数据权限。
3. 上游 confidential client secret 必须预先写入
   `agent-auth/admin-oidc/<tenant-id>`；SelfHosted 的逻辑 tenant id 固定为 `default`。runtime IAM
   只允许读 `agent-auth/admin-oidc/*`，handler 再按 Host 强制精确名称。
4. 每个公网 tenant origin 注册自己的精确回调
   `https://<tenant-origin>/admin/sso/callback`。不得在 t1/t2 共用 client、redirect 或 secret；
   SaaS control Host 不配置 tenant Admin OIDC。
5. CloudFront/API behavior 必须转发 cookie、query 和所有 Admin method 且不缓存。部署后执行
   [`e2e/admin_sso.sh`](../e2e/admin_sso.sh)，覆盖 Dev、t1、t2 的真实 Cognito 往返、auditor
   写拒绝、跨 tenant cookie、持久 logout，以及 baseline owner 的 RFC 9470 challenge、无副作用
   拒绝和上游 step-up 参数映射。
6. 先保留长期 bearer 作为 bootstrap/break-glass 并验证其高优先级审计，再开启日常 SSO。回滚前
   先 CAS 删除 OIDC config 使现有 session 立即失效；不得先删上游 client/secret 留下不可恢复配置。
7. `strong_acr_values` 只能填写该 tenant 上游 IdP 已验证、稳定并带可用 `auth_time` 的精确 ACR。
   不得把 `mfa`/`otp` AMR 或另一个 tenant 的映射复制成默认信任。完整 assurance 契约见
   [`ASSURANCE_STEP_UP.md`](ASSURANCE_STEP_UP.md)。

回滚顺序：

1. 全程保留并先验证 break-glass credential。
2. 按当前 revision CAS 删除 `/admin/oidc`，确认已有 cookie 请求 `/admin/session` 返回 `401`。
3. 部署上一版本 Lambda 与 SPA；专用 DynamoDB 表和 client-secret Secret 可以保留，旧代码不会读取。
4. 确认回滚后再删除上游 client 或 Secret。
5. 重跑 `e2e/saas_admin_acceptance.sh` 的 break-glass tenant 矩阵。

## 8 · Authentication assurance policy 部署(C12.4)

CDK 必须向 AuthFn、ReclaimFn 和 RecomputeFn 显式注入同一组策略，避免后台签发或重算路径与主
授权入口使用不同风险分类：

```text
AGENT_AUTH_STRONG_MAX_AGE_SECS=300
AGENT_AUTH_HIGH_RISK_RAR_ACTIONS=transfer
AGENT_AUTH_HIGH_RISK_ADMIN_ACTIONS=access.manage
```

`AGENT_AUTH_STRONG_MAX_AGE_SECS` 合法范围是 1–3600 秒。两个 action 变量是逗号分隔 token；
显式空串表示禁用对应集合。非法秒数、空白 action 或超长 token 必须使 runtime 初始化失败，不能
静默采用默认值。修改风险动作属于安全策略变更，Dev 和 SaaS 必须在同一 release 中 synth/diff/deploy，
并核对三类 Lambda 的运行时 env 一致。

部署后执行：

1. OIDC discovery 断言 `acr_values_supported` 只包含两个 Agent Auth canonical ACR；
2. [`e2e/passkey_flow.sh`](../e2e/passkey_flow.sh) 在 Dev 隔离环境证明 passkey 同时满足显式
   strong 和 `transfer` RAR，脚本 trap 必须恢复 passkey feature flag；
3. [`e2e/admin_sso.sh`](../e2e/admin_sso.sh) 在 Dev/t1/t2 创建一次性 Cognito identity/client，
   证明 Cognito 缺失/未知 ACR 不会提级，baseline `access.manage` 不产生 mutation，并把配置的
   provider ACR 与 `max_age` 发送给上游；
4. 抽查 access token、refresh 后 token、delegated token 与 introspection 的 canonical `acr` /
   规范化 `auth_time` 一致。

回滚策略变更时先保留 break-glass，确认不存在依赖待移除 strong mapping 的自动化管理任务，再部署
旧策略。回滚不得直接修改 DynamoDB session/code/refresh 记录；既有认证事件应由正常过期和吊销边界
处理。

## 9 · Security event 持久化、归档与重驱(Issue #24)

安全事件的 envelope、动作覆盖和 Admin 查询契约见
[`SECURITY_EVENTS.md`](SECURITY_EVENTS.md)。部署拓扑固定如下：

1. `SecurityEventsTable` 以 `event_id` 为主键，启用 PITR、AWS managed encryption、
   `NEW_IMAGE` stream 和 `expires_at` TTL。`tenant_occurred_at-index` 支持租户时间分页；
   `delivery_status-index` 以 `last_delivery_at` 排序，供 pending outbox、死信重驱和归档
   refresh 扫描。正常行 TTL 是 `occurred_at + 400 days`。
2. Auth Lambda 使用同一 event ID 条件写并做有界重试。持续失败时把完整
   `SecurityEventIngress` 放入保留 14 天的 `SecurityEventIngressQueue`。Archive Lambda
   使用 SQS `ApproximateReceiveCount` 重试原消息，避免自重投失败把 attempt 重置。四次失败
   后先写 retained quarantine 和 FIFO terminal DLQ，两个动作成功后才确认源消息。DynamoDB
   与 SQS 同时不可用时，完整 typed ingress 以 `SECURITY_EVENT_EMERGENCY` 写入保留 2555 天
   的 Auth log group；不能只记录 event ID。服务恢复后先用
   `scripts/replay_security_event_emergency.sh` dry-run 有结束时间和显式 tenant scope 的事故
   窗口，再加 `--execute` 将匹配 event id 送回正常 ingress queue。工具在去重前校验全部
   typed ingress，同 ID retained envelope 不一致时 fail closed；同 envelope 仅在 attempts 和
   status-history 前缀偏序上选择支配所有副本的 delivery snapshot，日志时间只为等价副本打破
   平局，不可比较的 history 同样 fail closed。热表已有同 envelope 时，仅当
   `source_delivery_attempts` 已覆盖 retained attempts，
   且计数相等时 source-history status 序列也覆盖 retained history，才跳过；否则重送以触发正常
   CAS history merge，包括同一次 attempt 响应超时后追加的 failed transition。
   大批次 deadline 中断时改用 `--marker batch-recovery` 重放预写的完整 recovery markers。
   DynamoDB 返回永久拒绝（包括 event ID 对应不同 envelope）时只进入 quarantine/incident，
   不写 tenant archive，避免覆盖可信对象。
   quarantine object key 与 terminal FIFO dedup ID 必须使用源 SQS `messageId`，不能使用
   envelope event ID；这样两个不同 collision 消息不会互相覆盖或被 FIFO 吞掉。合法 typed
   ingress 穷尽 transient retry 后写 tenant archive 时必须带 `If-None-Match: *`；若确定性
   key 已存在，只保留原可信对象，冲突 ingress 仍完整留在 quarantine/incident。
   单次业务操作生成超过 16 条事件时，Auth Lambda 在任何网络 I/O 前把全部 typed ingress
   写入保留 2555 天的 recovery log，再以每请求最多 10 条、最多 16 请求并发、总计 3.5 秒
   的预算直接送 ingress queue；SQS partial response 逐 entry 处理，仅 transient 失败项重试，
   permanent 失败项进入 retained emergency envelope，不得互相抑制。worker 随后写热表并触发
   同一归档链路。这样批量 Grant 吊销等路径不会把单事件 3.2 秒预算按波次串行放大到 Auth
   Lambda 的 10 秒上限。
3. Archive Lambda 从 stream `TRIM_HORIZON` 消费 INSERT，以
   `security-events/tenant_id=<tenant>/year=<yyyy>/month=<mm>/day=<dd>/<event_id>.json`
   确定性键写入私有 archive bucket。对象在顶层事件字段之外保留最终 delivery 状态、attempt
   计数和 transition history。首次写使用 `If-None-Match: *`；已有对象时强读 body/ETag，
   不可变 event 不同或 history 分叉即 fail closed，旧对象支配 proposed revision 时保留，
   proposed revision 严格更新时才以 `If-Match` 条件替换。bucket 开启 versioning 作为纵深
   恢复手段，避免热表 400 天 TTL 后的 event-ID 碰撞静默覆盖七年归档。对象、bucket 和
   Glue/Athena projected table 保留 2555 天，
   Athena 查询必须注入 tenant partition。栈对该 Glue database/table 显式保留
   `IAM_ALLOWED_PRINCIPALS` 的 Lake Formation `ALL`（`Super`）兼容授权，避免账户级默认
   权限为空时 Athena 只看到部分 catalog 列；这是恢复 IAM-compatible 模式所需的特殊授权，
   不带 grant option，实际 API 与对象访问仍由 IAM 和 S3 policy 控制。
4. 四次 S3 尝试耗尽后，worker 先把行置为 `dead_letter_pending` 并把 TTL 延长到 2555 天，
   再以 event ID 做 FIFO 去重发送 `SecurityEventArchiveDlq`，最后置 `dead_lettered`。
   EventBridge 每五分钟并发分页查询并逐页处理 `delivery_status-index` 中最旧的
   `dead_letter_pending`、`dead_lettered` 和 `archive_refresh_pending`：第一类续完未完成的
   incident-message outbox；第二类持有 10 分钟 redrive lease 重试 S3；第三类续完迟到 fallback
   duplicate 触发的归档刷新。redrive 每轮只累加 aggregate attempts、推进 last-attempt time，
   失败时释放 lease 并保持 `dead_lettered`，不无限追加 `retrying`/`failed` history；成功时追加
   `archived` 并恢复正常 400 天 hot TTL。每条失败单独收集，worker 继续处理同批后续记录和其余
   三类状态。单行反序列化失败只隔离该行；单类 query 慢或失败、单类 backlog 很大，均不阻断
   其余两类继续逐页处理。retained S3 failure notification 同样按 S3 对象和对象内 event 两层
   隔离，最后才返回带 status/event ID 或 notification index 的聚合错误，避免一个坏对象、坏
   outbox 或坏索引页永久饿死全局 redrive。
   14 天 FIFO 是告警和人工取证副本，不是唯一长期副本。
5. 已归档 event 收到同 ID、同 envelope 且 source attempts 更新的 fallback duplicate 时，
   DynamoDB 条件合并 source history、累加 aggregate attempts，并转
   `archive_refresh_pending`。refresh worker 先取得 60 秒 lease，再强读当前 delivery 并条件
   替换确定性 S3 key；最终 `archived` CAS 同时校验 observed status、attempt count、完整
   delivery history 和 lease token，并使用实际保留在 S3 对象中的 `archived_at`。
   Archive Lambda timeout 为 30 秒，短于 lease，因此过期 worker 不会与下一 claimant 并发写。
6. Stream event-source mapping 开启 batch bisect、三次重试和 24 小时 record age。耗尽的完整
   invocation 进入 retained `SecurityEventStreamFailureBucket`，S3 create 再触发同一 worker
   完成 pending/FIFO 状态机。
7. Ingress 四次恢复失败或 payload 无法解析时，worker 必须先把原始 body 写入 retained
   `SecurityEventIngressFailureBucket/security-event-ingress-failures/<source-message-id>.json`，
   再确认源消息并写 `SecurityEventIngressDlq`。隔离桶保留 2555 天且不触发 stream
   reconciliation。
8. Auth、Reclaim、Recompute、Archive 与 SSF Delivery log groups 均显式 `RETAIN` 2557 天。每个
   AppState runtime 的 security-event storage/fallback/invalid 指标进入同一 infrastructure
   alarm；七个 alarm 分别覆盖认证失败、infrastructure error、跨租户拒绝、
   stream/ingress backlog、archive/ingress dead letter、SSF delivery failure 和 SSF
   source-stream/due-outbox backlog。
   发布验收必须触发真实指标并观察 `ALARM -> OK`，不能只调用 `describe-alarms` 检查配置。

部署顺序：

1. 使用选定的 AWS profile 构建七个 Rust Lambda 产物并 synth/diff Dev 与 SaaS。
2. 部署后等待三个 GSI `ACTIVE`，确认四个 retained bucket、两个 FIFO queue、七个 alarm 和
   五分钟 archive maintenance rule 已创建。
3. 执行 [`e2e/security_events.sh`](../e2e/security_events.sh)，覆盖 direct write、fallback、
   pagination、Athena、poison quarantine、dead-letter TTL/redrive 和真实 alarm 状态。backlog
   验收会临时把 Archive Lambda reserved concurrency 置零，确认 SQS age alarm 后恢复原值；
   fallback 验收会临时把 Auth Lambda 的 security-event table 指向不存在表，执行真实业务
   mutation 后验证 SQS 恢复及 storage-error metric；双故障验收再同时指向不存在的 queue，
   证明同请求的所有 emergency envelopes 可经生产 replay 工具进入归档。cleanup trap 在失败/
   中断时会恢复完整 Lambda environment 与 reserved concurrency，并逐项读取回验，不会把未恢复
   状态当成成功。
4. 回滚 Lambda 代码时不得删除 retained table/bucket/index；先确认无 `dead_lettered` 行和
   incident queue backlog，再移除 redrive rule 或新 GSI。

双服务故障恢复示例（默认只打印计划，不发送）：

```bash
AWS_PROFILE=default scripts/replay_security_event_emergency.sh \
  --stack AgentAuthDev --start-time <incident-start-epoch> \
  --end-time <incident-end-epoch> --tenant-id default --all-matches

AWS_PROFILE=default scripts/replay_security_event_emergency.sh \
  --stack AgentAuthDev --start-time <incident-start-epoch> \
  --end-time <incident-end-epoch> --tenant-id default --all-matches --execute
```

跨 tenant 恢复必须把 `--tenant-id <id>` 显式替换为 `--all-tenants`；后者是 stack-wide
操作确认，不能作为默认值。

## 10 · Shared Signals transmitter (Issue #25)

协议与事件投影契约见 [`SHARED_SIGNALS.md`](SHARED_SIGNALS.md)。AWS 部署拓扑固定如下：

1. `SsfDeliveriesTable` 以 `tenant_id` / `record_key` 分区 stream 与 delivery 行，启用
   PITR、AWS managed encryption、400 天 TTL 和 retained removal policy。
   `due-index` 只投影带 `due_partition=active` 的 pending/retry 行。
2. `SsfDeliveryFn` 从 `SecurityEventsTable` 的 `LATEST` stream 接收新 INSERT，并由一分钟
   EventBridge rule 处理 due outbox。source batch 三次重试、24 小时 record age 后把完整
   invocation 放入 retained `SsfStreamFailureBucket`；bucket notification 经独立 SQS
   replay queue 自动重新读取原 invocation，连续四次失败进入 14 天 DLQ。函数日志保留七年。
3. `SsfDeliveryFailures` 覆盖 attempt exhaustion、lease 前过期和 source replay DLQ；
   `SsfDeliveryBacklog` 取 source stream iterator age、source replay queue age 和
   due-outbox oldest age 的最大值。两者与通用 `InfrastructureErrors` 一起监控 source
   poison、签名、存储和 HTTPS delivery。
4. Auth 与 SSF worker 必须共享同一个 active/published EC signing-key phase。默认二者使用
   stack-managed `SigningKeyEs256`。生产轮换用下列每栈独立环境变量表达，值必须是 KMS key
   ARN；active 必须属于 1..8 个唯一 published ARN：

| Stack | Active | Published CSV |
| --- | --- | --- |
| `AgentAuthDev` | `DEV_EC_SIGNING_KEY_ARN` | `DEV_EC_SIGNING_KEY_ARNS_PUBLISHED` |
| `AgentAuthSaas` | `SAAS_EC_SIGNING_KEY_ARN` | `SAAS_EC_SIGNING_KEY_ARNS_PUBLISHED` |

CDK 对 active key 只授 `kms:Sign`，对 published set 授 `kms:GetPublicKey`，并把同一配置注入
Auth、SSF、Reclaim 与 Recompute runtime。每个轮换相位必须先 `cdk diff` 再部署对应主栈；
不得用手工 Lambda environment 变更作为持久生产配置。

优雅 EC 轮换顺序：

1. publish-ahead：active=旧，published=旧+新；部署后等待至少两倍 JWKS `max-age`。
2. switch：active=新，published=旧+新；部署并证明新旧签名都可验证。
3. retire：从最后一个旧 key 签名时刻起，同时等待所有 OAuth token 过期和所有旧 SET
   `iat + 86400`，再加时钟偏移余量；随后 active=新，published=新。SSF redrive 不会重签，
   因而只等待 access/ID token TTL 会破坏仍可重试的 immutable SET。

每个生产相位完成验证后，必须由执行该相位的已认证 tenant operator 调用
`POST /admin/ssf/signing-key-rotations`，把 `publish_ahead`、`activate`、`retire`、
`emergency_revoke` 或 `rollback` 及其 `success`/`failure` 结果写入 canonical
security-event ledger。`old_kid`、`new_kid` 和 `operation_id` 只能是公开 opaque
identifier，禁止提交 KMS ARN。一次轮换的所有相位复用同一个 `operation_id`；相位失败必须先
记录 `failure`，恢复旧配置后再记录 `rollback/success`。audit 返回非 `201` 时该相位不得被
宣告完成。handler 会从 runtime signer 读取真实 active/published `kid` 集并拒绝与所报相位
不一致的审计，不能用任意 caller-supplied `kid` 伪造已完成轮换。`e2e/kms_rotation_drill.sh`
的执行模式已强制这套顺序，并验证 ledger 不含 key ARN。

`e2e/kms_rotation_drill.sh` 默认只做预检并打印上述相位。`EXECUTE=1` 的可逆 dev 演练默认停在
switch 且继续发布旧 key；只有显式设置 `RETIRE_AFTER_WAIT=1` 且
`RETIRE_WAIT_SECS>=86400` 才执行 graceful retire。独立紧急演练使用
`EMERGENCY_REVOKE=1 RETIRE_AFTER_WAIT=0`；它在 switch 后立即把 Auth/SSF 的 active/published
收成新 key-only，不读取或等待 `RETIRE_WAIT_SECS`，要求 `CLOUDFRONT_DIST_ID`，并等待
`/jwks.json` invalidation 完成后才断言旧 token 失败及记录 `emergency_revoke/success`。两个模式
互斥，invalidation 或 canonical audit 失败都会使演练失败。紧急路径会有意破坏在途 OAuth token
与 immutable SSF SET；这是事故处置的安全优先语义，不得复用 graceful-retire 的可用性承诺。

SaaS tenant-managed key registry 使用同一个已完成探针的 rotation candidate，但事故切换不走
graceful activation/retirement deadline。platform admin 先以一个 `operation_id` 发
`POST /admin/control/tenants/{tenant}/keys/rotate` 置备并发布 candidate；事故确认后对同一
`operation_id` 发 `POST /admin/control/tenants/{tenant}/keys/emergency-revoke`。provisioner
以单次 registry CAS 把 active/published EC+RSA 同时切到 candidate-only，再安排旧 pair 删除；
重复命令只恢复未完成清理，不会重复逻辑吊销。

两个主栈均为 `UPDATE_COMPLETE` 后运行真实互操作验收：

```bash
PROFILE=default REGION=us-east-1 ./e2e/ssf.sh
```

脚本依赖 `aws`、`curl`、`jq`、`openssl`、`zip` 与 Node.js。它从 Secrets Manager 读取部署
tenant Admin credential 但不打印，临时部署 API Gateway/Lambda/DynamoDB receiver，覆盖 Dev
与 SaaS `t1`/`t2` 的 metadata、三类事件、timeout/retry、同 SET dedupe、跨租户拒绝和
revoke-before-lease。退出时删除 receiver stack、versioned bootstrap object 和所有 seed
stream 行，并通过 Admin API tombstone fixture users；canonical event 与 archive 保留为
验收证据。清理不完整即验收失败。

## 11 · External OAuth/OIDC conformance release gate (Issue #27)

权威运维契约见 [`EXTERNAL_CONFORMANCE.md`](EXTERNAL_CONFORMANCE.md)。发布 profile claim 前，
release operator 必须从 `main` 手动运行 `.github/workflows/release-conformance.yml`，传入稳定
HTTPS issuer 与该环境实际部署的完整 Git commit，并要求该 run 全绿。workflow 从受保护的 GitHub
`conformance` environment 读取 OIDF API token、Basic OP 配置及 raw artifact 加密口令；
environment deployment policy 只允许 `main`。workflow 不开放 secret-bearing
`workflow_call`，第三方 Actions 固定完整 commit，OIDF runner 全部直接/传递依赖与验签依赖固定
版本和 SHA-256。OIDF host 固定为 `https://www.certification.openid.net/`，workflow 固定运行
官方 `oidcc-basic-certification-test-plan` 的 discovery + dynamic-client 档，同时运行项目自有
RFC 9700 选定条款回归。

OIDF runner/config 缺失、plan/module 漏跑、非终态、export 失败、suite/deployment 版本不符、
export origin/RSA 成员签名不可信、discovery runtime endpoint 非法或跨 issuer origin、未批准
profile claim 或过期限时例外均 fail closed。动态 client 对任何可能成功的注册响应都从
`finally` 边界尝试清理，清理失败不可豁免。JSON/HTML 原始 export 含敏感测试配置和 HTTP trace，
明文只存在 runner 临时目录；artifact 仅保留 AES-256 加密包与 checksum，不得直接附到公开
release。单次 plan 不需要等待 24 小时；独立的每日 03:17 UTC schedule 仅在仓库变量
`CONFORMANCE_SCHEDULE_ENABLED=true` 时运行，并从 `conformance` environment 读取稳定 issuer
与实际部署 commit；外部配置未齐时该变量必须保持未设置或 `false`，手工 release gate 仍然
fail closed。GitHub runner 中断时以新的 workflow attempt 重跑，不复用不完整 attempt 作为发布证据。
gate 失败时 workflow 按 deployment commit 创建或更新
跟踪 issue，附 workflow run 与 gate summary；未过期的逐测试例外必须精确绑定该 issue，并由
policy allowlist 中的 release owner 通过 GitHub label audit event 批准，且不得改写原始失败。
独立的 `release-conformance-monitor.yml` 每三小时在 GitHub-hosted runner 上检查 schedule、
专用 runner、完整部署 commit 和 24 小时 evidence 新鲜度；发现异常时维护单一 watchdog issue，
恢复后自动关闭。部署时必须把同一 verified commit 同时写入 `conformance` environment 和
repository scope 的 `CONFORMANCE_DEPLOYMENT_VERSION`；前者是 release gate 权威值，后者是
watchdog 的非敏感镜像。该 watchdog 不进入 `conformance` environment，也不读取其中 secrets。
combined evidence 中的 `requested_claims` 不是发布授权；只有 gate 全绿才生成带 evidence SHA-256
和 24 小时有效期的 schema-v2 `approved-profile-claims.json`。该文件明确列出获批 profile 与
FAPI、OpenID Federation、blanket RFC 9700 certification、真实 SCIM/EMA interoperability 等
非声明。下游 promotion 必须用 `release_conformance.py validate-promotion` 同时校验批准文件、
原始 evidence、目标 issuer、目标完整部署 commit、期限与所需 profile；合并到 `main` 本身不构成
发布或协议声明授权，Dev 与 SaaS 也不得复用彼此的批准文件。

## 12 · 单区域备份恢复与事故演练

生产数据分类、10 分钟 RPO / 4 小时 RTO、恢复前置、失败条件、断点续跑、清理与真实事故切换边界，
以 [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md) 为权威 runbook。部署入口遵守以下不变量：

1. `AgentAuthSaas` 默认启用 production recovery profile；`SAAS_PRODUCTION_RECOVERY=0` 仅允许
   disposable test stack。SelfHosted 需显式 `AGENT_AUTH_PRODUCTION_RECOVERY=1`。
2. 可安全恢复的 12 张 SaaS 权威表使用 `RETAIN + PITR + daily AWS Backup(35 days)`；静态
   KMS key 与 stack-managed Secrets 同样 `RETAIN`。
3. code/session/`jti`/refresh family/recovery code 以及包含永久 revoke tombstone/可发送
   outbox 的 `SsfDeliveriesTable` 不进备份。恢复后必须重走授权、恢复因子或 SSF stream 注册，
   禁止用旧表恢复可兑换性或 receiver 可发送状态。
4. `AdminAuthTable` 恢复后必须删除所有 `flow#`/`session#` 行，只允许 `config#` 行进入候选切换。
5. `cdk diff` 必须证明既有权威表、key、secret 无 replacement；任何 replacement 都先停止部署并
   评审迁移方案。
6. 部署 production recovery profile 时必须设置
   `AGENT_AUTH_DEPLOYMENT_COMMIT=$(git rev-parse HEAD)`；演练拒绝 stack output、HEAD 或 worktree
   任一不一致。

部署后执行真实隔离恢复演练：

```bash
STACK=AgentAuthSaas \
ISSUER_T1=https://t1.example.com \
ISSUER_T2=https://t2.example.com \
AWS_PROFILE=default REGION=us-east-1 \
./e2e/backup_restore_drill.sh
```

该演练不需要等待 24 小时；日备份是 fallback，脚本同时创建一次 on-demand recovery point，
并用所有恢复表共同支持的统一 PITR cutoff 实测 RPO/RTO。机器重启后用同一 `RUN_ID` 续跑；若只需回滚隔离资源，则运行
`ACTION=cleanup RUN_ID=<id> AWS_PROFILE=default ./e2e/backup_restore_drill.sh`。

## 13 · 多区域主动/被动切换

多区域部署、Global Tables 冲突语义、Region-local replay 表、Secret ARN 区域改写、primary/standby
两阶段部署、330 秒 activation fence、CloudFront 切流、降级操作、重启续跑、rollback 与 RTO/RPO
证据，以 [`MULTI_REGION_FAILOVER.md`](MULTI_REGION_FAILOVER.md) 为权威 runbook。

该演练不运行 24 小时。每次 failover/failback 固定等待 330 秒（300 秒 client assertion 最大寿命 +
30 秒 skew），完整流程理论下限约 11 分钟。tenant-key forward retirement 是独立
24 小时 gate，不得混作 Issue #29 的等待条件。

```bash
AWS_PROFILE=default \
PRIMARY_REGION=us-east-1 STANDBY_REGION=us-west-2 \
PRIMARY_STACK=AgentAuthSaas STANDBY_STACK=AgentAuthSaasStandby \
SAAS_ZONE=example.com TENANT=t1 \
./e2e/region_failover.sh
```

机器重启后以同一 `RUN_ID` 重跑；RTO 起点取 DynamoDB `changed_at`，quiescence deadline 取两区收敛
后持久化的 observation time，均不会因进程重启缩短或重置。查看状态使用 `ACTION=status`。紧急恢复
primary 使用 `ACTION=rollback`，但 rollback 同样必须
先重验持久部署上下文，再经过完整 quiescence 并推进新 revision；恢复 primary 后清理完整或部分
probe。任何 RTO/RPO 超标、双 writer、旧工件可兑换、JWKS 漂移、CloudFront 未恢复或探针清理失败
都不得产出 qualified evidence。

# Admin break-glass credential rotation

本 runbook 适用于 SelfHosted 平台 admin、SaaS 平台控制面和每个 SaaS tenant 的长期
bootstrap/break-glass bearer。日常管理员身份由短期 SSO session 承担；这里的每次成功使用都会
写入 `ADMIN_BREAK_GLASS_USE priority=high` 审计事件。

## 1. 运行时契约

每个 owner 使用不同的 Secrets Manager Secret ARN。Lambda 环境只保存 ARN，不保存
`SecretString`。Secret 内容是严格 JSON；未知字段、owner 不匹配、重复 credential id/值、非法时间窗、
过期值、retired ledger 回退或任一缺失 Secret 都会 fail closed。每个 bearer 必须由 CSPRNG 生成且
UTF-8 编码至少 16 bytes；本 runbook 默认生成 32 random bytes。

```json
{
  "schema_version": 1,
  "owner": { "kind": "tenant", "tenant_id": "t1" },
  "usage": "break_glass",
  "revision": 2,
  "current": {
    "credential_id": "t1-2026-07-a",
    "secret": "<current>",
    "created_at": 1785000000,
    "not_before": 1785000000,
    "expires_at": 1792776000
  },
  "next": {
    "credential_id": "t1-2026-07-b",
    "secret": "<next>",
    "created_at": 1785200000,
    "not_before": 1785200000,
    "expires_at": 1792976000
  },
  "rotation": {
    "overlap_starts_at": 1785200000,
    "cutover_at": 1785200900,
    "retire_current_at": 1785203600
  },
  "retired": [{
    "credential_id": "t1-2026-04",
    "secret_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "retired_at": 1785000000
  }]
}
```

平台 owner 使用 `{"kind":"platform"}`。时间均为 Unix 秒，边界是：

- `next` 从 `overlap_starts_at == next.not_before` 起可用；
- `cutover_at` 是持有方切换到 `next` 的确定时间；
- `current` 在 `retire_current_at` 起立即拒绝，即使 warm runtime 尚未刷新；
- overlap 最长 7 天，每条 credential 最长 400 天；
- `revision` 必须严格高于 `AWSPREVIOUS` 和 `AGENTAUTH_VALIDATED` 指向的最后可信版本；回滚也必须
  发布更高 revision，不能把 `AWSCURRENT` 指回旧版本；
- `retired[]` 是 append-only ledger。每次删除 active 记录都要保留原 `credential_id`、对原 secret
  做 lowercase SHA-256，并写 `retired_at <=` 发布时间；既有条目不得删除或修改；
- active id/值与 retired id/hash 在平台和所有 tenant 间全局互斥。退役值不得换 owner 或用更高
  revision 复活。

## 2. 首次迁移

旧部署的 SecretString 是单个 bearer。业务栈保留旧模板使用的 legacy source Secret，并为平台和每个
tenant 新建 credential-set target Secret。Rust `AdminCredentialMigration` custom resource 会在
`AuthFn` 更新前执行以下幂等复制：

1. 最多 4 路并发读取全部 source 和 target，先完整校验 schema、owner、时间窗、active/retired
   全局唯一性；source 始终作为不透明 bearer，即使其字节恰好是 schema v1 JSON 也不得解析；
2. 已是合法 schema v1 的 target 只校验，不改写；target 已有历史版本却被改回裸值时拒绝重置；
3. 新 target 把 source 裸值包装为 revision 1 的单 current 文档，使用 `ttl_seconds=7776000`，由
   Secrets Manager 新 JSON 版本的实际创建时间派生创建/生效/90 天到期边界，bearer 本身保持不变；
   写入使用确定性 `ClientRequestToken` 先创建带 `AGENTAUTH_MIGRATED` 的候选版本，再以首次读取的
   placeholder `VersionId` 作为 `RemoveFromVersionId` 原子移动 `AWSCURRENT`，最后附加
   `AGENTAUTH_VALIDATED`。expected current 已变化时拒绝覆盖；在两次 stage 移动间中断时可幂等完成，
   并发重试不会制造两个 revision 1 版本，也不会因陈旧 placeholder 提前过期；
4. migration role 只读 source，只对 target 有 `PutSecretValue` 及仅限
   `AWSCURRENT`/`AGENTAUTH_VALIDATED` 的 stage 更新；任何 source 都不改写；
5. 任一读取、owner、transition 或唯一性检查失败即让 stack update 失败，主 Lambda 不进入新配置。

旧 warm Lambda 继续使用 source 中的 bearer；新 Lambda 从 target 读取相同 current，因此
CloudFormation 滚动更新期间无凭据分叉。若栈自动回滚，旧模板仍重新解析未改写的 source，而不会把
credential-set JSON 当作旧 `ADMIN_TOKEN`。迁移允许部分 target 写入后重试：已包装项幂等校验，剩余
target 继续处理。不要手工修改 custom resource 的依赖或让 `AuthFn` 与迁移并行更新。

部署后确认 `AdminCredentialMigration` 为 `CREATE_COMPLETE`/`UPDATE_COMPLETE`，再检查主区域 Auth
Lambda 环境只有 `AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN`，其指向的 `RuntimeBootstrapConfig`
文档只引用 target credential Secret ARN，且没有 `ADMIN_TOKEN`、`ADMIN_TOKENS_BY_TENANT` 或直接的
`ADMIN_CREDENTIAL_SECRET_ARN`；standby 因使用区域副本 ARN，仍直接注入对应 target ARN。当前
runtime 对 target 只有只读 `GetSecretValue`/`DescribeSecret` 和带
`secretsmanager:VersionStage=AGENTAUTH_VALIDATED` IAM condition 的
`UpdateSecretVersionStage`；后者只可管理可信锚点和
`AGENTAUTH_ROLLBACK_PENDING` 故障屏障，不能移动 `AWSCURRENT`/`AWSPREVIOUS`，且 runtime 不具
`PutSecretValue`。每个未验证 transition 都先把 pending stage 附加到本轮 `AWSCURRENT` 作为序列化
屏障，再核对完整 `AWSCURRENT`/`AWSPREVIOUS`/`AGENTAUTH_VALIDATED`/pending 映射。屏障保持期间，
以读到的旧 validated VersionId 作为 `RemoveFromVersionId` CAS 移动 `AGENTAUTH_VALIDATED`；确认完整
映射为 current=validated=pending 后才清 pending，并再次核对最终映射。validated 移动是唯一提交点。
提交前中断时旧可信锚点不变且 pending 持续 fail closed；提交后中断时新可信锚点已建立，但 pending
仍阻止其他 current 被验证。runtime 将 Secrets Manager 单次 operation 限制为 5 秒，并在 deadline
前保留 30 秒 checkpoint 安全窗；pending 建立后为 validated 提交与 pending 清理两次操作各预留最坏
10 秒。进入该门槛即拒绝提交回滚并保留 pending 屏障。可信 stage 缺失时即使 revision 为 1 也 fail
closed。同时比较 source 部署前后 SHA-256
保持不变，target `.current.secret` SHA-256 与
source 相同。兼容窗口内不要删除或轮换 source；它只供旧模板回滚，当前 runtime 对全部 legacy source
有显式 `Deny GetSecretValue/DescribeSecret`，即使 source 名称命中其他 allow 前缀也不能读取。

## 3. 正常无停机轮换

1. 选择 `overlap_starts_at`、`cutover_at`、`retire_current_at`。给 warm runtime 刷新和持有方切换留足
   时间，且 `retire_current_at <= current.expires_at`。
2. 生成独立高熵 `next`，发布 revision `N+1` 的双值文档。
3. 等待至少 `ADMIN_CREDENTIAL_CACHE_TTL_SECS + 5s`，分别验证 current 和 next 都成功。
4. 在 `cutover_at` 让所有持有方切到 next。通过审计确认出现 next 的 `credential_id`，审计中不得出现值。
5. 在 `retire_current_at` 验证 current 返回 401、next 成功。
6. 发布 revision `N+2`：把 next 提升为唯一 current，删除 `next` 和 `rotation`，并把旧 current 的
   `credential_id`、secret SHA-256、退役时间追加到 `retired[]`。再次等待缓存刷新并验证。

生成 next 时保持临时文件模式，不把值放进 shell history、日志、Issue 或 PR：

```bash
umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NEXT_VALUE=$(openssl rand -hex 32)
printf '%s' "$NEXT_VALUE" >"$WORK/next-credential"
chmod 0600 "$WORK/next-credential"
```

读取 target 当前版本和文档：

```bash
aws secretsmanager get-secret-value \
  --secret-id '<target-secret-arn>' \
  --profile default --region us-east-1 \
  --output json >"$WORK/current-version.json"
jq -er '.SecretString | fromjson' "$WORK/current-version.json" >"$WORK/current.json"
```

首次迁移的 revision 1 使用 `ttl_seconds`，其实际创建/生效/到期时间由该 Secrets Manager
版本的 `CreatedDate` 派生。第一次发布 revision 2 前必须只做一次等价展开，不能用新发布时间重置
90 天 lifetime：

```bash
CREATED_DATE="$(jq -er '.CreatedDate' "$WORK/current-version.json")"
if [[ "$CREATED_DATE" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  CREATED_AT="${CREATED_DATE%%.*}"
else
  CREATED_AT="$(date -u -d "$CREATED_DATE" +%s)"
fi
if jq -e '.revision == 1 and (.current.ttl_seconds | type == "number")' \
  "$WORK/current.json" >/dev/null; then
  jq --argjson created_at "$CREATED_AT" '
    .current |= (
      .created_at = $created_at
      | .not_before = $created_at
      | .expires_at = ($created_at + .ttl_seconds)
      | del(.ttl_seconds)
    )
  ' "$WORK/current.json" >"$WORK/current-explicit.json"
  mv "$WORK/current-explicit.json" "$WORK/current.json"
fi
```

使用 `jq` 构造新文档后，先通过 `PutSecretValue` 写入唯一 pending stage，再以读取时的
`VersionId` 作为 `RemoveFromVersionId` 原子移动 `AWSCURRENT`。不得直接让 `PutSecretValue` 自动覆盖
`AWSCURRENT`；若 expected version 已变化，说明有并发 operator，必须删除 pending stage、重新读取并
重算，不得用旧文档覆盖。仓库 `e2e/admin_credential_rotation.sh` 的 `put_current_document` 是参考实现。
发布前还必须检查：

- owner 和 Secret ARN 对应；
- revision 严格递增；
- 已存在 active credential 的 id、值、`created_at`、`not_before`、`expires_at` 必须保持不变；
  原 current 不得移到 next，只有原 next 可在收口时提升为 current；
- 保留同一 current/next 的后续 revision 只能保持或提前 `retire_current_at`，不得延长既定退役窗口；
- 完整继承已有 `retired[]`，并为每个被移除记录追加准确 id/hash；不得把退役明文写入 ledger；
- current/next 的 id 和值在平台及所有 tenant 间均不重复，也不命中任一 retired id/hash；
- `overlap_starts_at < cutover_at < retire_current_at`；
- next 的过期时间晚于 retirement。

从本地 `0600` 文件计算退役 hash，避免把值写进命令参数：

```bash
jq -jr '.current.secret' "$WORK/current.json" >"$WORK/retiring-secret"
sha256sum "$WORK/retiring-secret"
```

## 4. Retirement 前回滚

仅在 `now < retire_current_at` 时允许回滚：

1. 停止持有方切换，确认至少一个 current 持有方仍可用。
2. 发布更高 revision 的单值文档：保留原 current 及其原始时间，删除 next/rotation，并把被撤下
   next 的 id/hash 追加到 `retired[]`。
3. 等待缓存 TTL，验证 current 成功、next 返回 401。
4. 撤销 next 的分发并调查失败原因。

不得手工移动 `AWSCURRENT`、`AWSPREVIOUS` 或 `AGENTAUTH_VALIDATED`；warm runtime 会拒绝 revision
回退。rollback revision 必须在 retirement 前成为 `AWSCURRENT` 并由 runtime 完整校验、推进
`AGENTAUTH_VALIDATED`；只提前创建一个未激活版本不构成回滚。该 revision 一旦在 deadline 前通过
校验，已删除 rotation 的原 deadline 不会在之后让恢复的 current 失效。到达 retirement 后也不得重新启用旧值。冷启动会同时
比较 `AWSCURRENT`、`AWSPREVIOUS` 和
最后通过全 registry 校验的 `AGENTAUTH_VALIDATED`。非法版本不会推进可信锚点，因此连续发布多个非法
版本、回收实例或让旧版本离开 `AWSPREVIOUS` 都不能绕过 retired ledger。

如果 `AGENTAUTH_ROLLBACK_PENDING` 留在 `AWSCURRENT`，或 `AGENTAUTH_VALIDATED` 仍指向前一版本，
说明 checkpoint 未提交；deadline 后运行时会持续返回 503。恢复时先暂停该 deployment 的 admin
流量/实例并确认可信 stage 指向，从该可信文档构造两代连续递增、继承完整 ledger 的安全 promotion，
使中断版本离开 `AWSPREVIOUS`；确认两代都已发布后再移除遗留 pending stage 并恢复流量。不得只删除
pending stage 后继续使用未提交的 rollback。

## 5. 泄露轮换

泄露时不设置 overlap，也不保留回滚到泄露值的能力：

1. 生成新值。
2. 立即发布 revision `N+1` 的单值文档，新值为唯一 current，`not_before <= now`；把泄露 current
   及被同时移除的 next 全部追加到 `retired[]`。
3. 等待最多缓存 TTL；逐 owner 验证新值成功、泄露值 401。
4. 搜索 `ADMIN_BREAK_GLASS_USE`，按 credential id、tenant 和时间界定泄露使用范围。
5. 轮换任何保存过该值的下游存储，并按事件响应流程升级。

缓存过期后 Secrets Manager 不可用或任一 registry 文档非法时，admin 请求返回 503，不会继续无限使用
stale 值。

## 6. Warm runtime 与验收

生产默认缓存 TTL 为 30 秒，最大允许 300 秒。registry 每次作为整体刷新，owner Secret 最多 4 路
并发读取；网络 I/O 不持有 cache lock。runtime 先以单次 `DescribeSecret` 固定每个 owner 的完整
stage 映射，再按不可变 VersionId 并发读取 current/previous/validated/pending 文档，读取后重查映射；
任一 stage 变化都丢弃该 owner 快照。全部 owner 与全局唯一性通过后，再核对全部完整映射，最多 4 路
并发持 pending 屏障推进 validated，最后核对所有 owner 的 finalized 映射。只有读取前后、checkpoint
前后均一致才缓存本轮 registry。平台或任一 tenant 配置错误、可信 stage 推进失败时，所有 admin
credential 都 fail closed，避免 stage ABA、重复值、retired resurrection 或 owner 错配只在部分实例
生效。TTL 只限制后端读取频率，不缓存时间有效性：每次请求都按当前时间检查全部 owner 至少有一个
active credential；任一 owner 在缓存期内到期也立即让整库返回 503。

每次发布后执行：

- 同一 warm endpoint 连续请求，确认不重部署 Lambda 也能在 TTL 后接受新 revision；
- 平台：control Host 200，所有 tenant Host 401；
- t1：t1 Host 200，control/t2 Host 401；
- t2：t2 Host 200，control/t1 Host 401；
- retirement 后所有旧值 401；
- 低 revision、同 revision 改写、删改 retired ledger、跨 owner 复用退役值，以及连续两个非法版本
  试图越过 `AWSPREVIOUS` 时，冷/warm 请求均 503；
- CloudWatch 中存在 `ADMIN_BREAK_GLASS_USE priority=high tenant=<scope> credential_id=<id>`；
- API、CloudWatch、CloudFormation output 和部署 diff 中均不存在 bearer 值。

仓库脚本先以默认只读模式核对 source/target 哈希、runtime 对 source 的显式 deny、可信 stage 和
platform/t1/t2 Host 矩阵：

```bash
set -a
source .env
set +a
./e2e/admin_credential_rotation.sh
```

只有显式设置 `MUTATE=1` 才会真实发布版本。该模式先创建并自动删除一个 disposable Secret，以真实
Secrets Manager API 验证并发 `AWSCURRENT` CAS 只有一个 winner，且 stale validated CAS 不能覆盖
已提交 checkpoint；随后在已部署 owner 上执行 overlap、pending checkpoint 并发恢复、deadline 前
rollback、deadline 后遗留 pending 的 fail-closed、两代单调恢复和提交后 pending 幂等清理。在改动
credential 前，脚本会预先发布一个不接收线上流量的临时 Lambda version；之后先以其确定冷启动直接
验证非法 rollback 历史返回 503，再在单调恢复后确认 retired/rollback 终态。临时 version 在检查后
自动删除，`$LATEST` 的临时 description fallback 也会恢复。故障注入的并发请求允许短暂返回 503，
但 stage 必须在 30 秒内收敛并恢复 200，否则测试失败并执行两代单调恢复。该模式最终保留 t1 的已验证
rollback，并把 SaaS platform/t2 切换到新 current；运行后必须让对应持有方从 target Secret 更新
本地引用：

```bash
MUTATE=1 ./e2e/admin_credential_rotation.sh
```

配置错误返回 503 时，修复内容并发布更高 revision；不要降低 revision，也不要临时恢复明文环境变量。

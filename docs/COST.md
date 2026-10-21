# AWS 成本估算（us-east-1）

按 **2026-10-21** 的 AWS 公开按量单价，为整套 Agent Auth 留一个月费预算：

| 场景 | AS 请求量/月 | 部署规模 | 模型估算/月 | 建议预算/月 |
| --- | --- | --- | --- | --- |
| 小规模试用 | 10 万 | 单租户、单区域 | 约 **$45** | **$30–60** |
| 团队/业务自部署 | 100 万 | 单租户、单区域，启用生产备份 | 约 **$70** | **$50–100** |
| 多租户 SaaS | 1000 万 | 100 租户、单区域，启用生产备份 | 约 **$650** | **$500–1000** |

这里估的是授权服务、前端、数据库、密钥、监控和后台任务的 AWS 费用，
单位为 **美元/月**。各档位的请求、签名、存储等假设见下文；它们是预算模型，
不是实测账单或吞吐承诺。多区域灾备、较大的历史数据和不同调用结构会改变结果。

## 估算口径

主区域为 `us-east-1`，按一个月约 730 小时、现行按量付费的基础档单价估算。
**不扣免费额度、促销 credits、Savings Plans 或其他折扣，不含税费。**
账户实际可用的免费额度可能使账单更低；共享额度不能给每个部署重复扣减。
CloudFront 按服务请求的边缘地区计费，本例用北美单价，不是把其全球费用视为
`us-east-1` 的区域定价；CloudFront 打包套餐也未套入本模型。

`us-east-1` 是本篇的报价基准，业务主区和备用区可以配置为其他标准商业区域
（`aws` 分区，暂不考虑中国区、GovCloud 等分区）。当前多区域拓扑为单主区加一个备用区，
区域设置见 [多区域部署手册](MULTI_REGION_FAILOVER.md)；选择其他区域需刷新区域单价。
CloudFront 证书、全局 WAF/日志与 Lambda@Edge 按 AWS 要求保留在 `us-east-1`，
因此其他业务主区仍可能产生少量边缘区费用、跨区域引用辅助 Lambda 和跨区调用费用。

`100 万请求` 指到达 **AS 的 HTTP API** 的请求，包括授权、token、refresh、
exchange、introspection 和管理等调用。登录用户数与这个计数没有固定换算关系。
RS/MCP 的离线 JWT 校验在业务资源服务器本地完成；它的每次业务调用不会自动
产生一次 AS 或 KMS 调用。在线 introspection 则增加 AS 请求。前端静态请求、
CDN 流量和后台任务另有预算。

本次核对基线为 `582fbd4b73d6c88485e74bc2fe5960be40207ce4`。资源依据：

- [CDK 主栈](../infra/lib/agent-auth-stack.ts)：HTTP API、ARM64 Lambda、
  按需 DynamoDB/PITR、KMS、Secrets、归档、队列、监控和备份。
- [前端构造](../infra/lib/frontend-construct.ts)：私有 S3、CloudFront、
  CloudFront Functions、4 条注册 WAF 规则；SaaS 另有 origin-auth Lambda@Edge。
- [部署入口](../infra/bin/agent-auth-infra.ts)：自部署与 SaaS 是独立栈；
  SaaS 默认启用生产恢复，自部署需显式启用。
- [备用区栈](../infra/lib/agent-auth-standby-stack.ts)与
  [部署设计](DEPLOYMENT.md)：多区域资源与每租户 EC/RSA key set。

默认架构没有常驻 EC2、ECS、RDS 或 NAT Gateway，也未配置 Lambda
Provisioned Concurrency。多个 Lambda/按需表不按资源数量收固定月费；
主要按调用、运行时间、请求单位和存储收费。HTTP 入口使用现有 API Gateway，
Lambda Function URL 一律禁用。
每档只包含一个所选业务栈；同时运行 `AgentAuthDev` 和 `AgentAuthSaas` 时，
应分别估算后相加。

## 主要单价与计费对象

`M` 表示 100 万；GB 采用相应 AWS 计费口径。以下为基础档近似值，超大用量、
不同存储类别、附加服务和其他区域应重新查价。

| 项目 | us-east-1 基础单价 | 本项目的计费对象 |
| --- | --- | --- |
| [API Gateway][api-price] HTTP API | **$1/M 请求** | 当前使用 HTTP API |
| [Lambda][lambda-price] ARM64 | **$0.20/M 调用 + $0.0000133334/GB·秒** | TokenFn/NonTokenFn 为 512 MiB；后台任务另计 |
| [DynamoDB][ddb-price] 按需读/写 | **$0.125/M RRU、$0.625/M WRU** | 按实际读写单位，包含 GSI/事务等放大 |
| DynamoDB 存储/PITR | **$0.25/GB·月、$0.20/GB·月** | 存储含索引；PITR 按适用的表数据计费 |
| [KMS][kms-price] 客户管理密钥 | **$1/key·月** | 部署级密钥、租户密钥及各区域副本 |
| KMS ECC / RSA-2048 / 一般对称调用 | **$15/M、$3/M、$3/M** | ES256 Sign、RS256 Sign、grace 等加密调用 |
| [Secrets Manager][secrets-price] | **$0.40/secret·月 + $5/M API 调用** | 部署/租户凭据、运行配置及读取 |
| [CloudFront][cf-price] 北美 HTTPS/出网 | **$1/M 请求 + $0.085/GB** | 动态 API 与前端静态流量 |
| CloudFront Functions / Lambda@Edge | **$0.10/M；$0.60/M + $0.00005001/GB·秒** | Host/SPA 重写；SaaS 的受保护回源 |
| [WAF][waf-price] | **$5/ACL·月 + $1/rule·月 + $0.60/M 请求** | 默认 1 个 ACL、4 条自定义规则，固定约 $9/月 |
| [CloudWatch][cw-price] 日志写入/保有 | **$0.50/GB、$0.03/GB·月** | 应用、后台任务、WAF 等日志 |
| CloudWatch 自定义指标/标准告警 | **$0.30/metric·月、$0.10/alarm metric·月** | 按实际有数据的指标及维度、告警指标收费 |
| [S3][s3-price] Standard 存储/PUT/GET | **$0.023/GB·月；$5/M PUT、$0.40/M GET** | SPA、审计归档、失败记录和部署资产 |
| [AWS Backup][backup-price] DynamoDB 暖备份 | **$0.10/备份 GB·月** | 与 PITR 分开；当前生产计划每日一次、保留 35 天 |
| [SQS][sqs-price] / [EventBridge][events-price] | Standard **$0.40/M**、FIFO **$0.50/M** 请求；自定义事件约 **$1/M** | 投递、重试、收发/删除、调度和后台扫描 |
| [Route 53][dns-price] / [ACM][acm-price] | **$0.50/hosted zone·月**；标准非导出公共证书无证书费 | 本例使用 CloudFront alias；域名注册另计 |

DynamoDB 的 API 次数不等于 RRU/WRU：一致性、项目大小、Query/Scan、
事务和索引都会改变单位数。WAF 规则虽然只针对注册路径做限速，ACL 处理的
其他请求也会产生请求费。AWS 基础服务指标不能当作全部收费的自定义指标；
新增租户/客户端维度可能增加收费指标数量。

## 三档假设与费用拆分

下表是可替换的预算输入，**不是默认资源的准确数量，也不是已测得的平均消耗**：

| 输入 | 小规模试用 | 团队/业务自部署 | 多租户 SaaS |
| --- | --- | --- | --- |
| AS 请求数 | 10 万 | 100 万 | 1000 万 |
| 主 HTTP Lambda 计费内存/平均时长 | 512 MiB / 200 ms | 同左 | 同左 |
| 每个 AS 请求的 DynamoDB 预算 | 8 RRU + 4 WRU | 同左 | 同左 |
| 每 100 万 AS 请求的 KMS 调用 | 25 万 ECC、5 万 RSA、10 万对称 | 同左 | 同左 |
| CDN 请求 / AS 请求 | 1.2 倍（包含静态请求） | 同左 | 同左 |
| CDN 出网/月 | 3 GB | 30 GB | 300 GB |
| 表+索引存储 / PITR 表数据 | 1 / 1 GB | 5 / 4 GB | 50 / 40 GB |
| 日志新增/月 / 已计费保有量 | 0.2 / 1 GB | 2 / 10 GB | 20 / 100 GB |
| S3 已保有存储 | 1 GB | 10 GB | 100 GB |
| 生产备份保有量 | 不启用 | 70 GB | 700 GB |
| KMS 密钥数 | 5 | 6 | 6 + 2 × 100 = 206 |
| Secret 数预算 | 10 | 10 | 10 + 3 × 100 = 310 |
| 自定义指标 / 告警指标预算 | 50 / 20 | 同左 | 同左 |
| 后台任务、队列及调度预算/月 | $5 | $5 | $15 |

200 ms 是包含冷启动均摊的预算假设，采用**计费时长**；实际以部署后的
Lambda 指标为准。Secrets API 读取按每个 AS 请求均摊 0.1 次估算，缓存命中和
实例重建会改变它。SaaS Lambda@Edge 另按 128 MiB、平均 10 ms 估算。
每 100 万 AS 请求预留 10 万次 S3 PUT 与 10 万次 GET；归档对象数量、缓存
命中、失败重放会改变该项。后台预算包含空闲轮询、定时任务和少量重试，
大规模扫描、迁移、恢复或积压重放需要单独增加。
EventBridge 自定义事件费按实际发布的自定义事件计数，不把每次定时触发都
当作一个收费的自定义事件。

监控的 50/20 和部署级 10 个 Secrets 是取整预留。SaaS 每租户 3 个 Secrets
按一个 Admin 凭据及两个 SCIM source/target 凭据预算；已存在或迁移后保留的
Secret 也须计入。实际数量、使用方式与账单可能不同。

生产恢复会增加 1 把备份密钥。备份保有量按可恢复权威表 2 GB / 20 GB、
35 份完整大小保守预算为 70 GB / 700 GB；不把当天表大小当作所有备份的
总大小。实际以备份计费库存为准，增量/保有方式可能降低该值。
小规模档采用自部署的默认恢复开关；生产自部署档显式启用恢复，SaaS 档
使用当前默认开启的生产恢复。

把这些输入代入单价，月费约为：

| 费用（美元/月，已取整） | 小规模试用 | 团队/业务自部署 | 多租户 SaaS |
| --- | --- | --- | --- |
| API Gateway + 主 HTTP Lambda | 0.3 | 2.5 | 25 |
| CloudFront / Functions / SaaS Edge | 0.4 | 4 | 45 |
| DynamoDB 读写、存储、PITR | 0.8 | 6 | 56 |
| KMS 密钥及调用 | 5 | 10 | 248 |
| Secrets 存储及读取 | 4 | 5 | 129 |
| WAF | 9 | 10 | 16 |
| CloudWatch 日志、指标和告警 | 17 | 18 | 30 |
| S3 存储及请求 | 0.1 | 1 | 8 |
| AWS Backup | 0 | 7 | 70 |
| 后台任务、队列及调度预留 | 5 | 5 | 15 |
| DNS hosted zone 分摊 | 0.5 | 0.5 | 0.5 |
| **模型总额，约** | **45** | **70** | **650** |
| **建议预算范围** | **30–60** | **50–100** | **500–1000** |

金额经过取整，合计不要求逐项精确相等；预算范围用于容纳调用结构和资源
存量的差异。小规模时 KMS、Secrets、WAF、告警等费用占比高，即使没有业务
请求也应给已有固定收费资源留预算。上表还预留了自定义监控和后台活动，
实际未产生数据的指标与较少的活动可能使费用更低。

## 用自己的数据调整

主要公式如下，所有请求数均采用整次计数，内存单位为 GiB：

```text
主 HTTP Lambda = 调用数 × 0.0000002
               + 调用数 × 内存 GiB × 平均计费秒数 × 0.0000133334
DynamoDB 读写  = RRU × 0.000000125 + WRU × 0.000000625
KMS           = key 数 × 1
               + ECC 次数 × 0.000015 + RSA-2048 次数 × 0.000003
               + 一般对称调用数 × 0.000003
Secrets       = secret 数 × 0.40 + API 调用数 × 0.000005
日志          = 本月新增 GB × 0.50 + 已计费保有 GB × 0.03
备份          = 已计费备份库存 GB × 0.10
```

签名费随**实际签发**增加：access token、refresh 和 exchange 通常需要新的
access-token 签名；需要 ID token 的流程还有相应签名。RS 使用公钥本地校验
不按每次业务请求调用 KMS Verify。业务使用方式应先换算为 AS 请求和签名
次数，再替换本模型的请求比例。

SaaS 的稳态租户签名密钥是 EC + RSA 两把，因此主区仅该项就是
**$2 × 租户数/月**。本模型另预留每租户 3 个 Secrets，即 **$1.20 × 租户数/月**；
100 租户合计约 $320，1000 租户约 $3200，还要加共享基础设施、流量和数据费用。
密钥轮换重叠期、对称 key 自动轮换后的保留版本、尚未删除的旧 key 会增加
费用；禁用旧 key 不等于删除，本表包含保留的 legacy grace key。
若为每个租户再新增 3 个持续有数据的自定义指标，还会增加约
**$0.90 × 租户数/月**，这里未按租户额外配置这些指标。

长期运行时，保有量会增长：应用日志和多类审计/失败归档默认保留约 7 年，
部分其他日志有更短保留期。每月新增量不能直接代替日志、DynamoDB、S3 或
备份的累计计费库存。应按实际留存/压缩后的 GB 调整表格。

## 灾备与可选能力

**本表是单区域主部署，不含备用区。** 增加一个备用区时：

- 每租户两把 signing MRK 的副本再增加约 **$2/租户/月/备用区**；
  其他区域本地 KMS key、Secrets 副本也单独收费。
- DynamoDB Global Tables 的每个副本有存储与适用备份费用；复制写入、
  跨区域传输和 TTL 删除在副本产生的费用需要另外预算。
- 备用区有独立 HTTP/runtime、Region-local 表及后台任务；冷备、热备、
  演练和实际 failover 的调用量不同，不能把主区全部请求简单重复一遍。

先规划时，可在主区预算之外给**一个备用区再留约 50%–100%**。
例如上面的 100 租户 SaaS 可先按 **$1000–1500/月总预算**考虑主区加一备区。
这是灾备预留，不是第二个区域的实查报价；确定目标区域后应使用该区价格，
并按实际复制范围重算。

生产恢复、跨区复制和每租户独立密钥都按部署契约计入预算。策略重算、
大规模 SCIM/治理、SSF 投递和恢复演练也会增加 API/队列/数据库/日志活动。
本项目 token 热路径不直接调用 AVP；若另行接入
[Verified Permissions][avp-price]，按实际授权/批量/策略管理调用另计。
[SES][ses-price] 邮件（出站基础约 $0.10/千个收件人，附加数据另计）、短信、
WAF Bot/CAPTCHA/Marketplace 规则、CloudTrail 附加数据事件、导出证书、私有 CA 及
额外安全服务不在上表的基础配置中，启用后追加预算。

上表不含业务 RS/MCP 的机器、数据库、模型推理或外部 API，不含第三方 IdP、
域名注册、CI/开发机器、AWS 支持计划和人力。保留的旧栈、备份、日志、
Secret、key 及 CDK 部署资产也可能继续收费。

部署后可用 Cost Explorer 按服务查看月费，用 Budgets 设置提示，再用实际
AS 请求、计费时长、DynamoDB 单位、key/secret 数和保有 GB 更新本模型。

## AWS 官方价格来源

单价核对使用 AWS 官方 [Price List API](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html)
的当前区域报价，例如
[us-east-1 KMS 报价 JSON](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/awskms/current/us-east-1/index.json)。
CloudFront、Route 53 与 CloudFront WAF 的全球计费项使用全球报价，
并选取上述地区/基础档。以下链接方便在实际部署前刷新价格：

[api-price]: https://aws.amazon.com/api-gateway/pricing/
[lambda-price]: https://aws.amazon.com/lambda/pricing/
[ddb-price]: https://aws.amazon.com/dynamodb/pricing/on-demand/
[kms-price]: https://aws.amazon.com/kms/pricing/
[secrets-price]: https://aws.amazon.com/secrets-manager/pricing/
[cf-price]: https://aws.amazon.com/cloudfront/pricing/
[waf-price]: https://aws.amazon.com/waf/pricing/
[cw-price]: https://aws.amazon.com/cloudwatch/pricing/
[s3-price]: https://aws.amazon.com/s3/pricing/
[backup-price]: https://aws.amazon.com/backup/pricing/
[sqs-price]: https://aws.amazon.com/sqs/pricing/
[events-price]: https://aws.amazon.com/eventbridge/pricing/
[dns-price]: https://aws.amazon.com/route53/pricing/
[acm-price]: https://aws.amazon.com/certificate-manager/pricing/
[avp-price]: https://aws.amazon.com/verified-permissions/pricing/
[ses-price]: https://aws.amazon.com/ses/pricing/

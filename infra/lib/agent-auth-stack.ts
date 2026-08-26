import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { isIP } from 'node:net';
import {
  Stack,
  StackProps,
  Duration,
  RemovalPolicy,
  CfnOutput,
  Fn,
  CfnElement,
  CustomResource,
  SecretValue,
} from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigw from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3Notifications from 'aws-cdk-lib/aws-s3-notifications';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as glue from 'aws-cdk-lib/aws-glue';
import * as lakeformation from 'aws-cdk-lib/aws-lakeformation';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53targets from 'aws-cdk-lib/aws-route53-targets';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as backup from 'aws-cdk-lib/aws-backup';
import { NagSuppressions } from 'cdk-nag';
import { FrontendConstruct } from './frontend-construct';
import { requireWebBaseUrl } from './config';
import { normalizeCimdDomains } from './cimd-config';

interface DynamoDbReplicaProvider extends Construct {
  readonly onEventHandler: lambda.Function;
  readonly isCompleteHandler: lambda.Function;
}

export function resolveMtlsTruststoreAssetPath(
  moduleDirectory: string = __dirname,
): string {
  const candidates = [
    path.resolve(moduleDirectory, '..', 'assets', 'mtls-truststore'),
    path.resolve(moduleDirectory, '..', '..', 'assets', 'mtls-truststore'),
  ];
  const resolved = candidates.find((candidate) =>
    existsSync(path.join(candidate, 'truststore.pem')),
  );
  if (!resolved) {
    throw new Error(
      `missing mTLS truststore asset; checked ${candidates.join(', ')}`,
    );
  }
  return resolved;
}

export function validateRedirectPrefixAllowedHosts(
  configured: Readonly<Record<string, unknown>>,
  tenantIds: readonly string[],
  selfHosted: boolean,
): void {
  for (const [tenant, hosts] of Object.entries(configured)) {
    if (!tenantIds.includes(tenant) || (selfHosted && tenant !== 'default')) {
      throw new Error(
        'redirectPrefixAllowedHosts keys must be configured tenants (SelfHosted uses default)',
      );
    }
    if (
      !Array.isArray(hosts) ||
      hosts.some((host) => typeof host !== 'string')
    ) {
      throw new Error(
        'redirectPrefixAllowedHosts values must be arrays of exact host names',
      );
    }
    const normalized = hosts.map((host) =>
      host.trim().replace(/\.$/, '').toLowerCase(),
    );
    const validDomain = (host: string): boolean => {
      let parsedHost: string;
      try {
        parsedHost = new URL(`https://${host}/`).hostname;
      } catch {
        return false;
      }
      return (
        host.length <= 253 &&
        parsedHost === host &&
        isIP(parsedHost) === 0 &&
        host.split('.').every(
          (label) =>
            label.length > 0 &&
            label.length <= 63 &&
            /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
        )
      );
    };
    if (
      normalized.length !== new Set(normalized).size ||
      normalized.some(
        (host) =>
          !host ||
          host.includes('/') ||
          host.includes(':') ||
          host.includes('*') ||
          !/^[a-z0-9.-]+$/.test(host) ||
          !validDomain(host),
      )
    ) {
      throw new Error(
        'redirectPrefixAllowedHosts values must be unique exact host names',
      );
    }
  }
}

function consolidateDynamoDbReplicaProviderPolicies(
  stack: Stack,
  tables: readonly dynamodb.Table[],
  replicaRegions: readonly string[],
  bootstrapTable: dynamodb.Table,
): void {
  if (tables.length === 0 || replicaRegions.length === 0) {
    return;
  }
  if (!tables.includes(bootstrapTable)) {
    throw new Error('DynamoDB replica bootstrap table must be replicated');
  }

  const provider = stack.node.tryFindChild(
    '@aws-cdk/aws-dynamodb.ReplicaProvider',
  ) as DynamoDbReplicaProvider | undefined;
  const onEventRole = provider?.onEventHandler.role;
  const isCompleteRole = provider?.isCompleteHandler.role;
  if (!provider || !onEventRole || !isCompleteRole) {
    throw new Error('DynamoDB replica provider handlers and roles must exist');
  }

  const onEventResources: string[] = [];
  const isCompleteResources: string[] = [];
  const indexedTableLogicalIds: string[] = [];
  const expectedReplicaCount = new Set(replicaRegions).size;
  const replicaResources: Construct[] = [];
  let bootstrapReplica: Construct | undefined;

  for (const table of tables) {
    const generatedPolicyConstructs = table.node.children.filter((child) =>
      child.node.id.startsWith('SourceTableAttachedManagedPolicy-'),
    );
    if (generatedPolicyConstructs.length !== 2) {
      throw new Error(
        `${table.node.path} must have exactly two CDK replica provider policies`,
      );
    }
    for (const policyConstruct of generatedPolicyConstructs) {
      const cfnPolicies = policyConstruct.node
        .findAll()
        .filter(
          (resource): resource is iam.CfnManagedPolicy =>
            resource instanceof iam.CfnManagedPolicy,
        );
      if (cfnPolicies.length !== 1) {
        throw new Error(
          `${policyConstruct.node.path} must contain exactly one managed policy`,
        );
      }
      // CDK creates one managed policy per table for each singleton provider
      // role. Detach them so 10+ replicated tables cannot exceed IAM's default
      // managed-policy attachment quota; the shared policies below replace them.
      cfnPolicies[0].roles = undefined;
    }

    const cfnTable = table.node.defaultChild as dynamodb.CfnTable;
    const hasIndexes =
      stack.resolve(cfnTable.globalSecondaryIndexes) !== undefined ||
      stack.resolve(cfnTable.localSecondaryIndexes) !== undefined;
    onEventResources.push(table.tableArn);
    isCompleteResources.push(table.tableArn);
    if (hasIndexes) {
      onEventResources.push(`${table.tableArn}/index/*`);
      indexedTableLogicalIds.push(stack.getLogicalId(cfnTable));
    }
    for (const region of replicaRegions) {
      onEventResources.push(
        stack.formatArn({
          service: 'dynamodb',
          region,
          resource: 'table',
          resourceName: table.tableName,
        }),
      );
    }

    const replicas = table.node.children.filter((child) =>
      child.node.id.startsWith('Replica'),
    );
    if (replicas.length !== expectedReplicaCount) {
      throw new Error(
        `${table.node.path} must have ${expectedReplicaCount} replica resources`,
      );
    }
    replicaResources.push(...replicas);
    if (table === bootstrapTable) {
      [bootstrapReplica] = replicas;
    }
  }
  if (!bootstrapReplica) {
    throw new Error('DynamoDB replica bootstrap resource must exist');
  }

  const onEventPolicy = new iam.Policy(
    stack,
    'DynamoDbReplicaProviderOnEventTablePolicy',
    {
      statements: [
        new iam.PolicyStatement({
          actions: ['dynamodb:*'],
          resources: onEventResources,
        }),
      ],
    },
  );
  onEventPolicy.attachToRole(onEventRole);

  const isCompletePolicy = new iam.Policy(
    stack,
    'DynamoDbReplicaProviderIsCompleteTablePolicy',
    {
      statements: [
        new iam.PolicyStatement({
          actions: ['dynamodb:DescribeTable'],
          resources: isCompleteResources,
        }),
      ],
    },
  );
  isCompletePolicy.attachToRole(isCompleteRole);

  for (const replica of replicaResources) {
    replica.node.addDependency(onEventPolicy, isCompletePolicy);
    if (replica !== bootstrapReplica) {
      // The first replica creates the account-level DynamoDB replication
      // service role. Wait for it to become ACTIVE before fanning out so the
      // remaining replicas cannot race IAM policy propagation.
      replica.node.addDependency(bootstrapReplica);
    }
  }

  NagSuppressions.addResourceSuppressions(onEventPolicy, [
    {
      id: 'AwsSolutions-IAM5',
      reason:
        'The CDK-owned replica provider needs the DynamoDB replica lifecycle API surface. Resources are limited to the exact replicated source and destination tables, plus index suffixes only for source tables that define indexes.',
      appliesTo: [
        'Action::dynamodb:*',
        ...indexedTableLogicalIds.map(
          (logicalId) => `Resource::<${logicalId}.Arn>/index/*`,
        ),
      ],
    },
  ]);
}

/**
 * Agent Auth P0 code flow 最小栈:KMS(ES256 签名)+ DynamoDB(codes/clients)+ Lambda(Rust arm64)
 * + API Gateway HTTP API。**触发源 = API Gateway,绝不用 Lambda Function URL**(见约定)。
 *
 * 只做资源编排,业务逻辑在 crates/(Rust)。资源打 dev 标记、可 `cdk destroy` 一键拆。
 * 决策真相源:docs/DESIGN §8;spec 005 实现边界 [b]。
 */
export type DcrMode = 'open' | 'initial_access_token';

export interface TenantResidencyConfig {
  readonly jurisdiction: string;
  readonly allowed_regions: readonly string[];
  readonly governance_region?: string;
}

export interface AgentAuthStackProps extends StackProps {
  /** Rust Lambda 产物目录(cargo lambda build 输出:含 bootstrap)。 */
  readonly lambdaAssetPath: string;
  /** security event DynamoDB Stream → S3 归档 worker 产物目录。 */
  readonly securityEventArchiveAssetPath: string;
  /** SecurityEvents Stream → SSF delivery outbox/push worker 产物目录。 */
  readonly ssfDeliveryAssetPath: string;
  /** Durable user-erasure and tenant-offboarding SQS worker artifact. */
  readonly governanceWorkerAssetPath: string;
  /** SaaS tenant EC/RSA key onboarding and rotation worker. Required for SaaS. */
  readonly tenantKeyProvisionerAssetPath?: string;
  /**
   * Regions that must contain a probed KMS multi-Region replica before a new
   * SaaS tenant signing generation can be published.
   */
  readonly tenantKeyReplicaRegions?: readonly string[];
  /**
   * ES256 active/published key set for a deployable rotation phase. Both values
   * must be KMS key ARNs and active must occur in published. Omit both to use
   * the stack-managed SigningKeyEs256 only.
   */
  readonly activeEcSigningKeyArn?: string;
  readonly publishedEcSigningKeyArns?: readonly string[];
  /** client 回收后台任务 Lambda 产物目录(agent-auth-reclaim bin,spec 005 §9.5)。缺省不部署回收任务。 */
  readonly reclaimAssetPath?: string;
  /** admin 预迁移与部署后 client/DCR 迁移共用的 Rust Lambda 产物目录。 */
  readonly credentialMigrationAssetPath: string;
  /** ⚠️ 仅 dev 栈:是否允许 authorize 的 login_user 占位(未接真实登录时 e2e)。生产 MUST false。 */
  readonly allowLoginPlaceholder?: boolean;
  /** DCR 准入档。缺省不注入,由 runtime fail-closed 到无票据的 initial_access_token 档。 */
  readonly dcrMode?: DcrMode;
  /** 是否部署前端 SPA(CloudFront+S3);需 web/dist 已构建。默认 true。 */
  readonly deployFrontend?: boolean;
  /** CloudFront `POST /register` IP/Host/ASN WAF coarse fallback (C10.8). */
  readonly registrationWafEnabled?: boolean;
  /** Override the SPA asset directory for deterministic tests; production defaults to web/dist. */
  readonly frontendAssetPath?: string;
  /** 前端公开 origin(magic-link/浏览器回跳与 __Host- cookie 同源);必填,不得使用裸 API Gateway。 */
  readonly webBaseUrl: string;
  /** Admin one-time invitation validity in seconds. Default 24 hours; 5 minutes to 7 days. */
  readonly invitationTtlSecs?: number;
  /**
   * 发布阶段(C1.2:决定哪些端点/grant 可达 + discovery 如实宣告)。`p0`..`p3`;缺省 `p2`
   * (所有 P2 grant——client_credentials/token-exchange/device/CIBA 已落地)。Rust 侧
   * `from_env_aws` 对无法识别值 fail-safe 回落 P1。
   */
  readonly phase?: string;
  /** 上游 IdP 联邦开关(spec 003 §4,C9.5):true → /federation/callback 可达 + idp_hint 生效。默认关。 */
  readonly federationEnabled?: boolean;
  /** Passkey 开关(spec 003 §3,C9.4):true → 注入 AGENT_AUTH_PASSKEY_ENABLED=1。默认关。 */
  readonly passkeyEnabled?: boolean;
  /** Bump after rotating one SaaS edge-origin Secret slot to refresh CloudFront and Lambda. */
  readonly saasOriginAuthRevision?: string;
  /** Stable MCP EMA profile 开关(spec 031/C13):默认关；开启时必须同时提供 emaPolicies。 */
  readonly emaEnabled?: boolean;
  /** 已在 Rust 启动期完整校验的 tenant-scoped EMA policy JSON array。 */
  readonly emaPolicies?: string;
  /** MCP Client ID Metadata Document feature gate. Requires at least one trusted domain policy. */
  readonly cimdEnabled?: boolean;
  /** Deployment-wide exact CIMD host allowlist. */
  readonly cimdAllowedDomains?: readonly string[];
  /** SaaS tenant label to exact CIMD host allowlist. SelfHosted stacks must not set this. */
  readonly cimdTenantAllowedDomains?: Readonly<Record<string, readonly string[]>>;
  /**
   * Cedar/AVP 授权引擎开关(spec 005 §7,C10.17):true → Grant 创建时 Cedar 预判写 effective +
   * 签发热路径 stale fail-safe 闸。默认关(字节等价现网)。**MUST 与重算任务同批启用**(recomputeAssetPath)。
   */
  readonly authzEnabled?: boolean;
  /** Cedar 策略集文本(部署级;authzEnabled 时注入 Lambda env AGENT_AUTH_POLICY_SET)。self-host 一份。 */
  readonly policySet?: string;
  /** 策略重算后台任务 Lambda 产物目录(agent-auth-recompute bin,spec 005 §7)。缺省不部署重算任务。 */
  readonly recomputeAssetPath?: string;
  /** 自定义域名(spec 003 §4 联邦真机 / spec 025):CloudFront 别名 + ACM(us-east-1)+ Route53 alias。 */
  readonly customDomain?: string;
  readonly certArn?: string;
  readonly hostedZoneId?: string;
  readonly hostedZoneName?: string;
  /**
   * SaaS 多租户形态(spec 020 §2.3/§2.5):设置后 Lambda 以 `AGENT_AUTH_FORM=saas` 启动,租户走
   * `t{N}.<zone>` 子域(每子域一个独立 OIDC issuer),`controlHost` 是控制面(非 issuer)。
   * 需同时开 `enableTenantPartitioning` 才真正物理隔离数据面(否则各租户共享 "" 分区,仅 issuer 不同)。
   */
  readonly saasZone?: string;
  readonly saasControlHost?: string;
  /** 数据面 tenant 分区开关(spec 020 §2.3,C10.19;env AGENT_AUTH_ENABLE_TENANT_PARTITIONING)。 */
  readonly enableTenantPartitioning?: boolean;
  /**
   * 逐租户 ECC/access Sign 公平闸容量(spec 020 §3.1 / C10.14;env AGENT_AUTH_KMS_TENANT_GATE_CAPACITY)。
   * 设正值即启用:单个 noisy 租户超自己份额即 503、**不扣全局桶**(隔离,不牵连守规租户)。默认不设=关。
   * ⚠️ **仅 SaaS 有意义**(自部署单租户无 noisy-neighbor);份额按"Σ 份额 ≤ 该区 KMS Sign 配额"标定,
   * refill(每秒补充)可另配 `kmsTenantGateRefillPerSec`(默认 20)。
   */
  readonly kmsTenantGateCapacity?: number;
  /** 逐租户 Sign 闸补充速率(个/秒,env AGENT_AUTH_KMS_TENANT_GATE_REFILL_PER_SEC;默认 20)。 */
  readonly kmsTenantGateRefillPerSec?: number;
  /**
   * SaaS 每租户旧版 admin-token source Secret ARN。key=租户标签(如 t1),value=该租户唯一 Secret ARN。
   * 首次升级把 bearer 复制到栈托管的 credential-set target Secret，source 保持不变供旧模板回滚。
   * SaaS 下必须与 customDomains 中除 control host 外的租户集合完全一致；SelfHosted 不使用。
   */
  readonly tenantAdminSecretArns?: Readonly<Record<string, string>>;
  /**
   * Optional per-tenant SaaS subject profile. Missing tenants keep the SaaS
   * privacy default (`pairwise`); keys must be configured issuer tenants.
   */
  readonly tenantSubjectTypes?: Readonly<Record<string, 'public' | 'pairwise'>>;
  /** Exact redirect hosts allowed to use confidential prefix matching, keyed by tenant. */
  readonly redirectPrefixAllowedHosts?: Readonly<Record<string, readonly string[]>>;
  /**
   * SaaS tenants whose owner-bound admin/SCIM target Secrets were intentionally
   * removed by the offboarding workflow. Only those credential migration
   * entries may treat Secrets Manager `Removed` as an already-complete state.
   */
  readonly offboardedTenantIds?: readonly string[];
  /**
   * Deployment-owned data-residency map. Keys must exactly match issuer
   * tenants; allowed Regions must exactly match the primary plus configured
   * durable replicas. Omit to derive one jurisdiction from the stack Region.
   */
  readonly tenantResidency?: Readonly<Record<string, TenantResidencyConfig>>;
  /**
   * BYOD(投放方式 b,spec 010 §5.4 / C8.1b)开关:true → 建 DomainMap 表 + 注入 AGENT_AUTH_BYOD_ENABLED=1
   * → 数据面 `GET /.well-known/oauth-protected-resource` 按入站 Host 托管 PRM(admin 面绑 domain→resource)。
   * 默认关(字节等价现网;well-known 短路 404、admin bind 拒)。
   */
  readonly byodEnabled?: boolean;
  /**
   * BYOD 真机演示别名(自有 zone 下 host,如 `mcp-demo.saas.example.com`):加到 CloudFront 别名 + Route53
   * A/AAAA alias,复用现有 `*.<zone>` 通配证书(**无新证书**)。⚠️ 该 host 是 issuer zone 子域,注册期
   * 护栏会挡它作 prm_domain——演示须显式知悉(真跨组织 BYOD 域名 = P3,见 spec 010 §5.4)。
   */
  readonly byodDemoDomain?: string;
  /**
   * CloudFront 别名要覆盖的**全部**子域(SaaS:t1/t2/c.<zone>)。留空则回落到单个 `customDomain`。
   * ACM 证书须覆盖这里的每一个 host(SAN 或通配 `*.zone`);Route53 为每个建 A/AAAA alias。
   */
  readonly customDomains?: string[];
  /**
   * X.509-SVID / mTLS(spec 012 §1.4 / C5.7,P3):**独立 mTLS 自定义域名**(绕过 CloudFront,直连 API Gateway
   * 连接级双向 TLS)。`mtlsSvidEnabled=true` 且域名配置齐备时才建 API Gateway DomainName、播种占位
   * truststore、映射同一 HttpApi/$default 并创建 Route53 alias。**仅 SelfHosted**(评审 B1);证书
   * `mtlsCertArn`(区域证书,us-east-1)+ 归属 zone(mtlsZoneId/Name)。缺任一或 feature 关闭都不建。
   * 运维 onboarding 时须用签发 SVID 的真实 CA bundle PEM 覆盖占位 `truststore.pem` 并 bump version。
   */
  readonly mtlsDomain?: string;
  readonly mtlsCertArn?: string;
  readonly mtlsZoneId?: string;
  readonly mtlsZoneName?: string;
  /** X.509-mTLS feature 开关(注入 Lambda env AGENT_AUTH_MTLS_SVID_ENABLED=1)。默认关=字节等价。 */
  readonly mtlsSvidEnabled?: boolean;
  /**
   * 生产恢复 profile：长期权威数据、静态 KMS key 和受管 Secrets 使用 RETAIN，
   * 并建立 35 天日备份与专用恢复角色。短命/一次性工件继续 DESTROY，恢复后必须重走协议。
   */
  readonly productionRecoveryEnabled?: boolean;
  /** Exact deployed Git commit, required for runtime and migration coverage identity. */
  readonly deploymentCommit: string;
}

export class AgentAuthStack extends Stack {
  public readonly credentialMigrationHandler?: lambda.Function;
  public readonly authorityReferenceMigrationHandler: lambda.Function;

  constructor(scope: Construct, id: string, props: AgentAuthStackProps) {
    super(scope, id, props);

    const webBaseUrl = requireWebBaseUrl('webBaseUrl', props.webBaseUrl);
    const invitationTtlSecs = props.invitationTtlSecs ?? 86_400;
    if (
      !Number.isSafeInteger(invitationTtlSecs) ||
      invitationTtlSecs < 300 ||
      invitationTtlSecs > 604_800
    ) {
      throw new Error('invitationTtlSecs must be an integer between 300 and 604800');
    }
    if (!/^[0-9a-f]{40}$/.test(props.deploymentCommit)) {
      throw new Error(
        'AGENT_AUTH_DEPLOYMENT_COMMIT must be a full lowercase Git SHA',
      );
    }
    const saasOriginAuthRevision = props.saasOriginAuthRevision ?? '1';
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(saasOriginAuthRevision)) {
      throw new Error(
        'saasOriginAuthRevision must be 1-64 characters from A-Z, a-z, 0-9, dot, underscore, or hyphen',
      );
    }

    // **启用前置校验(评审 H3/M3,spec 005 §7 补强 ⑨)**:authz 开则**必须**提供策略集,否则 current_pv 发布
    // 无源、主 Lambda 创建路径对每条 Grant 走 fail-closed 降级/热路径 503。synth 期挡下(不等 Lambda 首跑才暴露)。
    if (props.authzEnabled && (!props.policySet || props.policySet.trim().length === 0)) {
      throw new Error(
        'authzEnabled=true 但未提供 policySet(AGENT_AUTH_POLICY_SET_FILE / AGENT_AUTH_POLICY_SET):' +
          'Cedar 授权引擎启用 MUST 附带策略集,否则 current_pv 无发布源、签发路径 fail-closed。' +
          '安全启用顺序见 docs/DEPLOYMENT.md(先建 GSI+确认 ACTIVE → 带 policySet 部署 authzEnabled → ' +
          'RecomputeFn 首跑 publish+backfill 达 current_pv≥1 且存量 effective_pv 追平)。',
      );
    }

    if (props.emaEnabled && (!props.emaPolicies || props.emaPolicies.trim().length === 0)) {
      throw new Error(
        'emaEnabled=true requires non-empty emaPolicies (AGENT_AUTH_EMA_POLICIES)',
      );
    }
    if (props.emaEnabled && !['p2', 'p3'].includes((props.phase ?? 'p2').toLowerCase())) {
      throw new Error('emaEnabled=true requires phase p2 or later');
    }
    let canonicalEmaPolicies: string | undefined;
    if (props.emaPolicies) {
      try {
        const parsed = JSON.parse(props.emaPolicies) as unknown;
        if (!Array.isArray(parsed) || parsed.length === 0) {
          throw new Error('must be a non-empty JSON array');
        }
        canonicalEmaPolicies = JSON.stringify(parsed);
        if (Buffer.byteLength(canonicalEmaPolicies, 'utf8') > 65_536) {
          throw new Error('must not exceed the 64 KiB Secrets Manager value limit');
        }
      } catch (error) {
        throw new Error(`emaPolicies invalid JSON: ${String(error)}`);
      }
    }
    if (props.emaEnabled && !props.deploymentCommit) {
      throw new Error('emaEnabled=true requires deploymentCommit evidence binding');
    }

    if (
      (props.saasZone || props.saasControlHost) &&
      (props.allowLoginPlaceholder || props.dcrMode)
    ) {
      throw new Error(
        'SaaS Stack 禁止部署级 DCR/占位登录配置;DCR 必须等待逐租户控制面,用户认证必须走真实流程',
      );
    }

    if (
      props.dcrMode !== undefined &&
      props.dcrMode !== 'open' &&
      props.dcrMode !== 'initial_access_token'
    ) {
      throw new Error('CDK 仅允许已实现的 DCR 档:open / initial_access_token');
    }
    let saasTenantIds: string[] = [];
    const tenantKeyReplicaRegions = [...(props.tenantKeyReplicaRegions ?? [])];
    if (
      tenantKeyReplicaRegions.length > 0 &&
      props.deploymentCommit === undefined
    ) {
      throw new Error(
        'multi-Region deployment requires AGENT_AUTH_DEPLOYMENT_COMMIT as a full lowercase Git SHA',
      );
    }
    if (
      new Set(tenantKeyReplicaRegions).size !== tenantKeyReplicaRegions.length ||
      tenantKeyReplicaRegions.some(
        (replicaRegion) =>
          replicaRegion === this.region ||
          !/^[a-z]{2}(?:-gov)?-[a-z]+-\d+$/.test(replicaRegion),
      )
    ) {
      throw new Error(
        'tenantKeyReplicaRegions must contain unique non-primary AWS regions',
      );
    }
    if (
      tenantKeyReplicaRegions.length > 0 &&
      (this.region !== 'us-east-1' ||
        tenantKeyReplicaRegions.length !== 1 ||
      tenantKeyReplicaRegions[0] !== 'us-west-2')
    ) {
      throw new Error(
        'multi-Region deployment supports only primary us-east-1 and standby us-west-2',
      );
    }
    if (
      props.productionRecoveryEnabled &&
      (props.saasZone || props.saasControlHost) &&
      (this.region !== 'us-east-1' ||
        tenantKeyReplicaRegions.length !== 1 ||
        tenantKeyReplicaRegions[0] !== 'us-west-2')
    ) {
      throw new Error(
        'production SaaS requires the replay-safe us-east-1/us-west-2 Region fence; ' +
          'set SAAS_REPLICA_REGIONS=us-west-2',
      );
    }
    let legacyTenantAdminSecrets: Record<string, secretsmanager.ISecret> = {};
    if (props.saasZone || props.saasControlHost) {
      if (!props.saasZone || !props.saasControlHost) {
        throw new Error('SaaS 配置必须同时提供 saasZone 与 saasControlHost');
      }
      const domains = props.customDomains ?? [];
      if (!domains.includes(props.saasControlHost)) {
        throw new Error('SaaS customDomains 必须包含 saasControlHost');
      }
      const suffix = `.${props.saasZone}`;
      saasTenantIds = domains
        .filter((domain) => domain !== props.saasControlHost)
        .map((domain) => {
          if (!domain.endsWith(suffix)) {
            throw new Error(`SaaS 租户域名 ${domain} 不属于 zone ${props.saasZone}`);
          }
          const tenant = domain.slice(0, -suffix.length);
          if (!tenant || tenant.includes('.')) {
            throw new Error(`SaaS 租户域名 ${domain} 必须是 zone 下单层标签`);
          }
          return tenant;
        })
        .sort();
      if (saasTenantIds.length === 0 || new Set(saasTenantIds).size !== saasTenantIds.length) {
        throw new Error('SaaS 必须至少配置一个且不得重复的租户域名');
      }

      const secretArns = props.tenantAdminSecretArns ?? {};
      const configuredTenants = Object.keys(secretArns).sort();
      if (JSON.stringify(configuredTenants) !== JSON.stringify(saasTenantIds)) {
        throw new Error(
          'tenantAdminSecretArns 的 tenant 集合必须与 customDomains 中的 SaaS 租户完全一致',
        );
      }
      const arns = Object.values(secretArns);
      if (
        new Set(arns).size !== arns.length ||
        arns.some((arn) => !arn.includes(':secretsmanager:') || !arn.includes(':secret:'))
      ) {
        throw new Error('SaaS 每租户 admin Secret ARN 必须合法且互不相同');
      }
      legacyTenantAdminSecrets = Object.fromEntries(
        configuredTenants.map((tenant, index) => {
          const secret = secretsmanager.Secret.fromSecretCompleteArn(
            this,
            `TenantAdminToken${index}`,
            secretArns[tenant],
          );
          return [tenant, secret];
        }),
      );
      const subjectTypeTenants = Object.keys(props.tenantSubjectTypes ?? {});
      if (
        subjectTypeTenants.some((tenant) => !saasTenantIds.includes(tenant)) ||
        Object.values(props.tenantSubjectTypes ?? {}).some(
          (subjectType) => subjectType !== 'public' && subjectType !== 'pairwise',
        )
      ) {
        throw new Error(
          'tenantSubjectTypes 只能包含已配置 SaaS tenant，值必须为 public 或 pairwise',
        );
      }
      validateRedirectPrefixAllowedHosts(
        props.redirectPrefixAllowedHosts ?? {},
        saasTenantIds,
        false,
      );
      const offboardedTenantIds = [...(props.offboardedTenantIds ?? [])];
      if (
        new Set(offboardedTenantIds).size !== offboardedTenantIds.length ||
        offboardedTenantIds.some((tenant) => !saasTenantIds.includes(tenant))
      ) {
        throw new Error(
          'offboardedTenantIds 必须唯一且只能包含已配置 SaaS tenant',
        );
      }
    } else {
      if (Object.keys(props.tenantSubjectTypes ?? {}).length > 0) {
        throw new Error('SelfHosted 不得配置 tenantSubjectTypes');
      }
      validateRedirectPrefixAllowedHosts(
        props.redirectPrefixAllowedHosts ?? {},
        ['default'],
        true,
      );
      if ((props.offboardedTenantIds ?? []).length > 0) {
        throw new Error('SelfHosted 不得配置 offboardedTenantIds');
      }
    }
    const cimdAllowedDomains = normalizeCimdDomains(
      props.cimdAllowedDomains ?? [],
      'cimdAllowedDomains',
    );
    const cimdTenantAllowedDomains = Object.fromEntries(
      Object.entries(props.cimdTenantAllowedDomains ?? {}).map(([tenant, domains]) => {
        if (!tenant || tenant.trim() !== tenant) {
          throw new Error('cimdTenantAllowedDomains keys must be canonical tenant IDs');
        }
        return [
          tenant,
          normalizeCimdDomains(domains, `cimdTenantAllowedDomains.${tenant}`),
        ];
      }),
    );
    const cimdTenantPolicyKeys = Object.keys(cimdTenantAllowedDomains);
    const hasCimdPolicy =
      cimdAllowedDomains.length > 0 ||
      Object.values(cimdTenantAllowedDomains).some((domains) => domains.length > 0);
    const normalizedPhase = (props.phase ?? 'p2')
      .trim()
      .toLowerCase()
      .replace(/[.-]/g, '_');
    const mtlsSvidProfileEligible =
      props.mtlsSvidEnabled === true &&
      normalizedPhase === 'p3' &&
      saasTenantIds.length === 0;
    const mtlsSvidEndpointConfigured = Boolean(
      props.mtlsDomain &&
        props.mtlsCertArn &&
        props.mtlsZoneId &&
        props.mtlsZoneName,
    );
    if (mtlsSvidProfileEligible && !mtlsSvidEndpointConfigured) {
      throw new Error(
        'mTLS SVID deployment requires mtlsDomain, mtlsCertArn, mtlsZoneId, and mtlsZoneName',
      );
    }
    const mtlsSvidDeploymentEnabled =
      mtlsSvidProfileEligible && mtlsSvidEndpointConfigured;
    if (
      props.cimdEnabled &&
      (normalizedPhase === 'p0' || normalizedPhase === 'p0_5')
    ) {
      throw new Error('cimdEnabled=true requires phase p1 or later');
    }
    if (props.cimdEnabled && !hasCimdPolicy) {
      throw new Error('cimdEnabled=true requires a non-empty global or tenant domain allowlist');
    }
    if (props.cimdEnabled && saasTenantIds.length > 0 && !props.enableTenantPartitioning) {
      throw new Error('SaaS CIMD requires enableTenantPartitioning=true');
    }
    if (saasTenantIds.length === 0 && cimdTenantPolicyKeys.length > 0) {
      throw new Error('SelfHosted CIMD does not accept tenant domain policies');
    }
    if (
      saasTenantIds.length > 0 &&
      cimdTenantPolicyKeys.some((tenant) => !saasTenantIds.includes(tenant))
    ) {
      throw new Error('CIMD tenant domain policy contains a tenant outside the SaaS domain set');
    }
    if (saasTenantIds.length === 0 && tenantKeyReplicaRegions.length > 0) {
      throw new Error('tenantKeyReplicaRegions is only supported by the SaaS key control plane');
    }
    const durableReplication =
      tenantKeyReplicaRegions.length > 0
        ? { replicationRegions: tenantKeyReplicaRegions }
        : {};
    const runtimeSecretReplication =
      tenantKeyReplicaRegions.length > 0
        ? {
            replicaRegions: tenantKeyReplicaRegions.map((region) => ({ region })),
          }
        : {};
    const cloudFrontOriginSecret =
      saasTenantIds.length > 0
        ? new secretsmanager.Secret(this, 'CloudFrontOriginAuthSecret', {
            secretName: `${this.stackName}/cloudfront-origin-auth`,
            description:
              'Primary CloudFront-to-origin credential for all SaaS HTTP routes',
            generateSecretString: {
              excludePunctuation: true,
              passwordLength: 48,
            },
            removalPolicy: RemovalPolicy.DESTROY,
            ...runtimeSecretReplication,
          })
        : undefined;
    const cloudFrontOriginSecondarySecret =
      saasTenantIds.length > 0
        ? new secretsmanager.Secret(
            this,
            'CloudFrontOriginAuthSecondarySecret',
            {
              secretName: `${this.stackName}/cloudfront-origin-auth-secondary`,
              description:
                'Secondary CloudFront-to-origin credential for zero-downtime SaaS edge rotation',
              generateSecretString: {
                excludePunctuation: true,
                passwordLength: 48,
              },
              removalPolicy: RemovalPolicy.DESTROY,
              ...runtimeSecretReplication,
            },
          )
        : undefined;
    for (const secret of [
      cloudFrontOriginSecret,
      cloudFrontOriginSecondarySecret,
    ]) {
      if (secret) {
        NagSuppressions.addResourceSuppressions(secret, [
          {
            id: 'AwsSolutions-SMG4',
            reason:
              'The two machine-only edge credentials rotate one slot at a time; the unchanged slot authenticates traffic while CloudFront and both runtimes converge.',
          },
        ]);
      }
    }
    const governanceTenantIds =
      saasTenantIds.length > 0 ? saasTenantIds : ['default'];
    const storageRegions = [this.region, ...tenantKeyReplicaRegions].sort();
    const derivedJurisdiction = this.region.split('-')[0];
    const tenantResidency = props.tenantResidency ?? Object.fromEntries(
      governanceTenantIds.map((tenant) => [
        tenant,
        {
          jurisdiction: derivedJurisdiction,
          allowed_regions: storageRegions,
          governance_region: this.region,
        },
      ]),
    );
    if (
      JSON.stringify(Object.keys(tenantResidency).sort()) !==
      JSON.stringify(governanceTenantIds)
    ) {
      throw new Error(
        'tenantResidency keys must exactly match the configured issuer tenants',
      );
    }
    for (const [tenant, residency] of Object.entries(tenantResidency)) {
      const allowed = [...residency.allowed_regions].sort();
      if (
        !/^[A-Za-z0-9_.:-]{1,64}$/.test(residency.jurisdiction) ||
        new Set(allowed).size !== allowed.length ||
        JSON.stringify(allowed) !== JSON.stringify(storageRegions) ||
        !allowed.includes(residency.governance_region ?? this.region)
      ) {
        throw new Error(
          `tenantResidency for ${tenant} must use a bounded jurisdiction, exactly the deployed storage Regions, and one allowed governance Region`,
        );
      }
    }
    const canonicalTenantResidency = Object.fromEntries(
      governanceTenantIds.map((tenant) => [
        tenant,
        {
          jurisdiction: tenantResidency[tenant].jurisdiction,
          allowed_regions: [...tenantResidency[tenant].allowed_regions].sort(),
          governance_region:
            tenantResidency[tenant].governance_region ?? this.region,
        },
      ]),
    );
    // Cedar 策略集 synth 期语法校验(补强 ⑨:坏策略部署前挡下,免 fleet-wide fail-closed):最小括号/分号
    // 结构 sanity(完整 Cedar validate 在运行时 publish_policy_from_env fail-closed 兜底 + CI 可加 cedar CLI)。
    if (props.policySet && props.policySet.trim().length > 0) {
      const p = props.policySet;
      const balanced = (a: string, b: string) =>
        (p.split(a).length - 1) === (p.split(b).length - 1);
      if (!balanced('(', ')') || !p.includes('permit') && !p.includes('forbid')) {
        throw new Error(
          'policySet 未通过 synth 期 Cedar sanity(括号不配平 或 无 permit/forbid 语句):' +
            '疑似坏策略,部署前挡下(spec 005 §7 补强 ⑨)。完整校验见运行时 publish fail-closed。',
        );
      }
    }

    // === KMS:EC_NIST_P256(ES256)signing CMK ===
    const signingKey = new kms.Key(this, 'SigningKeyEs256', {
      description: 'agent-auth ES256 access token signing (P0)',
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      // dev 栈:destroy 时计划删除(生产应 RETAIN)。
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const externalActiveEcKey = props.activeEcSigningKeyArn;
    const externalPublishedEcKeys = props.publishedEcSigningKeyArns;
    if ((externalActiveEcKey === undefined) !== (externalPublishedEcKeys === undefined)) {
      throw new Error(
        'activeEcSigningKeyArn 与 publishedEcSigningKeyArns 必须同时设置或同时省略',
      );
    }
    const kmsKeyArn = /^arn:[^:]+:kms:[^:]+:\d{12}:key\/[A-Za-z0-9-]+$/;
    if (
      externalActiveEcKey &&
      (
        !kmsKeyArn.test(externalActiveEcKey) ||
        !externalPublishedEcKeys ||
        externalPublishedEcKeys.length === 0 ||
        externalPublishedEcKeys.length > 8 ||
        new Set(externalPublishedEcKeys).size !== externalPublishedEcKeys.length ||
        externalPublishedEcKeys.some((arn) => !kmsKeyArn.test(arn)) ||
        !externalPublishedEcKeys.includes(externalActiveEcKey)
      )
    ) {
      throw new Error(
        'ES256 signing key 配置必须是 1..8 个唯一 KMS key ARN，且 active 必须属于 published',
      );
    }
    const activeEcSigningKeyId = externalActiveEcKey ?? signingKey.keyId;
    const activeEcSigningKeyArn = externalActiveEcKey ?? signingKey.keyArn;
    const publishedEcSigningKeyArns = externalPublishedEcKeys
      ? [...externalPublishedEcKeys]
      : [signingKey.keyArn];
    const publishedEcSigningKeyIds = externalPublishedEcKeys
      ? externalPublishedEcKeys.join(',')
      : signingKey.keyId;

    // === KMS:RSA_2048(RS256)id_token signing CMK(spec 001 C2.7)===
    // id_token 按 per-client alg 签、默认 RS256(OIDC);access token 仍 ES256(上面那把)。
    const idTokenSigningKey = new kms.Key(this, 'SigningKeyRs256', {
      description: 'agent-auth RS256 id_token signing (spec 001 C2.7)',
      keySpec: kms.KeySpec.RSA_2048,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === KMS:宽限窗缓存 item-level 信封加密 CMK(spec 001 C3.4)===
    // SYMMETRIC_DEFAULT(GenerateDataKey/Decrypt):每宽限缓存项一把数据密钥加密 token 明文;
    // Decrypt 权限 MUST 只授专用 TokenFn；主 AuthFn 仅保留 GraceTable 删除能力。
    // Keep the original logical resource as a rollback tombstone. After the
    // token-runtime cutover, operations disables this key so a rollback to the
    // old monolith fails closed instead of restoring grace decrypt authority.
    const legacyGraceKey = new kms.Key(this, 'GraceEnvelopeKey', {
      description: 'agent-auth legacy grace-cache envelope key (disabled after C3.4 cutover)',
      // 默认 SYMMETRIC_DEFAULT + ENCRYPT_DECRYPT。
      enableKeyRotation: true, // cdk-nag AwsSolutions-KMS5:对称 CMK 开年度自动轮换
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const tokenGraceKey = new kms.Key(this, 'TokenGraceEnvelopeKey', {
      description: 'agent-auth token-runtime grace-cache envelope encryption (spec 001 C3.4)',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const cibaNotificationKeyAlias = `alias/c-${createHash('sha256')
      .update(this.stackName)
      .digest('hex')
      .slice(0, 12)}`;
    const cibaNotificationKey = new kms.Key(
      this,
      'CibaNotificationEnvelopeKey',
      {
        alias: cibaNotificationKeyAlias,
        description:
          'agent-auth CIBA client_notification_token envelope encryption',
        enableKeyRotation: true,
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );

    // === DynamoDB:授权码表(短命,TTL 只做 GC;有效期判定在应用层 C10.4)===
    const codesTable = new dynamodb.Table(this, 'CodesTable', {
      partitionKey: { name: 'code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, // 按需,控成本
      timeToLiveAttribute: 'expires_at', // TTL 只做异步 GC(非有效期真相,C10.4)
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    // GSI client_id-index(spec 005 §9.4b,C10.5):按 client 的治理/级联访问加速。回收的"无 active
    // code"结论不能依赖最终一致 GSI 未命中,当前由主表强一致读权威判定。
    codesTable.addGlobalSecondaryIndex({
      indexName: 'client_id-index',
      partitionKey: { name: 'client_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // === DynamoDB:客户端表(持久身份,不挂裸 TTL,C10.5)===
    const clientsTable = new dynamodb.Table(this, 'ClientsTable', {
      partitionKey: { name: 'client_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });
    // GSI last_used_day-index(spec 005 §9.4b,C10.5):回收扫描只 Query 旧 client(last_used_day < 阈值),
    // 避免全表 Scan(DESIGN §8 明列此访问模式)。稀疏索引——仅有 last_used_day 属性的行进索引
    // (从未使用的 client 无此属性 → 不进索引;其残渣清理走注册残渣 TTL 例外,非本扫描)。KEYS_ONLY。
    clientsTable.addGlobalSecondaryIndex({
      indexName: 'last_used_day-index',
      partitionKey: { name: 'last_used_day', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // === DynamoDB:initial access token ledger (verifier only; application checks expiry) ===
    const initialAccessTokensTable = new dynamodb.Table(this, 'InitialAccessTokensTable', {
      partitionKey: { name: 'token_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:refresh family 表(C3 rotation + 复用检测;原子 CAS UpdateItem)===
    const refreshTable = new dynamodb.Table(this, 'RefreshTable', {
      partitionKey: { name: 'family_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    // GSI client_id-index(spec 005 §9.4b,C10.5):加速 revoke_by_client(spec 025 DELETE 级联)等
    // 正向访问。回收的"无 active family"结论不能依赖最终一致 GSI 未命中,当前由主表强一致读权威判定。
    refreshTable.addGlobalSecondaryIndex({
      indexName: 'client_id-index',
      partitionKey: { name: 'client_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });
    // SCIM/Admin lifecycle revocation must stay user-scoped under shared-table growth.
    refreshTable.addGlobalSecondaryIndex({
      indexName: 'user_id-index',
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // Region-local active Code/Refresh references for bounded, strongly consistent
    // client reclamation checks. The source records remain the protocol authority.
    const clientAuthorityRefsTable = new dynamodb.Table(
      this,
      'ClientAuthorityRefsTable',
      {
        partitionKey: {
          name: 'client_key',
          type: dynamodb.AttributeType.STRING,
        },
        sortKey: {
          name: 'reference_key',
          type: dynamodb.AttributeType.STRING,
        },
        tableName: `${this.stackName}-refs`,
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        timeToLiveAttribute: 'expires_at',
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );

    // === DynamoDB:会话表(P0.5 登录会话;短命,TTL 只做 GC)===
    const sessionsTable = new dynamodb.Table(this, 'SessionsTable', {
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at', // TTL 只做异步 GC(判定走应用层 C10.4)
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    sessionsTable.addGlobalSecondaryIndex({
      indexName: 'user_id-index',
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // === DynamoDB:magic-link 表(待兑现 link + per-email 冷却;pk=link#<id> / cool#<email>)===
    const magicLinkTable = new dynamodb.Table(this, 'MagicLinkTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // Dedicated Admin-issued onboarding invitations(issue #34). The row
    // contains only an opaque locator + secret verifier; TTL is cleanup while
    // every consume transaction checks expires_at in application logic.
    const invitationsTable = new dynamodb.Table(this, 'InvitationsTable', {
      partitionKey: { name: 'locator', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:账户恢复码表(C9.3;持久码集不写 expires_at；短命 operation result 用 TTL GC)===
    const recoveryTable = new dynamodb.Table(this, 'RecoveryTable', {
      partitionKey: { name: 'user_lookup', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:授权会话状态机表(spec 004,C6;pk=session_id,GSI client_id-index 支撑
    //    GET /sessions?client_id=me;短命 TTL 只做 GC,判定走应用层 expires_at)===
    const authzSessionsTable = new dynamodb.Table(this, 'AuthzSessionsTable', {
      partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    authzSessionsTable.addGlobalSecondaryIndex({
      indexName: 'client_id-index',
      partitionKey: { name: 'client_id', type: dynamodb.AttributeType.STRING },
    });

    // === DynamoDB:workload 信任绑定表(spec 012 C5.5;pk=binding_id,持久不挂 TTL)===
    // 管理面登记 workload 平台身份信任策略(OIDC iss+sub / SigV4 ARN → client_id)。
    const workloadTrustTable = new dynamodb.Table(this, 'WorkloadTrustTable', {
      partitionKey: { name: 'binding_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });

    // === DynamoDB:CIBA 授权请求表(spec 013;pk=auth_req_id,短命 TTL 只做 GC,判定走 expires_at)===
    const cibaTable = new dynamodb.Table(this, 'CibaTable', {
      partitionKey: { name: 'auth_req_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:device 授权表(spec 013;pk=device_code,GSI user_code-index 供验证页反查)===
    const deviceTable = new dynamodb.Table(this, 'DeviceTable', {
      partitionKey: { name: 'device_code', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    deviceTable.addGlobalSecondaryIndex({
      indexName: 'user_code-index',
      partitionKey: { name: 'user_code', type: dynamodb.AttributeType.STRING },
    });

    // === DynamoDB:宽限窗缓存表(spec 001 C3.2/C3.4/C3.5)===
    // pk=family_id + sk=version:窗内同请求重放同一组 token(不再签);delete_family 按 pk Query 删全部版本(C3.5)。
    // item 存 KMS 信封加密后的密文(enc_dk/nonce/ciphertext),表级 SSE 不足以满足 C3.4。短命 TTL 只做 GC。
    const graceTable = new dynamodb.Table(this, 'GraceTable', {
      partitionKey: { name: 'family_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'version', type: dynamodb.AttributeType.NUMBER },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at', // 窗过后 GC(判定仍走应用层 expires_at)
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:jti→主体映射表(spec 011 C7.8;token-exchange subject 解析)===
    // pk=`tenant_id\x1fjti`(按 tenant 分区,跨租户查不到);短命 TTL=expires_at(≥token TTL)。
    const jtiTable = new dynamodb.Table(this, 'JtiTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:Grant 授权记录表(spec 011 §5.1;P2 权威源)===
    // pk=grant_id;GSI user_id-index 供用户自助列(FAPI Grant Management)。无 TTL(Grant 长期,吊销走 status)。
    const grantsTable = new dynamodb.Table(this, 'GrantsTable', {
      partitionKey: { name: 'grant_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });
    grantsTable.addGlobalSecondaryIndex({
      indexName: 'user_id-index',
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
    });
    // GSI policy_version-index(spec 005 §7 / C10.17):后台重算任务按 (gv_tenant, effective_pv) Query stale
    // Grant(effective_pv < current_pv),分页而非全表 Scan。**KEYS_ONLY + 回主表取全 Grant**:GSI 只投影主键,
    // list_stale 拿到命中的物理 grant_id 后逐条 GetItem 主表反序列化整条 Grant(评审 Blocker:早期实现漏了
    // 回表、直接 from_item 空 grant_json 静默返 0,已在 aws.rs list_stale 修)。KEYS_ONLY 保 GSI 精简。
    // gv_tenant = `tpk(tenant,"gv")`(**非空** key;见 aws.rs to_item)——DynamoDB 拒空串 GSI 键,self-host
    // tenant="" 直接落空串会整条写失败(评审 Blocker,已修)。所有 Grant 进本索引(非稀疏),flag 关时
    // current_pv=0 → 重算提前返回不扫,无处置成本。
    grantsTable.addGlobalSecondaryIndex({
      indexName: 'policy_version-index',
      partitionKey: { name: 'gv_tenant', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'effective_pv', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.KEYS_ONLY,
    });

    // === DynamoDB:联邦上游 IdP 配置表(spec 003 §4;复合键 pk=tenant_id / sk=upstream_idp_id,逐租户隔离)===
    const federationConfigTable = new dynamodb.Table(this, 'FederationConfigTable', {
      partitionKey: { name: 'tenant_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'upstream_idp_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });

    // === DynamoDB:联邦 flow 短命状态表(spec 003 §4;pk=state,TTL 只做 GC,判定走 expires_at)===
    const federationFlowTable = new dynamodb.Table(this, 'FederationFlowTable', {
      partitionKey: { name: 'state', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:Admin OIDC durable configuration(C12.3)===
    // The existing table remains the configuration authority so an upgrade
    // preserves config# rows. New flow/session state is written to the
    // Region-local runtime table below and old mixed rows become unreachable.
    const adminAuthTable = new dynamodb.Table(this, 'AdminAuthTable', {
      partitionKey: { name: 'key', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });
    const adminAuthRuntimeTable = new dynamodb.Table(this, 'AdminAuthRuntimeTable', {
      partitionKey: { name: 'key', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:passkey 凭证表(spec 003 §3,C9.4;pk=credential_id + GSI user_id-index)===
    // WebAuthn 注册凭证(credentialId 唯一/公钥 SEC1/signCount);GSI user_id-index 供 begin 的
    // excludeCredentials/allowCredentials 按 user 列。持久身份不挂 TTL(凭证长期,吊销走删行)。
    const passkeyTable = new dynamodb.Table(this, 'PasskeyTable', {
      partitionKey: { name: 'credential_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });
    passkeyTable.addGlobalSecondaryIndex({
      indexName: 'user_id-index',
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
    });

    // === DynamoDB:passkey challenge 短命表(spec 003 §3;pk=challenge,TTL 只做 GC,一次性走条件删)===
    // 仪式 challenge(begin 存、finish 条件删一次性防重放,判定走 expires_at);TTL 仅异步 GC(C10.4)。
    const passkeyChallengeTable = new dynamodb.Table(this, 'PasskeyChallengeTable', {
      partitionKey: { name: 'challenge', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:PAR 推送授权请求表(spec 006 §7.3,RFC 9126;pk=request_uri,TTL 只做 GC,判定走 expires_at)===
    // 短命 ≤90s;consume=条件删一次性;应用层 fail-closed 校 expires_at(不靠 TTL 惰性删,C10.4/H4)。
    const parTable = new dynamodb.Table(this, 'ParTable', {
      partitionKey: { name: 'request_uri', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:per-client 限流令牌桶表(spec 005 C10.7;pk=key[client_id],短命 TTL 只做空闲桶 GC)===
    const rateLimitTable = new dynamodb.Table(this, 'RateLimitTable', {
      partitionKey: { name: 'key', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === DynamoDB:消息 outbox 表(SES 未接前的模拟,spec 003 §1.5;pk=message_id,TTL=1 天自动 GC)===
    // 把 magic-link / recovery 通知落一行(不真发邮件),admin GET /admin/messages 可观测"发了什么"。
    const messagesTable = new dynamodb.Table(this, 'MessagesTable', {
      partitionKey: { name: 'message_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl', // TTL=1 天(应用写 ttl=created_at+86400,DynamoDB 自动删)
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // === Security events: immutable hot ledger + tenant/time export index ===
    const securityEventsTable = new dynamodb.Table(this, 'SecurityEventsTable', {
      partitionKey: { name: 'event_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      stream: tenantKeyReplicaRegions.length > 0
        ? dynamodb.StreamViewType.NEW_AND_OLD_IMAGES
        : dynamodb.StreamViewType.NEW_IMAGE,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN,
      ...durableReplication,
    });
    securityEventsTable.addGlobalSecondaryIndex({
      indexName: 'tenant_occurred_at-index',
      partitionKey: { name: 'tenant_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'occurred_at', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    securityEventsTable.addGlobalSecondaryIndex({
      indexName: 'delivery_status-index',
      partitionKey: { name: 'delivery_status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'last_delivery_at', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // === Shared Signals receiver registry + durable delivery outbox ===
    // Tenant is the physical partition key. Stream and delivery rows share the
    // partition so every Admin query is tenant-bound at the DynamoDB key layer.
    // Only active pending/retry rows carry due_partition/due_at and therefore
    // appear in the global due queue.
    const ssfDeliveriesTable = new dynamodb.Table(this, 'SsfDeliveriesTable', {
      partitionKey: { name: 'tenant_id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'record_key', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    ssfDeliveriesTable.addGlobalSecondaryIndex({
      indexName: 'due-index',
      partitionKey: { name: 'due_partition', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'due_at', type: dynamodb.AttributeType.NUMBER },
      projectionType: dynamodb.ProjectionType.ALL,
    });
    ssfDeliveriesTable.addGlobalSecondaryIndex({
      indexName: 'stream-created-at-index',
      partitionKey: { name: 'stream_partition', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'stream_created_at', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // Deterministic object keys use conditional writes; versioning preserves
    // prior revisions as defense in depth. The bucket and hot ledger are
    // retained independently from stack lifetime.
    const securityEventArchiveBucket = new s3.Bucket(this, 'SecurityEventArchiveBucket', {
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [{
        expiration: Duration.days(2555),
        noncurrentVersionExpiration: Duration.days(2555),
      }],
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const securityEventArchiveDlq = new sqs.Queue(this, 'SecurityEventArchiveDlq', {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
      visibilityTimeout: Duration.minutes(2),
      fifo: true,
    });
    const securityEventIngressDlq = new sqs.Queue(this, 'SecurityEventIngressDlq', {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
      visibilityTimeout: Duration.minutes(2),
      fifo: true,
    });
    const securityEventIngressQueue = new sqs.Queue(this, 'SecurityEventIngressQueue', {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
      visibilityTimeout: Duration.minutes(2),
    });
    const securityEventStreamFailureNotificationDlq = new sqs.Queue(
      this,
      'SecurityEventStreamFailureNotificationDlq',
      {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(2),
      },
    );
    const securityEventStreamFailureNotificationQueue = new sqs.Queue(
      this,
      'SecurityEventStreamFailureNotificationQueue',
      {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(2),
        deadLetterQueue: {
          queue: securityEventStreamFailureNotificationDlq,
          maxReceiveCount: 4,
        },
      },
    );
    const securityEventStreamFailureBucket = new s3.Bucket(
      this,
      'SecurityEventStreamFailureBucket',
      {
        encryption: s3.BucketEncryption.S3_MANAGED,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        enforceSSL: true,
        lifecycleRules: [{ expiration: Duration.days(2555) }],
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const securityEventIngressFailureBucket = new s3.Bucket(
      this,
      'SecurityEventIngressFailureBucket',
      {
        encryption: s3.BucketEncryption.S3_MANAGED,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        enforceSSL: true,
        lifecycleRules: [{ expiration: Duration.days(2555) }],
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );

    // Athena partition projection makes the seven-year JSON archive queryable
    // without a crawler. tenant_id is injected, so every query must scope a tenant.
    const securityEventArchiveDatabase = new glue.CfnDatabase(
      this,
      'SecurityEventArchiveDatabase',
      {
        catalogId: this.account,
        databaseInput: {
          description: 'Agent Auth long-term security event archive',
        },
      },
    );
    const securityEventArchiveTable = new glue.CfnTable(this, 'SecurityEventArchiveAthenaTable', {
      catalogId: this.account,
      databaseName: securityEventArchiveDatabase.ref,
      tableInput: {
        name: 'security_events',
        tableType: 'EXTERNAL_TABLE',
        parameters: {
          classification: 'json',
          EXTERNAL: 'TRUE',
          'projection.enabled': 'true',
          'projection.tenant_id.type': 'injected',
          'projection.year.type': 'integer',
          'projection.year.range': '2020,2100',
          'projection.year.digits': '4',
          'projection.month.type': 'integer',
          'projection.month.range': '1,12',
          'projection.month.digits': '2',
          'projection.day.type': 'integer',
          'projection.day.range': '1,31',
          'projection.day.digits': '2',
          'storage.location.template':
            `s3://${securityEventArchiveBucket.bucketName}/security-events/` +
            'tenant_id=${tenant_id}/year=${year}/month=${month}/day=${day}/',
        },
        partitionKeys: [
          { name: 'tenant_id', type: 'string' },
          { name: 'year', type: 'string' },
          { name: 'month', type: 'string' },
          { name: 'day', type: 'string' },
        ],
        storageDescriptor: {
          location: `s3://${securityEventArchiveBucket.bucketName}/security-events/`,
          inputFormat: 'org.apache.hadoop.mapred.TextInputFormat',
          outputFormat: 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
          serdeInfo: {
            serializationLibrary: 'org.openx.data.jsonserde.JsonSerDe',
          },
          columns: [
            { name: 'schema_version', type: 'string' },
            { name: 'event_id', type: 'string' },
            { name: 'occurred_at', type: 'bigint' },
            { name: 'actor', type: 'struct<kind:string,id:string>' },
            { name: 'subject', type: 'struct<kind:string,id:string>' },
            { name: 'category', type: 'string' },
            { name: 'action', type: 'string' },
            { name: 'outcome', type: 'string' },
            {
              name: 'correlation',
              type:
                'struct<request_id:string,session_fingerprint:string,authz_session_id:string,' +
                'client_id:string,grant_id:string,credential_id:string,operation_id:string>',
            },
            {
              name: 'delivery',
              type:
                'struct<status:string,attempts:int,last_attempt_at:bigint,archived_at:bigint,' +
                'dead_lettered_at:bigint,archive_key:string,' +
                'history:array<struct<status:string,occurred_at:bigint>>>',
            },
          ],
        },
      },
    });
    securityEventArchiveDatabase.applyRemovalPolicy(RemovalPolicy.RETAIN);
    securityEventArchiveTable.applyRemovalPolicy(RemovalPolicy.RETAIN);
    securityEventArchiveTable.addDependency(securityEventArchiveDatabase);
    // IAM_ALLOWED_PRINCIPALS requires Lake Formation Super (`ALL`) to restore
    // IAM-compatible catalog access. IAM and S3 policies remain the access boundary,
    // and the empty grant-option list prevents callers from delegating this permission.
    const iamAllowedPrincipal = {
      dataLakePrincipalIdentifier: 'IAM_ALLOWED_PRINCIPALS',
    };
    const securityEventArchiveDatabasePermission =
      new lakeformation.CfnPrincipalPermissions(
        this,
        'SecurityEventArchiveDatabaseQueryPermission',
        {
          principal: iamAllowedPrincipal,
          resource: {
            database: {
              catalogId: this.account,
              name: securityEventArchiveDatabase.ref,
            },
          },
          permissions: ['ALL'],
          permissionsWithGrantOption: [],
        },
      );
    securityEventArchiveDatabasePermission.applyRemovalPolicy(RemovalPolicy.RETAIN);
    securityEventArchiveDatabasePermission.addDependency(securityEventArchiveDatabase);
    const securityEventArchiveTablePermission = new lakeformation.CfnPrincipalPermissions(
      this,
      'SecurityEventArchiveTableQueryPermission',
      {
        principal: iamAllowedPrincipal,
        resource: {
          table: {
            catalogId: this.account,
            databaseName: securityEventArchiveDatabase.ref,
            name: 'security_events',
          },
        },
        permissions: ['ALL'],
        permissionsWithGrantOption: [],
      },
    );
    securityEventArchiveTablePermission.applyRemovalPolicy(RemovalPolicy.RETAIN);
    securityEventArchiveTablePermission.addDependency(securityEventArchiveTable);
    securityEventArchiveTablePermission.addDependency(
      securityEventArchiveDatabasePermission,
    );

    // === DynamoDB:用户目录表(spec 003 §1.4;pk=user_id + sparse GSIs,持久身份不挂 TTL,C10.5)===
    // magic-link 登录落 email→user_id 可查映射 + created_at;email-index 支撑 by-email 幂等 upsert。
    // SCIM canonical users additionally carry scim_tenant;the sparse index keeps tenant listing off full-table Scan.
    const usersTable = new dynamodb.Table(this, 'UsersTable', {
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });
    usersTable.addGlobalSecondaryIndex({
      indexName: 'email-index',
      partitionKey: { name: 'email', type: dynamodb.AttributeType.STRING },
      // 显式 ALL:lookup_by_email 经 GSI item 直读 user_id/email/created_at(不回主表);
      // 防将来误改 KEYS_ONLY 使 to_record 缺 created_at 静默把命中当未命中(评审 Kiro NIT-2)。
      projectionType: dynamodb.ProjectionType.ALL,
    });
    usersTable.addGlobalSecondaryIndex({
      indexName: 'scim_tenant-index',
      partitionKey: { name: 'scim_tenant', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // === DynamoDB:属性 namespace 注册表(spec 007 §7.15;tenant + exact URI lookup)===
    // Registration、migration checkpoint 与 Retired tombstone 共表持久化；无 TTL，避免旧 audience
    // 在解绑后重新落回 raw-audience namespace。lookup_key 使用服务端 exact-byte URI hash。
    const attributeNamespacesTable = new dynamodb.Table(
      this,
      'AttributeNamespacesTable',
      {
        partitionKey: {
          name: 'tenant_id',
          type: dynamodb.AttributeType.STRING,
        },
        sortKey: {
          name: 'lookup_key',
          type: dynamodb.AttributeType.STRING,
        },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption: dynamodb.TableEncryption.AWS_MANAGED,
        pointInTimeRecoverySpecification: {
          pointInTimeRecoveryEnabled: true,
        },
        removalPolicy: RemovalPolicy.DESTROY,
        ...durableReplication,
      },
    );

    // === DynamoDB:federation claim-to-attribute mapping authority(issue #213)===
    // Registry、tenant-wide target owner 与永久 mapping-id marker 共表。无 TTL，避免删除后的
    // mapping id 被复用或 target ownership 在恢复/切区后丢失。
    const federationAttributeMappingsTable = new dynamodb.Table(
      this,
      'FederationAttributeMappingsTable',
      {
        partitionKey: {
          name: 'tenant_id',
          type: dynamodb.AttributeType.STRING,
        },
        sortKey: {
          name: 'lookup_key',
          type: dynamodb.AttributeType.STRING,
        },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption: dynamodb.TableEncryption.AWS_MANAGED,
        pointInTimeRecoverySpecification: {
          pointInTimeRecoveryEnabled: true,
        },
        removalPolicy: RemovalPolicy.DESTROY,
        ...durableReplication,
      },
    );

    // === DynamoDB:SCIM Groups + membership index + explicit tenant role mapping(C12.3)===
    // Base-table partitions hold canonical Groups, externalId claims, and per-user membership rows.
    // The sparse GSI lists active Groups for one tenant without scanning membership/alias records.
    const scimGroupsTable = new dynamodb.Table(this, 'ScimGroupsTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });
    scimGroupsTable.addGlobalSecondaryIndex({
      indexName: 'tenant_kind-index',
      partitionKey: { name: 'tenant_kind', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'group_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // === DynamoDB:本地密码凭证表(spec 003 C9.8;pk=tenant-scoped user_id,持久无 TTL)===
    // 仅存 Argon2id PHC hash + must_change/version/updated_at;与 UserRecord/API schema 隔离。
    const passwordCredentialsTable = new dynamodb.Table(this, 'PasswordCredentialsTable', {
      partitionKey: { name: 'user_id', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });

    // === DynamoDB:BYOD 域名映射表(spec 010 §5.4 / C8.1b;pk=domain 归一小写,**全局键**非 tenant 分区)===
    // 数据面 well-known PRM 按入站 Host 反查绑定(O(1) GetItem);登记时 conditional put attribute_not_exists
    // 保 fleet 全局域名唯一(反跨租户劫持)。持久绑定不挂 TTL。BYOD 未启用(AGENT_AUTH_BYOD_ENABLED≠1)时不写。
    const domainMapTable = new dynamodb.Table(this, 'DomainMapTable', {
      partitionKey: { name: 'domain', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.DESTROY,
      ...durableReplication,
    });

    const tenantKeysTable = saasTenantIds.length > 0
      ? new dynamodb.Table(this, 'TenantKeysTable', {
          partitionKey: { name: 'tenant_id', type: dynamodb.AttributeType.STRING },
          billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
          pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
          removalPolicy: RemovalPolicy.RETAIN,
          ...durableReplication,
        })
      : undefined;
    const regionControlTable = tenantKeyReplicaRegions.length > 0
      ? new dynamodb.Table(this, 'RegionControlTable', {
          partitionKey: { name: 'region_id', type: dynamodb.AttributeType.STRING },
          billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
          encryption: dynamodb.TableEncryption.AWS_MANAGED,
          pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
          removalPolicy: RemovalPolicy.RETAIN,
          replicationRegions: tenantKeyReplicaRegions,
        })
      : undefined;
    const governanceTable = new dynamodb.Table(this, 'GovernanceTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      deletionProtection: true,
      removalPolicy: RemovalPolicy.RETAIN,
      ...durableReplication,
    });
    const governanceSuppressionTable = new dynamodb.Table(
      this,
      'GovernanceSuppressionTable',
      {
        partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
        sortKey: { name: 'epoch', type: dynamodb.AttributeType.NUMBER },
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption: dynamodb.TableEncryption.AWS_MANAGED,
        stream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
        deletionProtection: true,
        removalPolicy: RemovalPolicy.RETAIN,
        ...durableReplication,
      },
    );
    for (const table of [governanceTable, governanceSuppressionTable]) {
      const cfnTable = table.node.defaultChild as dynamodb.CfnTable;
      cfnTable.addPropertyOverride(
        'PointInTimeRecoverySpecification.RecoveryPeriodInDays',
        35,
      );
    }
    const governanceWorkerDlq = new sqs.Queue(this, 'GovernanceWorkerDlq', {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
      visibilityTimeout: Duration.minutes(6),
      fifo: true,
    });
    const governanceWorkerQueue = new sqs.Queue(this, 'GovernanceWorkerQueue', {
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      enforceSSL: true,
      retentionPeriod: Duration.days(14),
      visibilityTimeout: Duration.minutes(6),
      deliveryDelay: Duration.seconds(15),
      fifo: true,
      deadLetterQueue: {
        queue: governanceWorkerDlq,
        maxReceiveCount: 5,
      },
    });
    if (regionControlTable) {
      new cr.AwsCustomResource(this, 'RegionControlBootstrap', {
        installLatestAwsSdk: false,
        onCreate: {
          service: 'DynamoDB',
          action: 'transactWriteItems',
          parameters: {
            TransactItems: [
              {
                Put: {
                  TableName: regionControlTable.tableName,
                  Item: {
                    region_id: { S: 'control' },
                    active_region: { S: this.region },
                    state: { S: 'active' },
                    revision: { N: '1' },
                  },
                  ConditionExpression: 'attribute_not_exists(region_id)',
                },
              },
              {
                Put: {
                  TableName: regionControlTable.tableName,
                  Item: {
                    region_id: { S: this.region },
                    active: { BOOL: true },
                    activation_not_before: { N: '0' },
                    revision: { N: '1' },
                  },
                  ConditionExpression: 'attribute_not_exists(region_id)',
                },
              },
              {
                Put: {
                  TableName: regionControlTable.tableName,
                  Item: {
                    region_id: { S: `fence#${this.region}` },
                    active: { BOOL: true },
                    activation_not_before: { N: '0' },
                    revision: { N: '1' },
                  },
                  ConditionExpression: 'attribute_not_exists(region_id)',
                },
              },
            ],
          },
          physicalResourceId: cr.PhysicalResourceId.of(
            'agent-auth-region-control-bootstrap',
          ),
        },
        policy: cr.AwsCustomResourcePolicy.fromStatements([
          new iam.PolicyStatement({
            actions: ['dynamodb:PutItem'],
            resources: [regionControlTable.tableArn],
          }),
        ]),
      });
    }
    const regionFenceEnvironment: Record<string, string> = regionControlTable
      ? {
          REGION_CONTROL_TABLE: regionControlTable.tableName,
        }
      : {};
    const grantRegionControlRead = (target: lambda.Function): void => {
      if (!regionControlTable) {
        return;
      }
      regionControlTable.grantReadData(target);
      target.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactGetItems'],
          resources: [regionControlTable.tableArn],
        }),
      );
    };
    const tenantKeyOperationsDlq = saasTenantIds.length > 0
      ? new sqs.Queue(this, 'TenantKeyOperationsDlq', {
          encryption: sqs.QueueEncryption.SQS_MANAGED,
          enforceSSL: true,
          retentionPeriod: Duration.days(14),
          visibilityTimeout: Duration.minutes(6),
        })
      : undefined;
    const tenantKeyOperationsQueue = tenantKeyOperationsDlq
      ? new sqs.Queue(this, 'TenantKeyOperationsQueue', {
          encryption: sqs.QueueEncryption.SQS_MANAGED,
          enforceSSL: true,
          retentionPeriod: Duration.days(14),
          visibilityTimeout: Duration.minutes(6),
          deadLetterQueue: {
            queue: tenantKeyOperationsDlq,
            maxReceiveCount: 5,
          },
        })
      : undefined;
    // GSI client_id-index(评审 M1/L3):删 client 级联的**权威反查**——list_by_client 走此 GSI,
    // 不依赖可漂移的 ClientRecord.prm_domains 展示副本(并发 bind race 下会漏项 → 悬空行永不清)。
    // 标量键 client_id 可索引(区别于不可索引的 List 成员);ALL 投影直读绑定属性组装 DomainBinding(不回主表)。
    domainMapTable.addGlobalSecondaryIndex({
      indexName: 'client_id-index',
      partitionKey: { name: 'client_id', type: dynamodb.AttributeType.STRING },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    // === Secrets Manager:server_secret(magic-link tag + CSRF HMAC 密钥)===
    // 随机生成(非公开 dev 常量);注入 Lambda env SERVER_SECRET(fail-closed:缺则拒启动)。
    // 注:env 注入是 P0.5 折中(优于公开常量);更严格应运行时 GetSecretValue,留后续。
    const serverSecret = new secretsmanager.Secret(this, 'ServerSecret', {
      description: 'agent-auth server_secret (magic-link tag + CSRF HMAC)',
      generateSecretString: {
        passwordLength: 48,
        excludePunctuation: true,
      },
      removalPolicy: RemovalPolicy.DESTROY,
      ...runtimeSecretReplication,
    });
    NagSuppressions.addResourceSuppressions(serverSecret, [
      {
        id: 'AwsSolutions-SMG4',
        reason: 'server_secret 是 HMAC 对称密钥(magic-link tag + CSRF);轮换需配套双密钥重叠期逻辑(与签名 key 轮换同属 P3 密钥轮换编排 C10.11b),非 P0.5 自动轮换目标。',
      },
    ]);
    const governanceHmacSecret = new secretsmanager.Secret(
      this,
      'GovernanceHmacSecret',
      {
        description:
          'agent-auth dedicated governance cursor, job, and suppression HMAC key',
        generateSecretString: {
          passwordLength: 48,
          excludePunctuation: true,
        },
        removalPolicy: RemovalPolicy.RETAIN,
        ...runtimeSecretReplication,
      },
    );
    NagSuppressions.addResourceSuppressions(governanceHmacSecret, [
      {
        id: 'AwsSolutions-SMG4',
        reason:
          'Governance suppression HMAC versions cannot rotate or retire until every retained suppression row has migrated; rotation is application-coordinated.',
      },
    ]);

    // === Secrets Manager:admin credential source + target(spec 030 / issue #16)===
    // AdminToken 是旧模板读取的裸 bearer source，升级时绝不原地改写。新 target 由 Rust migration
    // 在 AuthFn 更新前复制并包装；若栈回滚，旧 Lambda 仍从未变的 source 读取同一 bearer。
    const legacyAdminSecret = new secretsmanager.Secret(this, 'AdminToken', {
      description: 'agent-auth legacy admin console token (rollback source)',
      generateSecretString: {
        passwordLength: 48,
        excludePunctuation: true,
      },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    NagSuppressions.addResourceSuppressions(legacyAdminSecret, [
      {
        id: 'AwsSolutions-SMG4',
        reason:
          '旧版 admin bearer 仅作为升级复制源和旧模板回滚兼容面保留；活跃运行时改读独立 credential-set target，contract release 后再移除 source。',
      },
    ]);

    const adminCredentialSecret = new secretsmanager.Secret(this, 'AdminCredentialSet', {
      description: 'agent-auth platform admin break-glass credential set',
      generateSecretString: {
        passwordLength: 48,
        excludePunctuation: true,
      },
      removalPolicy: RemovalPolicy.DESTROY,
      ...runtimeSecretReplication,
    });
    const tenantAdminCredentialSecrets = Object.fromEntries(
      Object.keys(legacyTenantAdminSecrets).map((tenant) => [
        tenant,
        new secretsmanager.Secret(this, `TenantAdminCredentialSet-${tenant}`, {
          description: `agent-auth tenant ${tenant} admin break-glass credential set`,
          generateSecretString: {
            passwordLength: 48,
            excludePunctuation: true,
          },
          removalPolicy: RemovalPolicy.DESTROY,
          ...runtimeSecretReplication,
        }),
      ]),
    );
    for (const secret of [
      adminCredentialSecret,
      ...Object.values(tenantAdminCredentialSecrets),
    ]) {
      NagSuppressions.addResourceSuppressions(secret, [
        {
          id: 'AwsSolutions-SMG4',
          reason:
            '应用支持 owner-bound current/next 有界重叠、确定性 cutover/retirement 与 warm-runtime refresh；自动定时轮换需外部持有方协调，按 docs/ADMIN_CREDENTIAL_ROTATION.md 由运营流程触发。',
        },
      ]);
    }

    // SCIM 是新部署面，但仍使用 source -> owner-bound target 的可回滚迁移模型。
    // SelfHosted 只有 default owner；SaaS 为每个 issuer tenant 创建独立 owner。
    const scimTenantIds = saasTenantIds.length > 0 ? saasTenantIds : ['default'];
    const legacyScimSecrets = Object.fromEntries(
      scimTenantIds.map((tenant) => [
        tenant,
        new secretsmanager.Secret(this, `ScimToken-${tenant}`, {
          description: `agent-auth tenant ${tenant} legacy SCIM bearer (rollback source)`,
          generateSecretString: {
            passwordLength: 48,
            excludePunctuation: true,
          },
          removalPolicy: RemovalPolicy.DESTROY,
        }),
      ]),
    );
    const scimCredentialSecrets = Object.fromEntries(
      scimTenantIds.map((tenant) => [
        tenant,
        new secretsmanager.Secret(this, `ScimCredentialSet-${tenant}`, {
          description: `agent-auth tenant ${tenant} SCIM provisioning credential set`,
          generateSecretString: {
            passwordLength: 48,
            excludePunctuation: true,
          },
          removalPolicy: RemovalPolicy.DESTROY,
          ...runtimeSecretReplication,
        }),
      ]),
    );
    for (const secret of Object.values(legacyScimSecrets)) {
      NagSuppressions.addResourceSuppressions(secret, [
        {
          id: 'AwsSolutions-SMG4',
          reason:
            'SCIM bearer source 只供首次 owner-bound credential-set 迁移和部署回滚；运行时显式 Deny，完成兼容窗口后退役。',
        },
      ]);
    }
    for (const secret of Object.values(scimCredentialSecrets)) {
      NagSuppressions.addResourceSuppressions(secret, [
        {
          id: 'AwsSolutions-SMG4',
          reason:
            'SCIM credential set 由应用 current/next、expiry、cutover、retirement 与 checkpoint 协议轮换；外部目录持有方按 runbook 协调。',
        },
      ]);
    }

    // === Production backup and restore (spec 030 / issue #28) ===
    // Only durable authority that is safe to replay is recoverable. Refresh families
    // and recovery-code ledgers stay out with the short-lived protocol artifacts:
    // rolling either store back could revive a revoked family or a consumed code.
    const recoverableAuthorityTables = [
      clientsTable,
      workloadTrustTable,
      grantsTable,
      federationConfigTable,
      adminAuthTable,
      passkeyTable,
      securityEventsTable,
      usersTable,
      attributeNamespacesTable,
      federationAttributeMappingsTable,
      scimGroupsTable,
      passwordCredentialsTable,
      domainMapTable,
      ...(tenantKeysTable ? [tenantKeysTable] : []),
    ];
    const replicatedAuthorityTables = {
      clients: clientsTable,
      workload_trust: workloadTrustTable,
      grants: grantsTable,
      federation_config: federationConfigTable,
      admin_auth: adminAuthTable,
      passkeys: passkeyTable,
      security_events: securityEventsTable,
      users: usersTable,
      attribute_namespaces: attributeNamespacesTable,
      federation_attribute_mappings: federationAttributeMappingsTable,
      scim_groups: scimGroupsTable,
      password_credentials: passwordCredentialsTable,
      domain_map: domainMapTable,
      governance: governanceTable,
      governance_suppression: governanceSuppressionTable,
      ...(tenantKeysTable ? { tenant_keys: tenantKeysTable } : {}),
    };
    if (regionControlTable) {
      consolidateDynamoDbReplicaProviderPolicies(
        this,
        [...Object.values(replicatedAuthorityTables), regionControlTable],
        tenantKeyReplicaRegions,
        workloadTrustTable,
      );
    }
    const regionLocalTables = [
      codesTable,
      initialAccessTokensTable,
      refreshTable,
      sessionsTable,
      magicLinkTable,
      invitationsTable,
      recoveryTable,
      authzSessionsTable,
      cibaTable,
      deviceTable,
      graceTable,
      jtiTable,
      federationFlowTable,
      adminAuthRuntimeTable,
      passkeyChallengeTable,
      parTable,
      rateLimitTable,
      messagesTable,
      ssfDeliveriesTable,
    ];
    let governanceRetentionBackupVaultName: string | undefined;
    let governanceRetentionBackupVaultArn: string | undefined;
    let governanceRetentionRecoveryTableArns: string[] = [];
    if (props.productionRecoveryEnabled) {
      for (const table of recoverableAuthorityTables) {
        table.applyRemovalPolicy(RemovalPolicy.RETAIN);
        const cfnTable = table.node.defaultChild as dynamodb.CfnTable;
        cfnTable.addPropertyOverride(
          'PointInTimeRecoverySpecification.RecoveryPeriodInDays',
          35,
        );
      }
      for (const key of [
        signingKey,
        idTokenSigningKey,
        legacyGraceKey,
        tokenGraceKey,
        cibaNotificationKey,
      ]) {
        key.applyRemovalPolicy(RemovalPolicy.RETAIN);
      }
      for (const secret of [
        serverSecret,
        governanceHmacSecret,
        legacyAdminSecret,
        adminCredentialSecret,
        ...Object.values(tenantAdminCredentialSecrets),
        ...Object.values(legacyScimSecrets),
        ...Object.values(scimCredentialSecrets),
      ]) {
        secret.applyRemovalPolicy(RemovalPolicy.RETAIN);
      }

      const recoveryBackupKey = new kms.Key(this, 'RecoveryBackupKey', {
        description: 'agent-auth production recovery-point encryption',
        enableKeyRotation: true,
        removalPolicy: RemovalPolicy.RETAIN,
      });
      const recoveryBackupVault = new backup.BackupVault(
        this,
        'RecoveryBackupVault',
        {
          encryptionKey: recoveryBackupKey,
          removalPolicy: RemovalPolicy.RETAIN,
        },
      );
      governanceRetentionBackupVaultName = recoveryBackupVault.backupVaultName;
      governanceRetentionBackupVaultArn = recoveryBackupVault.backupVaultArn;
      governanceRetentionRecoveryTableArns = recoverableAuthorityTables.map(
        (table) => table.tableArn,
      );
      const recoveryBackupRole = new iam.Role(this, 'RecoveryBackupRole', {
        assumedBy: new iam.ServicePrincipal('backup.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName(
            'service-role/AWSBackupServiceRolePolicyForBackup',
          ),
        ],
      });
      recoveryBackupKey.grant(
        recoveryBackupRole,
        'kms:Decrypt',
        'kms:DescribeKey',
        'kms:Encrypt',
        'kms:GenerateDataKey',
        'kms:ReEncryptFrom',
        'kms:ReEncryptTo',
      );

      const recoveryBackupPlan = new backup.BackupPlan(
        this,
        'RecoveryBackupPlan',
        {
          backupVault: recoveryBackupVault,
          backupPlanRules: [
            new backup.BackupPlanRule({
              ruleName: 'DailyDurableAuthority',
              scheduleExpression: events.Schedule.cron({
                minute: '0',
                hour: '5',
              }),
              startWindow: Duration.hours(1),
              completionWindow: Duration.hours(4),
              deleteAfter: Duration.days(35),
              recoveryPointTags: {
                'agent-auth-data-class': 'durable-authority',
              },
            }),
          ],
        },
      );
      recoveryBackupPlan.addSelection('DurableAuthorityTables', {
        backupSelectionName: 'DurableAuthorityTables',
        resources: recoverableAuthorityTables.map((table) =>
          backup.BackupResource.fromDynamoDbTable(table)),
        role: recoveryBackupRole,
        disableDefaultBackupPolicy: true,
      });

      new CfnOutput(this, 'RecoveryBackupVaultName', {
        value: recoveryBackupVault.backupVaultName,
      });
      new CfnOutput(this, 'RecoveryBackupPlanId', {
        value: recoveryBackupPlan.backupPlanId,
      });
      new CfnOutput(this, 'RecoveryBackupRoleArn', {
        value: recoveryBackupRole.roleArn,
      });
      new CfnOutput(this, 'RecoveryDeploymentCommit', {
        value: props.deploymentCommit!,
      });
      new CfnOutput(this, 'RecoveryAuthorityTableNames', {
        value: Fn.toJsonString(
          recoverableAuthorityTables.map((table) => table.tableName),
        ),
      });
      if (props.saasZone && saasTenantIds.length > 0) {
        new CfnOutput(this, 'RecoveryTenantIssuers', {
          value: Fn.toJsonString(
            Object.fromEntries(
              saasTenantIds.map((tenant) => [
                tenant,
                `https://${tenant}.${props.saasZone}`,
              ]),
            ),
          ),
        });
      }
      NagSuppressions.addResourceSuppressions(
        recoveryBackupRole,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              'AWS Backup requires its service-owned backup policy; the selection is restricted to this stack durable DynamoDB table ARNs.',
          },
        ],
        true,
      );
    }

    const credentialMigrationEntries = [
      {
        SourceSecretArn: legacyAdminSecret.secretArn,
        TargetSecretArn: adminCredentialSecret.secretArn,
        Owner: { kind: 'platform' },
        CredentialId: 'platform-bootstrap-v1',
      },
      ...Object.entries(legacyTenantAdminSecrets).map(([tenant, sourceSecret]) => ({
        SourceSecretArn: sourceSecret.secretArn,
        TargetSecretArn: tenantAdminCredentialSecrets[tenant].secretArn,
        Owner: { kind: 'tenant', tenant_id: tenant },
        CredentialId: `${tenant}-bootstrap-v1`,
        ...(props.offboardedTenantIds?.includes(tenant)
          ? { AllowRemoved: true }
          : {}),
      })),
      ...scimTenantIds.map((tenant) => ({
        SourceSecretArn: legacyScimSecrets[tenant].secretArn,
        TargetSecretArn: scimCredentialSecrets[tenant].secretArn,
        Owner: { kind: 'scim_tenant', tenant_id: tenant },
        CredentialId: `${tenant}-scim-bootstrap-v1`,
        ...(props.offboardedTenantIds?.includes(tenant)
          ? { AllowRemoved: true }
          : {}),
      })),
    ];
    const adminCredentialMigrationFn = new lambda.Function(
      this,
      'AdminCredentialMigrationFn',
      {
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        timeout: Duration.seconds(60),
        code: lambda.Code.fromAsset(props.credentialMigrationAssetPath),
        environment: {
          CREDENTIAL_MIGRATION_MODE: 'admin',
        },
      },
    );
    for (const secret of [
      legacyAdminSecret,
      ...Object.values(legacyTenantAdminSecrets),
      adminCredentialSecret,
      ...Object.values(tenantAdminCredentialSecrets),
      ...Object.values(legacyScimSecrets),
      ...Object.values(scimCredentialSecrets),
    ]) {
      secret.grantRead(adminCredentialMigrationFn);
    }
    adminCredentialMigrationFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['secretsmanager:PutSecretValue'],
        resources: [
          adminCredentialSecret.secretArn,
          ...Object.values(tenantAdminCredentialSecrets).map((secret) => secret.secretArn),
          ...Object.values(scimCredentialSecrets).map((secret) => secret.secretArn),
        ],
      }),
    );
    adminCredentialMigrationFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['secretsmanager:UpdateSecretVersionStage'],
        resources: [
          adminCredentialSecret.secretArn,
          ...Object.values(tenantAdminCredentialSecrets).map((secret) => secret.secretArn),
          ...Object.values(scimCredentialSecrets).map((secret) => secret.secretArn),
        ],
        conditions: {
          StringEquals: {
            'secretsmanager:VersionStage': ['AWSCURRENT', 'AGENTAUTH_VALIDATED'],
          },
        },
      }),
    );
    const adminCredentialMigrationProvider = new cr.Provider(
      this,
      'AdminCredentialMigrationProvider',
      { onEventHandler: adminCredentialMigrationFn },
    );
    const adminCredentialMigration = new CustomResource(
      this,
      'AdminCredentialMigration',
      {
        serviceToken: adminCredentialMigrationProvider.serviceToken,
        properties: {
          MigrationVersion: 'admin-scim-credential-set-v3-copy',
          Credentials: credentialMigrationEntries,
        },
      },
    );
    NagSuppressions.addResourceSuppressions(
      adminCredentialMigrationFn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'One-time credential wrapper uses AWSLambdaBasicExecutionRole only for CloudWatch Logs; secret access is restricted to the configured platform and tenant ARNs.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      adminCredentialMigrationProvider,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'CDK Provider framework Lambda uses AWSLambdaBasicExecutionRole for CloudFormation callbacks.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'CDK Provider framework invokes only the admin credential migration handler; framework wildcard permission is scoped to that function.',
        },
      ],
      true,
    );

    const tenantAdminTargetArns = Object.fromEntries(
      Object.entries(tenantAdminCredentialSecrets).map(([tenant, secret]) => [
        tenant,
        secret.secretArn,
      ]),
    );
    const scimTargetArns = Object.fromEntries(
      Object.entries(scimCredentialSecrets).map(([tenant, secret]) => [
        tenant,
        secret.secretArn,
      ]),
    );
    const tenantSecretDependencies = Object.fromEntries(
      governanceTenantIds.map((tenant) => {
        const dependencies: Array<Record<string, unknown>> = [];
        const tenantAdminTarget = tenantAdminCredentialSecrets[tenant];
        if (tenantAdminTarget) {
          dependencies.push({
            purpose: 'tenant_admin',
            secret_ref: tenantAdminTarget.secretArn,
            ownership: 'product_managed',
            resource_account: this.account,
            resource_region: this.region,
            ownership_revision: 1,
          });
        }
        const scimTarget = scimCredentialSecrets[tenant];
        if (scimTarget) {
          dependencies.push({
            purpose: 'scim',
            secret_ref: scimTarget.secretArn,
            ownership: 'product_managed',
            resource_account: this.account,
            resource_region: this.region,
            ownership_revision: 1,
          });
        }
        const tenantAdminSource = legacyTenantAdminSecrets[tenant];
        if (tenantAdminSource) {
          dependencies.push({
            purpose: 'tenant_admin_legacy_source',
            secret_ref: tenantAdminSource.secretArn,
            ownership: 'external',
            resource_account: this.account,
            resource_region: this.region,
            ownership_revision: 0,
          });
        }
        const scimSource = legacyScimSecrets[tenant];
        if (scimSource) {
          dependencies.push({
            purpose: 'scim_legacy_source',
            secret_ref: scimSource.secretArn,
            ownership: 'product_managed',
            resource_account: this.account,
            resource_region: this.region,
            ownership_revision: 1,
          });
        }
        return [tenant, dependencies];
      }),
    );
    const runtimeBootstrapDocument = {
      schema_version: 1,
      governance_hmac_secret_arn: governanceHmacSecret.secretArn,
      admin_credential_secret_arn: adminCredentialSecret.secretArn,
      passkey_origin_secret_arn: cloudFrontOriginSecret?.secretArn ?? null,
      saas_tenants: saasTenantIds,
      tenant_subject_types: props.tenantSubjectTypes ?? {},
      redirect_prefix_allowed_hosts: props.redirectPrefixAllowedHosts ?? {},
      tenant_admin_secret_arns: tenantAdminTargetArns,
      scim_credential_secret_arn:
        saasTenantIds.length > 0 ? null : scimCredentialSecrets.default.secretArn,
      scim_tenant_secret_arns: saasTenantIds.length > 0 ? scimTargetArns : {},
      federation_attribute_mappings_table:
        federationAttributeMappingsTable.tableName,
      tenant_residency: canonicalTenantResidency,
      tenant_secret_dependencies: tenantSecretDependencies,
    };
    const runtimeBootstrapSecretString = Fn.toJsonString(runtimeBootstrapDocument);
    const runtimeBootstrapConfigSecret = new secretsmanager.Secret(
      this,
      'RuntimeBootstrapConfig',
      {
        description:
          'Deployment-owned Agent Auth governance and credential bootstrap configuration',
        secretStringValue: SecretValue.unsafePlainText(
          runtimeBootstrapSecretString,
        ),
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );
    const runtimeBootstrapRevision = createHash('sha256')
      .update(JSON.stringify(this.resolve(runtimeBootstrapSecretString)))
      .update(canonicalEmaPolicies ?? '')
      .digest('hex')
      .slice(0, 16);
    NagSuppressions.addResourceSuppressions(runtimeBootstrapConfigSecret, [
      {
        id: 'AwsSolutions-SMG4',
        reason:
          'This Secret is an immutable deployment bootstrap document containing resource references, not an independently rotatable credential; stack updates publish new versions.',
      },
    ]);
    const runtimeBootstrapEnvironment: Record<string, string> = {
      AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN:
        runtimeBootstrapConfigSecret.secretArn,
      AGENT_AUTH_BOOTSTRAP_REVISION: runtimeBootstrapRevision,
    };
    const emaPoliciesSecret = canonicalEmaPolicies
      ? new secretsmanager.Secret(this, 'EmaPolicies', {
          description:
            'Deployment-owned tenant-scoped EMA trust policy configuration',
          secretStringValue: SecretValue.unsafePlainText(canonicalEmaPolicies),
          removalPolicy: RemovalPolicy.DESTROY,
        })
      : undefined;
    if (emaPoliciesSecret) {
      NagSuppressions.addResourceSuppressions(emaPoliciesSecret, [
        {
          id: 'AwsSolutions-SMG4',
          reason:
            'This Secret stores deployment-owned public trust policy rather than a rotatable credential; stack updates publish new versions.',
        },
      ]);
    }
    let standbyRuntimeBootstrapConfigSecret:
      | secretsmanager.Secret
      | undefined;
    if (tenantKeyReplicaRegions.length > 0) {
      const standbyRegion = tenantKeyReplicaRegions[0];
      const replicaSecretArn = (secret: secretsmanager.ISecret): string => {
        const arnParts = Fn.split(':', secret.secretArn);
        return Fn.join(':', [
          Fn.select(0, arnParts),
          Fn.select(1, arnParts),
          Fn.select(2, arnParts),
          standbyRegion,
          Fn.select(4, arnParts),
          Fn.select(5, arnParts),
          Fn.select(6, arnParts),
        ]);
      };
      const standbyTenantAdminArns = Object.fromEntries(
        Object.entries(tenantAdminCredentialSecrets).map(
          ([tenant, secret]) => [tenant, replicaSecretArn(secret)],
        ),
      );
      const standbyScimArns = Object.fromEntries(
        Object.entries(scimCredentialSecrets).map(([tenant, secret]) => [
          tenant,
          replicaSecretArn(secret),
        ]),
      );
      const standbyTenantSecretDependencies = Object.fromEntries(
        saasTenantIds.map((tenant) => [
          tenant,
          [
            {
              purpose: 'tenant_admin',
              secret_ref: standbyTenantAdminArns[tenant],
              ownership: 'product_managed',
              resource_account: this.account,
              resource_region: standbyRegion,
              ownership_revision: 1,
            },
            {
              purpose: 'scim',
              secret_ref: standbyScimArns[tenant],
              ownership: 'product_managed',
              resource_account: this.account,
              resource_region: standbyRegion,
              ownership_revision: 1,
            },
          ],
        ]),
      );
      const standbyRuntimeBootstrapSecretString = Fn.toJsonString({
        schema_version: 1,
        governance_hmac_secret_arn: replicaSecretArn(governanceHmacSecret),
        admin_credential_secret_arn: replicaSecretArn(adminCredentialSecret),
        passkey_origin_secret_arn: cloudFrontOriginSecret
          ? replicaSecretArn(cloudFrontOriginSecret)
          : null,
        saas_tenants: saasTenantIds,
        tenant_subject_types: props.tenantSubjectTypes ?? {},
        redirect_prefix_allowed_hosts: props.redirectPrefixAllowedHosts ?? {},
        tenant_admin_secret_arns: standbyTenantAdminArns,
        scim_credential_secret_arn: null,
        scim_tenant_secret_arns: standbyScimArns,
        tenant_residency: canonicalTenantResidency,
        tenant_secret_dependencies: standbyTenantSecretDependencies,
      });
      standbyRuntimeBootstrapConfigSecret = new secretsmanager.Secret(
        this,
        'StandbyRuntimeBootstrapConfig',
        {
          description:
            'Deployment-owned standby bootstrap configuration with replica-local resource references',
          secretStringValue: SecretValue.unsafePlainText(
            standbyRuntimeBootstrapSecretString,
          ),
          removalPolicy: RemovalPolicy.DESTROY,
          ...runtimeSecretReplication,
        },
      );
      NagSuppressions.addResourceSuppressions(
        standbyRuntimeBootstrapConfigSecret,
        [
          {
            id: 'AwsSolutions-SMG4',
            reason:
              'This replicated Secret is an immutable deployment bootstrap document containing resource references, not an independently rotatable credential; stack updates publish new versions.',
          },
        ],
      );
    }
    const deploymentFormEnvironment: Record<string, string> = {
      AGENT_AUTH_DEPLOYMENT_COMMIT: props.deploymentCommit,
      ...(props.saasZone && props.saasControlHost
        ? {
            AGENT_AUTH_FORM: 'saas',
            AGENT_AUTH_ZONE: props.saasZone,
            AGENT_AUTH_CONTROL_HOST: props.saasControlHost,
          }
        : {}),
      ...(props.enableTenantPartitioning
        ? { AGENT_AUTH_ENABLE_TENANT_PARTITIONING: '1' }
        : {}),
    };
    const tenantKeyRuntimeEnvironment: Record<string, string> =
      tenantKeysTable && tenantKeyOperationsQueue
        ? {
            TENANT_KEYS_TABLE: tenantKeysTable.tableName,
            TENANT_KEY_OPERATIONS_QUEUE_URL: tenantKeyOperationsQueue.queueUrl,
          }
        : {};

    // === EventBridge:授权会话状态迁移事件投影 + CloudWatch Logs 审计湖(spec 004 §3.3 / C6.5)===
    // 专用 bus 收 AuthzSessionTransition 投影(source=agent-auth.authz-session)→ rule → CloudWatch Logs
    // target(**持久可查的消费方**,解"无消费者=半成品":投影落地成可回放的审计流)。权威源仍是 DynamoDB
    // 会话记录;投影 at-least-once/无序,detail 带每会话单调 sequence 供消费方去重排序回放。
    const authzEventBus = new events.EventBus(this, 'AuthzEventBus', {
      eventBusName: `${this.stackName}-authz-events`,
    });
    const authzAuditLog = new logs.LogGroup(this, 'AuthzAuditLog', {
      // 审计用保留期 6 个月(评审 Kiro M1:30 天对审计偏短);dev 栈 DESTROY 便于 cdk destroy。
      // ⚠️ CloudWatch Logs 是 P1 落地档;长期审计湖(多年留存 + Glue 可查)应 P2/P3 换 Firehose→S3→Glue(spec 004 §3.3)。
      retention: logs.RetentionDays.SIX_MONTHS,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    new events.Rule(this, 'AuthzAuditRule', {
      eventBus: authzEventBus,
      description: 'agent-auth 授权会话迁移投影 → CloudWatch Logs 审计湖(C6.5)',
      eventPattern: { source: ['agent-auth.authz-session'] },
      targets: [new targets.CloudWatchLogGroup(authzAuditLog)],
    });
    // cdk-nag 抑制:CloudWatchLogGroup 事件目标由 CDK 自动生成一个 custom resource(设 log group resource
    // policy 允许 events.amazonaws.com 投递)+ 复用 CDK 共享的 custom-resource provider Lambda。这些是 CDK
    // 托管的**基础设施 plumbing**(非本栈业务 IAM):IAM5 通配是 log resource policy 所需、IAM4 是共享 provider
    // 的基本执行角色。用 by-path 抑制(精确到 CDK 生成资源,不放宽业务角色)。
    // 这两个 CDK 框架生成的资源(CloudWatchLogGroup 事件目标的 log-group-policy custom resource +
    // 共享 custom-resource provider Lambda)的**逻辑 id 含 stack 名 + CDK 生成 hash**(跨栈不同,如
    // AgentAuthDev vs AgentAuthSaas),故**不硬编码路径**——按 id 前缀动态定位后逐个抑制(SaaS 栈同样适用)。
    for (const child of this.node.findAll()) {
      const cid = child.node.id;
      if (cid.startsWith('EventsLogGroupPolicy')) {
        NagSuppressions.addResourceSuppressions(
          child,
          [
            {
              id: 'AwsSolutions-IAM5',
              reason:
                'CDK CloudWatchLogGroup 事件目标自动生成的 log group resource policy custom resource;通配限于设置该 log group 的投递策略,非业务 IAM。',
            },
          ],
          true,
        );
      }
      // 共享 custom-resource provider Lambda(CDK 命名 `AWS<hash>`)的基本执行角色(IAM4)。
      if (/^AWS[0-9a-f]{20,}$/.test(cid)) {
        NagSuppressions.addResourceSuppressions(
          child,
          [
            {
              id: 'AwsSolutions-IAM4',
              reason:
                'CDK 共享 custom-resource provider Lambda 的基本执行角色(AWSLambdaBasicExecutionRole,仅 CloudWatch Logs 写);CDK 托管 plumbing,非本栈业务权限。',
            },
          ],
          true,
        );
      }
    }

    // === API Gateway HTTP API(触发源;绝不用 Function URL)===
    // API Gateway 只是 CloudFront 回源。SelfHosted issuer 必须是浏览器公开统一入口,
    // 由已校验的 WEB_BASE_URL 固定注入；首次部署用 bootstrap origin、取得 CloudFront 域后立即二次部署。
    const httpApi = new apigw.HttpApi(this, 'HttpApi', {
      description: 'agent-auth P0 (API Gateway HTTP API → Lambda;no Function URL)',
      createDefaultStage: false,
    });
    const apiHost = Fn.select(1, Fn.split('://', httpApi.apiEndpoint));
    const runtimeIssuerHost =
      !props.saasZone ? new URL(webBaseUrl).hostname : apiHost;
    const assurancePolicyEnvironment = {
      AGENT_AUTH_STRONG_MAX_AGE_SECS: '300',
      AGENT_AUTH_HIGH_RISK_RAR_ACTIONS: 'transfer',
      AGENT_AUTH_HIGH_RISK_ADMIN_ACTIONS: 'access.manage',
    };

    // === Lambda:Rust arm64(provided.al2023),同一 artifact、独立 route scope/IAM role ===
    const authEnvironment = {
        // SaaS reconstructs issuers from tenant hosts; only SelfHosted consumes this value.
        ...(!props.saasZone ? { AGENT_AUTH_HOST: runtimeIssuerHost } : {}),
        ...regionFenceEnvironment,
        ...(props.emaEnabled && props.deploymentCommit
          ? { AGENT_AUTH_DEPLOYMENT_COMMIT: props.deploymentCommit }
          : {}),
        ...(saasTenantIds.length > 0
          ? {}
          : {
              SIGNING_KEY_ID: activeEcSigningKeyId,
              SIGNING_KEY_IDS_PUBLISHED: publishedEcSigningKeyIds,
              RSA_SIGNING_KEY_ID: idTokenSigningKey.keyId,
            }),
        CODES_TABLE: codesTable.tableName,
        AUTH_REFS_TABLE: clientAuthorityRefsTable.tableName,
        CLIENTS_TABLE: clientsTable.tableName,
        INITIAL_ACCESS_TOKENS_TABLE: initialAccessTokensTable.tableName,
        REFRESH_TABLE: refreshTable.tableName,
        SESSIONS_TABLE: sessionsTable.tableName,
        MAGICLINK_TABLE: magicLinkTable.tableName,
        INVITATIONS_TABLE: invitationsTable.tableName,
        ...(invitationTtlSecs !== 86_400
          ? { AGENT_AUTH_INVITATION_TTL_SECS: String(invitationTtlSecs) }
          : {}),
        RECOVERY_TABLE: recoveryTable.tableName,
        AUTHZ_SESSIONS_TABLE: authzSessionsTable.tableName,
        AUTHZ_EVENT_BUS: authzEventBus.eventBusName,
        MESSAGES_TABLE: messagesTable.tableName,
        SECURITY_EVENTS_TABLE: securityEventsTable.tableName,
        SSF_DELIVERIES_TABLE: ssfDeliveriesTable.tableName,
        SECURITY_EVENT_INGRESS_QUEUE_URL: securityEventIngressQueue.queueUrl,
        WORKLOAD_TRUST_TABLE: workloadTrustTable.tableName,
        CIBA_TABLE: cibaTable.tableName,
        DEVICE_TABLE: deviceTable.tableName,
        GRANTS_TABLE: grantsTable.tableName,
        ...(props.federationEnabled ? { AGENT_AUTH_FEDERATION_ENABLED: '1' } : {}),
        FEDERATION_CONFIG_TABLE: federationConfigTable.tableName,
        FEDERATION_FLOW_TABLE: federationFlowTable.tableName,
        ADMIN_AUTH_TABLE: adminAuthTable.tableName,
        ADMIN_AUTH_RUNTIME_TABLE: adminAuthRuntimeTable.tableName,
        GOVERNANCE_TABLE: governanceTable.tableName,
        GOVERNANCE_SUPPRESSION_TABLE: governanceSuppressionTable.tableName,
        GOVERNANCE_QUEUE_URL: governanceWorkerQueue.queueUrl,
        USERS_TABLE: usersTable.tableName,
        SCIM_GROUPS_TABLE: scimGroupsTable.tableName,
        PASSWORD_CREDENTIALS_TABLE: passwordCredentialsTable.tableName,
        ...(props.passkeyEnabled ? { AGENT_AUTH_PASSKEY_ENABLED: '1' } : {}),
        ...(props.cimdEnabled ? { AGENT_AUTH_CIMD_ENABLED: '1' } : {}),
        ...(cimdAllowedDomains.length > 0
          ? { AGENT_AUTH_CIMD_ALLOWED_DOMAINS: cimdAllowedDomains.join(',') }
          : {}),
        ...(cimdTenantPolicyKeys.length > 0
          ? {
              AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS: JSON.stringify(
                cimdTenantAllowedDomains,
              ),
            }
          : {}),
        PASSKEY_TABLE: passkeyTable.tableName,
        PASSKEY_CHALLENGE_TABLE: passkeyChallengeTable.tableName,
        PAR_TABLE: parTable.tableName,
        RATE_LIMIT_TABLE: rateLimitTable.tableName,
        AGENT_AUTH_PHASE: props.phase ?? 'p2',
        JTI_TABLE: jtiTable.tableName,
        GRACE_TABLE: graceTable.tableName,
        CIBA_KMS: cibaNotificationKeyAlias,
        SERVER_SECRET: serverSecret.secretValue.unsafeUnwrap(),
        ...runtimeBootstrapEnvironment,
        WEB_BASE_URL: webBaseUrl,
        ...assurancePolicyEnvironment,
        ...(props.allowLoginPlaceholder ? { AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER: '1' } : {}),
        ...(props.dcrMode ? { AGENT_AUTH_DCR_MODE: props.dcrMode } : {}),
        ...deploymentFormEnvironment,
        ...(cloudFrontOriginSecondarySecret
          ? { AGENT_AUTH_ORIGIN_AUTH_REVISION: saasOriginAuthRevision }
          : {}),
        ...tenantKeyRuntimeEnvironment,
        ...(props.kmsTenantGateCapacity !== undefined
          ? {
              AGENT_AUTH_KMS_TENANT_GATE_CAPACITY: String(props.kmsTenantGateCapacity),
              AGENT_AUTH_KMS_TENANT_GATE_REFILL_PER_SEC: String(
                props.kmsTenantGateRefillPerSec ?? 20,
              ),
            }
          : {}),
        ...(props.authzEnabled ? { AGENT_AUTH_AUTHZ_ENABLED: '1' } : {}),
        ...(props.policySet ? { AGENT_AUTH_POLICY_SET: props.policySet } : {}),
        DOMAIN_MAP_TABLE: domainMapTable.tableName,
        ...(props.byodEnabled ? { AGENT_AUTH_BYOD_ENABLED: '1' } : {}),
        ...(mtlsSvidDeploymentEnabled
          ? { AGENT_AUTH_MTLS_SVID_ENABLED: '1' }
          : {}),
        ...(emaPoliciesSecret
          ? { AGENT_AUTH_EMA_POLICIES_SECRET_ARN: emaPoliciesSecret.secretArn }
          : {}),
        ...(props.emaEnabled ? { AGENT_AUTH_EMA_ENABLED: '1' } : {}),
    };
    const authFnLogGroup = new logs.LogGroup(this, 'AuthFnLogGroup', {
      retention: logs.RetentionDays.SEVEN_YEARS,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    // 使用新的逻辑资源完成一次性拆分：先创建 TokenFn/exact routes，再把 proxy 切到
    // NonTokenFn，最后删除旧单体 AuthFn。禁止原地缩权造成部署窗口内 /token 中断或权限回退。
    const fn = new lambda.Function(this, 'NonTokenFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.lambdaAssetPath),
      memorySize: 512,
      timeout: Duration.seconds(10),
      logGroup: authFnLogGroup,
      environment: {
        ...authEnvironment,
        ...(!props.saasZone
          ? {
              ATTRIBUTE_NAMESPACES_TABLE:
                attributeNamespacesTable.tableName,
              FEDERATION_ATTRIBUTE_MAPPINGS_TABLE:
                federationAttributeMappingsTable.tableName,
            }
          : {}),
        SCOPE: 'non_token',
      },
    });
    const tokenFnLogGroup = new logs.LogGroup(this, 'TokenFnLogGroup', {
      retention: logs.RetentionDays.SEVEN_YEARS,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const tokenFn = new lambda.Function(this, 'TokenFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.lambdaAssetPath),
      memorySize: 512,
      timeout: Duration.seconds(10),
      logGroup: tokenFnLogGroup,
      environment: {
        ...authEnvironment,
        SCOPE: 'token',
        GRACE_KMS_KEY_ID: tokenGraceKey.keyId,
      },
    });
    const httpRuntimes = [fn, tokenFn] as const;
    for (const runtime of httpRuntimes) {
      runtimeBootstrapConfigSecret.grantRead(runtime);
      cloudFrontOriginSecret?.grantRead(runtime);
      cloudFrontOriginSecondarySecret?.grantRead(runtime);
      if (emaPoliciesSecret) {
        emaPoliciesSecret.grantRead(runtime);
        runtime.node.addDependency(emaPoliciesSecret);
      }
      governanceHmacSecret.grantRead(runtime);
      runtime.node.addDependency(adminCredentialMigration);
    }

    // Sign 仅授 active key；GetPublicKey 覆盖有界 published 集，支持 CDK 表达完整轮换相位。
    const managedTenantKeyArn = Stack.of(this).formatArn({
      service: 'kms',
      resource: 'key',
      resourceName: '*',
    });
    const managedTenantReplicaKeyArns = tenantKeyReplicaRegions.map((replicaRegion) =>
      Stack.of(this).formatArn({
        service: 'kms',
        region: replicaRegion,
        resource: 'key',
        resourceName: '*',
      }),
    );
    const managedTenantKeyAnyRegionArn = Stack.of(this).formatArn({
      service: 'kms',
      region: '*',
      resource: 'key',
      resourceName: '*',
    });
    const kmsMultiRegionServiceLinkedRoleArn = Stack.of(this).formatArn({
      service: 'iam',
      region: '',
      resource: 'role',
      resourceName:
        'aws-service-role/mrk.kms.amazonaws.com/AWSServiceRoleForKeyManagementServiceMultiRegionKeys',
    });
    const managedTenantKeyCondition = {
      StringEquals: {
        'aws:ResourceTag/agent-auth-managed': 'true',
        ...(tenantKeysTable
          ? {
              'aws:ResourceTag/agent-auth-deployment':
                tenantKeysTable.tableName,
            }
          : {}),
      },
    };
    const managedTenantKeyTagKeys = [
      'agent-auth-managed',
      'agent-auth-deployment',
      'agent-auth-tenant',
      'agent-auth-operation',
      'agent-auth-algorithm',
      'agent-auth-generation',
    ];
    const requiredManagedTenantRequestTags = {
      'ForAllValues:StringEquals': {
        'aws:TagKeys': managedTenantKeyTagKeys,
      },
      Null: Object.fromEntries(
        managedTenantKeyTagKeys.map((tagKey) => [
          `aws:RequestTag/${tagKey}`,
          'false',
        ]),
      ),
    };
    const signingKeyRuntimePolicy = new iam.Policy(this, 'SigningKeyRuntimePolicy', {
      statements: saasTenantIds.length > 0
        ? [
            new iam.PolicyStatement({
              actions: ['kms:Sign', 'kms:GetPublicKey'],
              resources: [managedTenantKeyArn],
              conditions: managedTenantKeyCondition,
            }),
          ]
        : [
            new iam.PolicyStatement({
              actions: ['kms:Sign'],
              resources: [activeEcSigningKeyArn, idTokenSigningKey.keyArn],
            }),
            new iam.PolicyStatement({
              actions: ['kms:GetPublicKey'],
              resources: [...publishedEcSigningKeyArns, idTokenSigningKey.keyArn],
            }),
          ],
    });
    if (saasTenantIds.length > 0) {
      NagSuppressions.addResourceSuppressions(
        signingKeyRuntimePolicy,
        [
          {
            id: 'AwsSolutions-IAM5',
            reason:
              'Tenant signing keys are created after stack deployment, so their key IDs cannot be enumerated at synthesis. ' +
              'The resource wildcard is limited to KMS keys in this account and region, requires the ' +
              'managed and deployment-registry resource tags, and grants only Sign and GetPublicKey.',
            appliesTo: [
              `Resource::arn:<AWS::Partition>:kms:${this.region}:${this.account}:key/*`,
              'Resource::arn:<AWS::Partition>:kms:<AWS::Region>:<AWS::AccountId>:key/*',
            ],
          },
        ],
        true,
      );
    }
    const grantSecurityEventDelivery = (runtime: lambda.Function) => {
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
          resources: [securityEventsTable.tableArn],
        }),
      );
      securityEventIngressQueue.grantSendMessages(runtime);
    };
    const grantHttpRuntimePermissions = (runtime: lambda.Function) => {
      signingKeyRuntimePolicy.attachToRole(runtime.role!);
      tenantKeysTable?.grantReadData(runtime);
      tenantKeyOperationsQueue?.grantSendMessages(runtime);
      codesTable.grantReadWriteData(runtime);
      clientAuthorityRefsTable.grantReadWriteData(runtime);
      clientsTable.grantReadWriteData(runtime);
      initialAccessTokensTable.grantReadWriteData(runtime);
      refreshTable.grantReadWriteData(runtime);
      sessionsTable.grantReadWriteData(runtime);
      magicLinkTable.grantReadWriteData(runtime);
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:DeleteItem'],
          resources: [invitationsTable.tableArn],
        }),
      );
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactWriteItems'],
          resources: [
            invitationsTable.tableArn,
            usersTable.tableArn,
            passwordCredentialsTable.tableArn,
            sessionsTable.tableArn,
          ],
        }),
      );
      recoveryTable.grantReadWriteData(runtime);
      authzSessionsTable.grantReadWriteData(runtime);
      messagesTable.grantReadWriteData(runtime);
      grantSecurityEventDelivery(runtime);
      ssfDeliveriesTable.grantReadWriteData(runtime);
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:Query'],
          resources: [
            securityEventsTable.tableArn,
            `${securityEventsTable.tableArn}/index/tenant_occurred_at-index`,
          ],
        }),
      );
      workloadTrustTable.grantReadWriteData(runtime);
      cibaTable.grantReadWriteData(runtime);
      deviceTable.grantReadWriteData(runtime);
      jtiTable.grantReadWriteData(runtime);
      grantsTable.grantReadWriteData(runtime);
      federationConfigTable.grantReadWriteData(runtime);
      federationFlowTable.grantReadWriteData(runtime);
      adminAuthTable.grantReadWriteData(runtime);
      adminAuthRuntimeTable.grantReadWriteData(runtime);
      governanceTable.grantReadWriteData(runtime);
      governanceWorkerQueue.grantSendMessages(runtime);
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            'dynamodb:GetItem',
            'dynamodb:Query',
            'dynamodb:ConditionCheckItem',
          ],
          resources: [governanceSuppressionTable.tableArn],
        }),
      );
      grantRegionControlRead(runtime);
      usersTable.grantReadWriteData(runtime);
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactWriteItems'],
          resources: [
            usersTable.tableArn,
            codesTable.tableArn,
            refreshTable.tableArn,
            clientAuthorityRefsTable.tableArn,
            authzSessionsTable.tableArn,
          ],
        }),
      );
      scimGroupsTable.grantReadWriteData(runtime);
      passwordCredentialsTable.grantReadWriteData(runtime);
      domainMapTable.grantReadWriteData(runtime);
      parTable.grantReadWriteData(runtime);
      passkeyTable.grantReadWriteData(runtime);
      passkeyChallengeTable.grantReadWriteData(runtime);
      rateLimitTable.grantReadWriteData(runtime);
    };
    for (const runtime of httpRuntimes) {
      grantHttpRuntimePermissions(runtime);
    }
    if (!props.saasZone) {
      attributeNamespacesTable.grantReadWriteData(fn);
      federationAttributeMappingsTable.grantReadWriteData(fn);
      fn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactGetItems', 'dynamodb:TransactWriteItems'],
          resources: [
            attributeNamespacesTable.tableArn,
            federationAttributeMappingsTable.tableArn,
          ],
        }),
      );
    }
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:Query', 'dynamodb:DeleteItem'],
        resources: [graceTable.tableArn],
      }),
    );
    graceTable.grantReadWriteData(tokenFn);

    const governanceWorkerLogGroup = new logs.LogGroup(
      this,
      'GovernanceWorkerLogGroup',
      {
        retention: logs.RetentionDays.SEVEN_YEARS,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const governanceWorkerFn = new lambda.Function(this, 'GovernanceWorkerFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(
        props.governanceWorkerAssetPath ?? props.lambdaAssetPath,
      ),
      memorySize: 512,
      timeout: Duration.minutes(5),
      logGroup: governanceWorkerLogGroup,
      environment: {
        AGENT_AUTH_HOST: runtimeIssuerHost,
        ...regionFenceEnvironment,
        WEB_BASE_URL: webBaseUrl,
        ...(saasTenantIds.length > 0
          ? {}
          : {
              SIGNING_KEY_ID: activeEcSigningKeyId,
              SIGNING_KEY_IDS_PUBLISHED: publishedEcSigningKeyIds,
              RSA_SIGNING_KEY_ID: idTokenSigningKey.keyId,
            }),
        CODES_TABLE: codesTable.tableName,
        AUTH_REFS_TABLE: clientAuthorityRefsTable.tableName,
        CLIENTS_TABLE: clientsTable.tableName,
        INITIAL_ACCESS_TOKENS_TABLE: initialAccessTokensTable.tableName,
        REFRESH_TABLE: refreshTable.tableName,
        SESSIONS_TABLE: sessionsTable.tableName,
        MAGICLINK_TABLE: magicLinkTable.tableName,
        INVITATIONS_TABLE: invitationsTable.tableName,
        RECOVERY_TABLE: recoveryTable.tableName,
        AUTHZ_SESSIONS_TABLE: authzSessionsTable.tableName,
        MESSAGES_TABLE: messagesTable.tableName,
        SECURITY_EVENTS_TABLE: securityEventsTable.tableName,
        SSF_DELIVERIES_TABLE: ssfDeliveriesTable.tableName,
        SECURITY_EVENT_INGRESS_QUEUE_URL: securityEventIngressQueue.queueUrl,
        WORKLOAD_TRUST_TABLE: workloadTrustTable.tableName,
        CIBA_TABLE: cibaTable.tableName,
        DEVICE_TABLE: deviceTable.tableName,
        GRANTS_TABLE: grantsTable.tableName,
        FEDERATION_CONFIG_TABLE: federationConfigTable.tableName,
        FEDERATION_FLOW_TABLE: federationFlowTable.tableName,
        ADMIN_AUTH_TABLE: adminAuthTable.tableName,
        ADMIN_AUTH_RUNTIME_TABLE: adminAuthRuntimeTable.tableName,
        GOVERNANCE_TABLE: governanceTable.tableName,
        GOVERNANCE_SUPPRESSION_TABLE: governanceSuppressionTable.tableName,
        GOVERNANCE_QUEUE_URL: governanceWorkerQueue.queueUrl,
        USERS_TABLE: usersTable.tableName,
        SCIM_GROUPS_TABLE: scimGroupsTable.tableName,
        PASSWORD_CREDENTIALS_TABLE: passwordCredentialsTable.tableName,
        AGENT_AUTH_PASSWORD_WORKERS: '2',
        PASSKEY_TABLE: passkeyTable.tableName,
        PASSKEY_CHALLENGE_TABLE: passkeyChallengeTable.tableName,
        RATE_LIMIT_TABLE: rateLimitTable.tableName,
        PAR_TABLE: parTable.tableName,
        JTI_TABLE: jtiTable.tableName,
        GRACE_TABLE: graceTable.tableName,
        CIBA_KMS: cibaNotificationKeyAlias,
        DOMAIN_MAP_TABLE: domainMapTable.tableName,
        SERVER_SECRET: serverSecret.secretValue.unsafeUnwrap(),
        ...assurancePolicyEnvironment,
        ...runtimeBootstrapEnvironment,
        ...deploymentFormEnvironment,
        ...tenantKeyRuntimeEnvironment,
        AGENT_AUTH_PHASE: props.phase ?? 'p2',
        WORKER: 'governance',
      },
    });
    runtimeBootstrapConfigSecret.grantRead(governanceWorkerFn);
    governanceHmacSecret.grantRead(governanceWorkerFn);
    governanceWorkerQueue.grantConsumeMessages(governanceWorkerFn);
    governanceWorkerQueue.grantSendMessages(governanceWorkerFn);
    grantSecurityEventDelivery(governanceWorkerFn);
    tenantKeyOperationsQueue?.grantSendMessages(governanceWorkerFn);
    governanceWorkerFn.addEventSource(
      new lambdaEventSources.SqsEventSource(governanceWorkerQueue, {
        batchSize: 1,
        reportBatchItemFailures: true,
      }),
    );
    const governanceRetentionRule = new events.Rule(
      this,
      'GovernanceRetentionSchedule',
      {
        schedule: events.Schedule.rate(Duration.hours(1)),
        description:
          'Reverify due governance retention jobs and append immutable completion evidence',
      },
    );
    governanceRetentionRule.addTarget(
      new targets.LambdaFunction(governanceWorkerFn),
    );
    governanceTable.grantReadWriteData(governanceWorkerFn);
    governanceWorkerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:GetItem',
          'dynamodb:Query',
          'dynamodb:PutItem',
          'dynamodb:TransactWriteItems',
        ],
        resources: [governanceSuppressionTable.tableArn],
      }),
    );
    for (const table of [
      codesTable,
      clientAuthorityRefsTable,
      clientsTable,
      initialAccessTokensTable,
      refreshTable,
      sessionsTable,
      magicLinkTable,
      invitationsTable,
      recoveryTable,
      authzSessionsTable,
      messagesTable,
      ssfDeliveriesTable,
      workloadTrustTable,
      cibaTable,
      deviceTable,
      jtiTable,
      graceTable,
      grantsTable,
      federationConfigTable,
      federationAttributeMappingsTable,
      federationFlowTable,
      adminAuthTable,
      adminAuthRuntimeTable,
      usersTable,
      scimGroupsTable,
      passwordCredentialsTable,
      passkeyTable,
      passkeyChallengeTable,
      parTable,
      rateLimitTable,
      domainMapTable,
      ...(tenantKeysTable ? [tenantKeysTable] : []),
    ]) {
      table.grantReadWriteData(governanceWorkerFn);
    }
    governanceWorkerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:TransactWriteItems'],
        resources: [
          codesTable.tableArn,
          refreshTable.tableArn,
          clientAuthorityRefsTable.tableArn,
        ],
      }),
    );
    grantRegionControlRead(governanceWorkerFn);
    governanceWorkerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:GetPublicKey'],
        resources: [...publishedEcSigningKeyArns, idTokenSigningKey.keyArn],
      }),
    );
    governanceWorkerFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:DescribeKey'],
        resources: [managedTenantKeyAnyRegionArn],
        conditions: managedTenantKeyCondition,
      }),
    );
    const federationSecretPrefixArn =
      `arn:aws:secretsmanager:${this.region}:${this.account}:secret:agent-auth/federation/*`;
    const adminOidcSecretPrefixArn =
      `arn:aws:secretsmanager:${this.region}:${this.account}:secret:agent-auth/admin-oidc/*`;
    const productManagedTenantSecretArns = [
      ...Object.values(tenantAdminCredentialSecrets).map((secret) => secret.secretArn),
      ...Object.values(scimCredentialSecrets).map((secret) => secret.secretArn),
      ...Object.values(legacyScimSecrets).map((secret) => secret.secretArn),
    ];
    if (productManagedTenantSecretArns.length > 0) {
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            'secretsmanager:DescribeSecret',
            'secretsmanager:RemoveRegionsFromReplication',
            'secretsmanager:DeleteSecret',
          ],
          resources: productManagedTenantSecretArns,
        }),
      );
    }
    const externalTenantSecretArns = Object.values(legacyTenantAdminSecrets).map(
      (secret) => secret.secretArn,
    );
    const governanceExternalSecretInspectionPolicy = new iam.Policy(
      this,
      'GovernanceExternalSecretInspectionPolicy',
      {
        statements: [
          new iam.PolicyStatement({
            actions: ['secretsmanager:DescribeSecret'],
            resources: [
              ...externalTenantSecretArns,
              federationSecretPrefixArn,
              adminOidcSecretPrefixArn,
            ],
          }),
        ],
      },
    );
    governanceExternalSecretInspectionPolicy.attachToRole(governanceWorkerFn.role!);
    NagSuppressions.addResourceSuppressions(
      governanceExternalSecretInspectionPolicy,
      [
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Governance verifies externally owned tenant dependencies without reading or deleting them. ' +
            'Federation and Admin OIDC references are selected from tenant configuration and remain ' +
            'restricted to their dedicated Secrets Manager prefixes.',
          appliesTo: [
            `Resource::${federationSecretPrefixArn}`,
            `Resource::${adminOidcSecretPrefixArn}`,
          ],
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      governanceWorkerFn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'Governance worker basic execution role is limited to its retained CloudWatch log group; destructive business permissions are explicit below.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Governance deletion adapters query subject indexes and conditionally delete rows; CDK table grants are scoped to the enumerated stack tables and their indexes. Suppression mutation remains a separate PutItem-only statement.',
        },
      ],
      true,
    );
    const runtimeCredentialSecretArns = [
      adminCredentialSecret.secretArn,
      ...Object.values(tenantAdminCredentialSecrets).map((secret) => secret.secretArn),
      ...Object.values(scimCredentialSecrets).map((secret) => secret.secretArn),
    ];
    const legacyCredentialSourceArns = [
      legacyAdminSecret.secretArn,
      ...Object.values(legacyTenantAdminSecrets).map((secret) => secret.secretArn),
      ...Object.values(legacyScimSecrets).map((secret) => secret.secretArn),
    ];
    const adminCredentialRuntimePolicy = new iam.Policy(
      this,
      'AdminCredentialRuntimePolicy',
      {
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.DENY,
            actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
            resources: legacyCredentialSourceArns,
          }),
          new iam.PolicyStatement({
            actions: ['secretsmanager:DescribeSecret', 'secretsmanager:GetSecretValue'],
            resources: runtimeCredentialSecretArns,
          }),
          new iam.PolicyStatement({
            actions: ['secretsmanager:UpdateSecretVersionStage'],
            resources: runtimeCredentialSecretArns,
            conditions: {
              StringEquals: {
                'secretsmanager:VersionStage': [
                  'AGENTAUTH_VALIDATED',
                  'AGENTAUTH_ROLLBACK_PENDING',
                ],
              },
            },
          }),
          new iam.PolicyStatement({
            actions: ['secretsmanager:GetSecretValue'],
            resources: [federationSecretPrefixArn, adminOidcSecretPrefixArn],
          }),
        ],
      },
    );
    adminCredentialRuntimePolicy.attachToRole(fn.role!);
    NagSuppressions.addResourceSuppressions(
      adminCredentialRuntimePolicy,
      [
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Federation and Admin OIDC client secrets are selected from tenant configuration at runtime. ' +
            'Access is restricted to two dedicated Secrets Manager prefixes; Admin OIDC additionally ' +
            'requires the exact agent-auth/admin-oidc/<tenant> reference before any read.',
          appliesTo: [
            `Resource::${federationSecretPrefixArn}`,
            `Resource::${adminOidcSecretPrefixArn}`,
          ],
        },
      ],
      true,
    );
    // 联邦和 Admin OIDC 上游 secret 读取也固定在上述受审计策略内，避免 CDK 将它们挤入
    // 自动生成且未被结构测试覆盖的 overflow managed policy。Admin handler 还会把引用收紧为
    // `agent-auth/admin-oidc/<tenant>`，防跨租户选取。
    // 宽限缓存 CMK 严格只授 TokenFn。主 AuthFn 仅可 Query/Delete GraceTable 完成撤销级联,
    // 无法读取、写入或解密 envelope payload。
    tokenFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
        resources: [tokenGraceKey.keyArn],
      }),
    );
    // CIBA notification token 使用独立 CMK;CIBA protocol 与 token poll 分别位于两个 runtime。
    for (const runtime of httpRuntimes) {
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
          resources: [cibaNotificationKey.keyArn],
        }),
      );
      authzEventBus.grantPutEventsTo(runtime);
    }

    // === Security event archive delivery: DynamoDB Stream → S3, retry → SQS ===
    const securityEventArchiveLogGroup = new logs.LogGroup(
      this,
      'SecurityEventArchiveLogGroup',
      {
        retention: logs.RetentionDays.SEVEN_YEARS,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const securityEventArchiveFn = new lambda.Function(this, 'SecurityEventArchiveFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.securityEventArchiveAssetPath),
      memorySize: 256,
      timeout: Duration.seconds(30),
      logGroup: securityEventArchiveLogGroup,
      environment: {
        SECURITY_EVENTS_TABLE: securityEventsTable.tableName,
        SECURITY_EVENT_ARCHIVE_BUCKET: securityEventArchiveBucket.bucketName,
        SECURITY_EVENT_ARCHIVE_DLQ_URL: securityEventArchiveDlq.queueUrl,
        SECURITY_EVENT_INGRESS_DLQ_URL: securityEventIngressDlq.queueUrl,
        SECURITY_EVENT_INGRESS_FAILURE_BUCKET: securityEventIngressFailureBucket.bucketName,
      },
    });
    securityEventArchiveFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem'],
        resources: [securityEventsTable.tableArn],
      }),
    );
    securityEventArchiveFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:Query'],
        resources: [
          `${securityEventsTable.tableArn}/index/delivery_status-index`,
        ],
      }),
    );
    securityEventArchiveBucket.grantPut(
      securityEventArchiveFn,
      'security-events/*',
    );
    securityEventArchiveFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetObject'],
        resources: [
          securityEventArchiveBucket.arnForObjects('security-events/*'),
        ],
      }),
    );
    securityEventArchiveDlq.grantSendMessages(securityEventArchiveFn);
    securityEventIngressDlq.grantSendMessages(securityEventArchiveFn);
    securityEventStreamFailureBucket.grantRead(securityEventArchiveFn);
    securityEventIngressFailureBucket.grantPut(
      securityEventArchiveFn,
      'security-event-ingress-failures/*',
    );
    securityEventArchiveFn.addEventSource(
      new lambdaEventSources.DynamoEventSource(securityEventsTable, {
        startingPosition: lambda.StartingPosition.TRIM_HORIZON,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3,
        maxRecordAge: Duration.days(1),
        onFailure: new lambdaEventSources.S3OnFailureDestination(
          securityEventStreamFailureBucket,
        ),
        filters: [
          lambda.FilterCriteria.filter({
            eventName: lambda.FilterRule.isEqual('INSERT'),
          }),
        ],
      }),
    );
    securityEventStreamFailureBucket.addEventNotification(
      s3.EventType.OBJECT_CREATED,
      new s3Notifications.SqsDestination(securityEventStreamFailureNotificationQueue),
    );
    securityEventArchiveFn.addEventSource(
      new lambdaEventSources.SqsEventSource(securityEventStreamFailureNotificationQueue, {
        batchSize: 1,
      }),
    );
    securityEventArchiveFn.addEventSource(
      new lambdaEventSources.SqsEventSource(securityEventIngressQueue, {
        batchSize: 1,
      }),
    );
    const securityEventRedriveRule = new events.Rule(this, 'SecurityEventRedriveSchedule', {
      schedule: events.Schedule.rate(Duration.minutes(5)),
      description:
        'Resume security-event pending outboxes, redrive dead letters, and refresh S3 archives',
    });
    securityEventRedriveRule.addTarget(new targets.LambdaFunction(securityEventArchiveFn));

    let tenantKeyProvisionerFn: lambda.Function | undefined;
    let tenantKeyProvisionerLogGroup: logs.LogGroup | undefined;
    let tenantKeyReconcileRule: events.Rule | undefined;
    if (tenantKeysTable && tenantKeyOperationsQueue && tenantKeyOperationsDlq) {
      if (!props.tenantKeyProvisionerAssetPath) {
        throw new Error('SaaS Stack requires tenantKeyProvisionerAssetPath');
      }
      tenantKeyProvisionerLogGroup = new logs.LogGroup(
        this,
        'TenantKeyProvisionerLogGroup',
        {
          retention: logs.RetentionDays.SEVEN_YEARS,
          removalPolicy: RemovalPolicy.RETAIN,
        },
      );
      tenantKeyProvisionerFn = new lambda.Function(this, 'TenantKeyProvisionerFn', {
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        code: lambda.Code.fromAsset(props.tenantKeyProvisionerAssetPath),
        memorySize: 256,
        timeout: Duration.minutes(5),
        logGroup: tenantKeyProvisionerLogGroup,
        environment: {
          TENANT_KEYS_TABLE: tenantKeysTable.tableName,
          TENANT_KEY_OPERATIONS_QUEUE_URL: tenantKeyOperationsQueue.queueUrl,
          GOVERNANCE_TABLE: governanceTable.tableName,
          GOVERNANCE_SUPPRESSION_TABLE: governanceSuppressionTable.tableName,
          SAAS_TENANTS: JSON.stringify(saasTenantIds),
          TENANT_KEY_REPLICA_REGIONS: JSON.stringify(tenantKeyReplicaRegions),
          ...regionFenceEnvironment,
        },
      });
      tenantKeysTable.grantReadWriteData(tenantKeyProvisionerFn);
      governanceTable.grantReadWriteData(tenantKeyProvisionerFn);
      tenantKeyProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactWriteItems'],
          resources: [governanceTable.tableArn],
        }),
      );
      tenantKeyOperationsQueue.grantSendMessages(tenantKeyProvisionerFn);
      grantRegionControlRead(tenantKeyProvisionerFn);
      tenantKeyProvisionerFn.addEventSource(
        new lambdaEventSources.SqsEventSource(tenantKeyOperationsQueue, {
          batchSize: 1,
          reportBatchItemFailures: true,
        }),
      );
      tenantKeyProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:CreateKey', 'kms:TagResource'],
          resources: ['*'],
          conditions: {
            StringEquals: {
              'aws:RequestTag/agent-auth-managed': 'true',
              'aws:RequestTag/agent-auth-deployment':
                tenantKeysTable.tableName,
              'aws:RequestedRegion': [this.region, ...tenantKeyReplicaRegions],
            },
            ...requiredManagedTenantRequestTags,
          },
        }),
      );
      tenantKeyProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['iam:CreateServiceLinkedRole'],
          resources: [kmsMultiRegionServiceLinkedRoleArn],
          conditions: {
            StringEquals: {
              'iam:AWSServiceName': 'mrk.kms.amazonaws.com',
            },
          },
        }),
      );
      if (tenantKeyReplicaRegions.length > 0) {
        // ReplicateKey does not expose request/resource tag condition keys.
        tenantKeyProvisionerFn.addToRolePolicy(
          new iam.PolicyStatement({
            actions: ['kms:ReplicateKey'],
            resources: [managedTenantKeyArn],
            conditions: {
              StringEquals: {
                'kms:CallerAccount': this.account,
                'kms:ReplicaRegion': tenantKeyReplicaRegions,
              },
            },
          }),
        );
      }
      tenantKeyProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['tag:GetResources'],
          resources: ['*'],
        }),
      );
      tenantKeyProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: [
            'kms:GetPublicKey',
            'kms:ListResourceTags',
            'kms:Sign',
          ],
          resources: [managedTenantKeyArn, ...managedTenantReplicaKeyArns],
          conditions: managedTenantKeyCondition,
        }),
      );
      tenantKeyProvisionerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:DescribeKey', 'kms:ScheduleKeyDeletion'],
          resources: [managedTenantKeyAnyRegionArn],
          conditions: managedTenantKeyCondition,
        }),
      );
      tenantKeyReconcileRule = new events.Rule(this, 'TenantKeyReconcileSchedule', {
        schedule: events.Schedule.rate(Duration.minutes(1)),
        description:
          'Ensure fixed-domain SaaS tenant key sets and reconcile compensation/retirement',
      });
      tenantKeyReconcileRule.addTarget(
        new targets.LambdaFunction(tenantKeyProvisionerFn),
      );
      NagSuppressions.addResourceSuppressions(
        tenantKeyProvisionerFn,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              'Lambda basic execution role is limited to writing this provisioner log group.',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason:
              'KMS CreateKey has no resource ARN before creation and Resource Groups Tagging GetResources has no resource-level permissions. ' +
              'Creation requires the complete managed tag set, including the deployment registry id, and is limited to the primary and configured replica regions. ' +
              'KMS ReplicateKey does not support tag condition keys, so it is restricted to this account primary-region key ARNs, this caller account, and configured replica regions. ' +
              'Historical MRK replicas can outlive the current region configuration, ' +
              'so cleanup spans this account in all regions and requires both managed and deployment-registry resource tags.',
          },
        ],
        true,
      );
    }

    // === Shared Signals transmitter: canonical SecurityEvents → outbox → HTTPS receiver ===
    const ssfStreamFailureBucket = new s3.Bucket(this, 'SsfStreamFailureBucket', {
      versioned: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [{
        expiration: Duration.days(400),
        noncurrentVersionExpiration: Duration.days(400),
      }],
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const ssfStreamFailureReplayDlq = new sqs.Queue(
      this,
      'SsfStreamFailureReplayDlq',
      {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(31),
      },
    );
    const ssfStreamFailureReplayQueue = new sqs.Queue(
      this,
      'SsfStreamFailureReplayQueue',
      {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(31),
        deadLetterQueue: {
          queue: ssfStreamFailureReplayDlq,
          maxReceiveCount: 4,
        },
      },
    );
    const ssfDeliveryLogGroup = new logs.LogGroup(this, 'SsfDeliveryLogGroup', {
      retention: logs.RetentionDays.SEVEN_YEARS,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const ssfDeliveryFn = new lambda.Function(this, 'SsfDeliveryFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.ssfDeliveryAssetPath),
      memorySize: 256,
      timeout: Duration.minutes(5),
      logGroup: ssfDeliveryLogGroup,
      environment: {
        AGENT_AUTH_HOST: runtimeIssuerHost,
        ...(regionControlTable ? { AGENT_AUTH_REGION_ID: this.region } : {}),
        ...(saasTenantIds.length > 0
          ? {}
          : {
              SIGNING_KEY_ID: activeEcSigningKeyId,
              SIGNING_KEY_IDS_PUBLISHED: publishedEcSigningKeyIds,
            }),
        SSF_DELIVERIES_TABLE: ssfDeliveriesTable.tableName,
        SSF_STREAM_FAILURE_BUCKET: ssfStreamFailureBucket.bucketName,
        ...deploymentFormEnvironment,
        ...(tenantKeysTable ? { TENANT_KEYS_TABLE: tenantKeysTable.tableName } : {}),
      },
    });
    ssfDeliveryFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:ConditionCheckItem',
          'dynamodb:GetItem',
          'dynamodb:PutItem',
          'dynamodb:UpdateItem',
          'dynamodb:Query',
          'dynamodb:TransactWriteItems',
        ],
        resources: [
          ssfDeliveriesTable.tableArn,
          `${ssfDeliveriesTable.tableArn}/index/*`,
        ],
      }),
    );
    if (tenantKeysTable) {
      tenantKeysTable.grantReadData(ssfDeliveryFn);
      ssfDeliveryFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:Sign', 'kms:GetPublicKey'],
          resources: [managedTenantKeyArn],
          conditions: managedTenantKeyCondition,
        }),
      );
    } else {
      ssfDeliveryFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:Sign'],
          resources: [activeEcSigningKeyArn],
        }),
      );
      ssfDeliveryFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:GetPublicKey'],
          resources: publishedEcSigningKeyArns,
        }),
      );
    }
    ssfDeliveryFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['s3:GetObject', 's3:GetObjectVersion'],
        resources: [ssfStreamFailureBucket.arnForObjects('*')],
      }),
    );
    ssfDeliveryFn.addEventSource(
      new lambdaEventSources.DynamoEventSource(securityEventsTable, {
        startingPosition: lambda.StartingPosition.LATEST,
        batchSize: 10,
        bisectBatchOnError: true,
        retryAttempts: 3,
        maxRecordAge: Duration.days(1),
        onFailure: new lambdaEventSources.S3OnFailureDestination(
          ssfStreamFailureBucket,
        ),
        filters: [
          lambda.FilterCriteria.filter({
            eventName: lambda.FilterRule.isEqual('INSERT'),
          }),
        ],
      }),
    );
    ssfStreamFailureBucket.addEventNotification(
      s3.EventType.OBJECT_CREATED,
      new s3Notifications.SqsDestination(ssfStreamFailureReplayQueue),
    );
    ssfDeliveryFn.addEventSource(
      new lambdaEventSources.SqsEventSource(ssfStreamFailureReplayQueue, {
        batchSize: 1,
      }),
    );
    const ssfDeliveryRule = new events.Rule(this, 'SsfDeliverySchedule', {
      schedule: events.Schedule.rate(Duration.minutes(1)),
      description: 'Deliver due Shared Signals SET outbox rows',
    });
    ssfDeliveryRule.addTarget(new targets.LambdaFunction(ssfDeliveryFn));

    if (governanceRetentionBackupVaultName) {
      const retentionBuckets = {
        security_event_archive: securityEventArchiveBucket.bucketName,
        security_event_stream_failures: securityEventStreamFailureBucket.bucketName,
        security_event_ingress_failures: securityEventIngressFailureBucket.bucketName,
        ssf_stream_failures: ssfStreamFailureBucket.bucketName,
      };
      const retentionLogGroups = {
        auth: authFnLogGroup.logGroupName,
        token: tokenFnLogGroup.logGroupName,
        governance: governanceWorkerLogGroup.logGroupName,
        security_event_archive: securityEventArchiveLogGroup.logGroupName,
        ssf_delivery: ssfDeliveryLogGroup.logGroupName,
        ...(tenantKeyProvisionerLogGroup
          ? {
              tenant_key_provisioner:
                tenantKeyProvisionerLogGroup.logGroupName,
            }
          : {}),
      };
      const retentionQueues = {
        governance_worker: governanceWorkerQueue.queueUrl,
        governance_worker_dlq: governanceWorkerDlq.queueUrl,
        security_event_archive_dlq: securityEventArchiveDlq.queueUrl,
        security_event_ingress: securityEventIngressQueue.queueUrl,
        security_event_ingress_dlq: securityEventIngressDlq.queueUrl,
        security_event_stream_failures:
          securityEventStreamFailureNotificationQueue.queueUrl,
        security_event_stream_failures_dlq:
          securityEventStreamFailureNotificationDlq.queueUrl,
        ssf_stream_failures: ssfStreamFailureReplayQueue.queueUrl,
        ssf_stream_failures_dlq: ssfStreamFailureReplayDlq.queueUrl,
        ...(tenantKeyOperationsQueue && tenantKeyOperationsDlq
          ? {
              tenant_key_operations: tenantKeyOperationsQueue.queueUrl,
              tenant_key_operations_dlq: tenantKeyOperationsDlq.queueUrl,
            }
          : {}),
      };
      const governanceRetentionConfigString = Fn.toJsonString({
        replicated_tables: Object.fromEntries(
          Object.entries(replicatedAuthorityTables).map(([role, table]) => [
            role,
            table.tableName,
          ]),
        ),
        backup_vault_name: governanceRetentionBackupVaultName,
        recovery_table_arns: governanceRetentionRecoveryTableArns,
        s3_buckets: retentionBuckets,
        log_groups: retentionLogGroups,
        queue_urls: retentionQueues,
      });
      const governanceRetentionConfigSecret = new secretsmanager.Secret(
        this,
        'GovernanceRetentionConfig',
        {
          description:
            'Deployment-owned resource inventory for governance retention verification',
          secretStringValue: SecretValue.unsafePlainText(
            governanceRetentionConfigString,
          ),
          removalPolicy: RemovalPolicy.DESTROY,
        },
      );
      const governanceWorkerBootstrapRevision = createHash('sha256')
        .update(runtimeBootstrapRevision)
        .update('\0')
        .update(JSON.stringify(this.resolve(governanceRetentionConfigString)))
        .digest('hex')
        .slice(0, 16);
      governanceWorkerFn.addEnvironment(
        'GOVERNANCE_RETENTION_CONFIG_SECRET_ARN',
        governanceRetentionConfigSecret.secretArn,
      );
      governanceWorkerFn.addEnvironment(
        'AGENT_AUTH_BOOTSTRAP_REVISION',
        governanceWorkerBootstrapRevision,
      );
      governanceRetentionConfigSecret.grantRead(governanceWorkerFn);
      NagSuppressions.addResourceSuppressions(governanceRetentionConfigSecret, [
        {
          id: 'AwsSolutions-SMG4',
          reason:
            'This Secret is an immutable deployment inventory of resource identifiers, not an independently rotatable credential; stack updates publish new versions and the combined bootstrap revision restarts the worker.',
        },
      ]);
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:Scan'],
          resources: Object.values(replicatedAuthorityTables).map((table) =>
            this.formatArn({
              service: 'dynamodb',
              region: '*',
              resource: 'table',
              resourceName: table.tableName,
            })),
        }),
      );
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['backup:ListRecoveryPointsByBackupVault'],
          resources: [governanceRetentionBackupVaultArn!],
        }),
      );
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['s3:ListBucket', 's3:ListBucketVersions'],
          resources: [
            securityEventArchiveBucket.bucketArn,
            securityEventStreamFailureBucket.bucketArn,
            securityEventIngressFailureBucket.bucketArn,
            ssfStreamFailureBucket.bucketArn,
          ],
        }),
      );
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['s3:GetObject', 's3:GetObjectVersion'],
          resources: [
            securityEventArchiveBucket.arnForObjects('*'),
            securityEventStreamFailureBucket.arnForObjects('*'),
            securityEventIngressFailureBucket.arnForObjects('*'),
            ssfStreamFailureBucket.arnForObjects('*'),
          ],
        }),
      );
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['logs:FilterLogEvents'],
          resources: [
            authFnLogGroup.logGroupArn,
            tokenFnLogGroup.logGroupArn,
            governanceWorkerLogGroup.logGroupArn,
            securityEventArchiveLogGroup.logGroupArn,
            ssfDeliveryLogGroup.logGroupArn,
            ...(tenantKeyProvisionerLogGroup
              ? [tenantKeyProvisionerLogGroup.logGroupArn]
              : []),
          ],
        }),
      );
      governanceWorkerFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['sqs:GetQueueAttributes'],
          resources: [
            governanceWorkerQueue.queueArn,
            governanceWorkerDlq.queueArn,
            securityEventArchiveDlq.queueArn,
            securityEventIngressQueue.queueArn,
            securityEventIngressDlq.queueArn,
            securityEventStreamFailureNotificationQueue.queueArn,
            securityEventStreamFailureNotificationDlq.queueArn,
            ssfStreamFailureReplayQueue.queueArn,
            ssfStreamFailureReplayDlq.queueArn,
            ...(tenantKeyOperationsQueue && tenantKeyOperationsDlq
              ? [
                  tenantKeyOperationsQueue.queueArn,
                  tenantKeyOperationsDlq.queueArn,
                ]
              : []),
          ],
        }),
      );
    }

    const securityMetricNamespace = `AgentAuth/Security/${this.stackName}`;
    const addMetricFilter = (
      id: string,
      logGroup: logs.ILogGroup,
      pattern: logs.IFilterPattern,
      metricName: string,
    ) =>
      new logs.MetricFilter(this, id, {
        logGroup,
        filterPattern: pattern,
        metricNamespace: securityMetricNamespace,
        metricName,
        metricValue: '1',
      });
    const addSecurityEventWriterMetrics = (
      idPrefix: string,
      logGroup: logs.ILogGroup,
    ) => {
      addMetricFilter(
        `${idPrefix}SecurityEventStorageFailureMetric`,
        logGroup,
        logs.FilterPattern.allTerms('SECURITY_EVENT_DELIVERY', 'result=failed'),
        'InfrastructureErrors',
      );
      addMetricFilter(
        `${idPrefix}SecurityEventFallbackFailureMetric`,
        logGroup,
        logs.FilterPattern.allTerms('SECURITY_EVENT_FALLBACK', 'result=failed'),
        'InfrastructureErrors',
      );
      addMetricFilter(
        `${idPrefix}SecurityEventFallbackTimeoutMetric`,
        logGroup,
        logs.FilterPattern.allTerms('SECURITY_EVENT_FALLBACK', 'result=timeout'),
        'InfrastructureErrors',
      );
      addMetricFilter(
        `${idPrefix}SecurityEventInvalidMetric`,
        logGroup,
        logs.FilterPattern.allTerms('SECURITY_EVENT_INVALID'),
        'InfrastructureErrors',
      );
    };
    for (const [runtimeName, runtime] of [
      ['AuthFn', fn],
      ['TokenFn', tokenFn],
    ] as const) {
      for (const outcome of ['failure', 'denied']) {
        addMetricFilter(
          `${runtimeName}Authentication${outcome}Metric`,
          runtime.logGroup,
          logs.FilterPattern.allTerms(
            'SECURITY_EVENT',
            'category=authentication',
            `outcome=${outcome}`,
          ),
          'AuthenticationFailures',
        );
      }
      addSecurityEventWriterMetrics(runtimeName, runtime.logGroup);
    }
    addMetricFilter(
      'GovernanceWorkerFailureMetric',
      governanceWorkerLogGroup,
      logs.FilterPattern.allTerms('GOVERNANCE_CHECKPOINT_FAILURE'),
      'InfrastructureErrors',
    );
    addMetricFilter(
      'SecurityEventArchiveFailureMetric',
      securityEventArchiveFn.logGroup,
      logs.FilterPattern.allTerms(
        'SECURITY_EVENT_ARCHIVE',
        'result=dead_letter_pending',
      ),
      'InfrastructureErrors',
    );
    addMetricFilter(
      'SecurityEventArchiveDeadLetterPendingMetric',
      securityEventArchiveFn.logGroup,
      logs.FilterPattern.allTerms(
        'SECURITY_EVENT_ARCHIVE',
        'result=dead_letter_pending',
      ),
      'ArchiveDeadLetters',
    );
    addMetricFilter(
      'SecurityEventArchiveDeadLetterMetric',
      securityEventArchiveFn.logGroup,
      logs.FilterPattern.allTerms(
        'SECURITY_EVENT_ARCHIVE',
        'result=dead_lettered',
      ),
      'ArchiveDeadLetters',
    );
    addMetricFilter(
      'SecurityEventArchiveRedriveFailureMetric',
      securityEventArchiveFn.logGroup,
      logs.FilterPattern.allTerms(
        'SECURITY_EVENT_ARCHIVE',
        'result=redrive_failed',
      ),
      'InfrastructureErrors',
    );
    addMetricFilter(
      'SecurityEventIngressDeadLetterMetric',
      securityEventArchiveFn.logGroup,
      logs.FilterPattern.allTerms(
        'SECURITY_EVENT_INGRESS',
        'result=dead_lettered',
      ),
      'ArchiveDeadLetters',
    );
    addMetricFilter(
      'SecurityEventIngressInvalidMetric',
      securityEventArchiveFn.logGroup,
      logs.FilterPattern.allTerms(
        'SECURITY_EVENT_INGRESS',
        'event_id=unvalidated',
        'result=dead_lettered',
      ),
      'InfrastructureErrors',
    );
    for (const [runtimeName, runtime] of [
      ['AuthFn', fn],
      ['TokenFn', tokenFn],
    ] as const) {
      addMetricFilter(
        `${runtimeName}KmsSigningFailureMetric`,
        runtime.logGroup,
        logs.FilterPattern.anyTerm('KMS_SIGNING_ERROR'),
        'InfrastructureErrors',
      );
    }
    addMetricFilter(
      'SsfDeadLetterMetric',
      ssfDeliveryLogGroup,
      logs.FilterPattern.allTerms(
        'SSF_DELIVERY_FAILURE',
        'result=dead_lettered',
      ),
      'SsfDeliveryFailures',
    );
    addMetricFilter(
      'SsfTerminalMetric',
      ssfDeliveryLogGroup,
      logs.FilterPattern.allTerms(
        'SSF_DELIVERY_FAILURE',
        'result=terminal',
      ),
      'SsfDeliveryFailures',
    );
    addMetricFilter(
      'SsfLostLeaseMetric',
      ssfDeliveryLogGroup,
      logs.FilterPattern.allTerms(
        'SSF_DELIVERY_FAILURE',
        'result=lost_lease',
      ),
      'InfrastructureErrors',
    );
    new logs.MetricFilter(this, 'SsfDeliveryBacklogAgeMetric', {
      logGroup: ssfDeliveryLogGroup,
      filterPattern: logs.FilterPattern.exists('$.ssf_delivery_backlog_age_seconds'),
      metricNamespace: securityMetricNamespace,
      metricName: 'SsfDeliveryBacklogAgeSeconds',
      metricValue: '$.ssf_delivery_backlog_age_seconds',
    });
    for (const [runtimeName, runtime] of [
      ['AuthFn', fn],
      ['TokenFn', tokenFn],
    ] as const) {
      addMetricFilter(
        `${runtimeName}CrossTenantDenialMetric`,
        runtime.logGroup,
        logs.FilterPattern.allTerms(
          'SECURITY_EVENT',
          'category=tenant_boundary',
          'outcome=denied',
        ),
        'CrossTenantDenials',
      );
    }
    const securityMetric = (metricName: string) =>
      new cloudwatch.Metric({
        namespace: securityMetricNamespace,
        metricName,
        statistic: 'Sum',
        period: Duration.minutes(5),
      });
    const alarm = (
      suffix: string,
      metric: cloudwatch.IMetric,
      threshold: number,
    ) =>
      new cloudwatch.Alarm(this, `${suffix}Alarm`, {
        alarmName: `${this.stackName}-${suffix}`,
        metric,
        threshold,
        evaluationPeriods: 1,
        comparisonOperator:
          cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
    alarm('AuthenticationFailures', securityMetric('AuthenticationFailures'), 5);
    const infrastructureErrorMetrics: Record<string, cloudwatch.IMetric> = {
      custom: securityMetric('InfrastructureErrors'),
      auth: fn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      }),
      token: tokenFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      }),
      archive: securityEventArchiveFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      }),
      ssf: ssfDeliveryFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      }),
      governance: governanceWorkerFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      }),
    };
    if (tenantKeyProvisionerFn) {
      infrastructureErrorMetrics.tenantKeys = tenantKeyProvisionerFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      });
    }
    alarm('CrossTenantDenials', securityMetric('CrossTenantDenials'), 1);
    alarm(
      'GovernanceWorkerBacklog',
      governanceWorkerQueue.metricApproximateAgeOfOldestMessage({
        statistic: 'Maximum',
        period: Duration.minutes(5),
      }),
      300,
    );
    alarm(
      'GovernanceWorkerDeadLetters',
      governanceWorkerDlq.metricApproximateNumberOfMessagesVisible({
        statistic: 'Maximum',
        period: Duration.minutes(5),
      }),
      1,
    );
    for (const [name, table] of [
      ['Governance', governanceTable],
      ['GovernanceSuppression', governanceSuppressionTable],
    ] as const) {
      alarm(
        `${name}SystemErrors`,
        new cloudwatch.Metric({
          namespace: 'AWS/DynamoDB',
          metricName: 'SystemErrors',
          statistic: 'Sum',
          period: Duration.minutes(5),
          dimensionsMap: {
            TableName: table.tableName,
            Operation:
              name === 'Governance' ? 'TransactWriteItems' : 'PutItem',
          },
        }),
        1,
      );
      for (const replicaRegion of tenantKeyReplicaRegions) {
        alarm(
          `${name}ReplicationLatency${replicaRegion.replace(/-/g, '')}`,
          new cloudwatch.Metric({
            namespace: 'AWS/DynamoDB',
            metricName: 'ReplicationLatency',
            statistic: 'Maximum',
            period: Duration.minutes(5),
            dimensionsMap: {
              TableName: table.tableName,
              ReceivingRegion: replicaRegion,
            },
          }),
          60_000,
        );
      }
    }
    alarm(
      'SsfDeliveryFailures',
      new cloudwatch.MathExpression({
        expression: 'attempts + sourceReplayDeadLetters',
        usingMetrics: {
          attempts: securityMetric('SsfDeliveryFailures'),
          sourceReplayDeadLetters:
            ssfStreamFailureReplayDlq.metricApproximateNumberOfMessagesVisible({
              statistic: 'Maximum',
              period: Duration.minutes(5),
            }),
        },
        period: Duration.minutes(5),
      }),
      1,
    );
    alarm(
      'SsfDeliveryBacklog',
      new cloudwatch.MathExpression({
        expression: 'MAX([stream / 1000, due, sourceReplay])',
        usingMetrics: {
          stream: ssfDeliveryFn.metric('IteratorAge', {
            statistic: 'Maximum',
            period: Duration.minutes(5),
          }),
          due: securityMetric('SsfDeliveryBacklogAgeSeconds'),
          sourceReplay:
            ssfStreamFailureReplayQueue.metricApproximateAgeOfOldestMessage({
              statistic: 'Maximum',
              period: Duration.minutes(5),
            }),
        },
        period: Duration.minutes(5),
      }),
      60,
    );
    if (tenantKeyOperationsQueue && tenantKeyOperationsDlq) {
      alarm(
        'TenantKeyOperationsBacklog',
        tenantKeyOperationsQueue.metricApproximateAgeOfOldestMessage({
          statistic: 'Maximum',
          period: Duration.minutes(5),
        }),
        60,
      );
      alarm(
        'TenantKeyOperationsDeadLetters',
        tenantKeyOperationsDlq.metricApproximateNumberOfMessagesVisible({
          statistic: 'Maximum',
          period: Duration.minutes(5),
        }),
        1,
      );
    }
    alarm(
      'ArchiveBacklog',
      new cloudwatch.MathExpression({
        expression: 'MAX([stream, ingress * 1000, failureNotifications * 1000])',
        usingMetrics: {
          stream: securityEventArchiveFn.metric('IteratorAge', {
            statistic: 'Maximum',
            period: Duration.minutes(5),
          }),
          ingress: securityEventIngressQueue.metricApproximateAgeOfOldestMessage({
            statistic: 'Maximum',
            period: Duration.minutes(5),
          }),
          failureNotifications:
            securityEventStreamFailureNotificationQueue.metricApproximateAgeOfOldestMessage({
              statistic: 'Maximum',
              period: Duration.minutes(5),
            }),
        },
        period: Duration.minutes(5),
      }),
      60_000,
    );
    alarm(
      'ArchiveDeadLetters',
      new cloudwatch.MathExpression({
        expression: 'transitions + archive + ingress + failureNotifications',
        usingMetrics: {
          transitions: securityMetric('ArchiveDeadLetters'),
          archive: securityEventArchiveDlq.metricApproximateNumberOfMessagesVisible({
            statistic: 'Maximum',
            period: Duration.minutes(5),
          }),
          ingress: securityEventIngressDlq.metricApproximateNumberOfMessagesVisible({
            statistic: 'Maximum',
            period: Duration.minutes(5),
          }),
          failureNotifications:
            securityEventStreamFailureNotificationDlq.metricApproximateNumberOfMessagesVisible({
              statistic: 'Maximum',
              period: Duration.minutes(5),
            }),
        },
        period: Duration.minutes(5),
      }),
      1,
    );

    // === client/DCR 凭据迁移 handler(由独立 post-deploy 栈触发)===
    // 不可逆迁移不能作为本业务栈的 Custom Resource：若同一 stack update 后续失败并回滚到
    // 不认识 verifier schema 的旧 Auth Lambda，已删除的 plaintext 无法恢复。这里仅部署 handler；
    // CredentialMigrationStack 在本栈 UPDATE_COMPLETE 后单独部署和触发。
    if (props.credentialMigrationAssetPath) {
      const credentialMigrationFn = new lambda.Function(this, 'CredentialMigrationFn', {
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        code: lambda.Code.fromAsset(props.credentialMigrationAssetPath),
        memorySize: 256,
        timeout: Duration.minutes(15),
        environment: {
          CREDENTIAL_MIGRATION_MODE: 'client',
          CLIENTS_TABLE: clientsTable.tableName,
          SERVER_SECRET: serverSecret.secretValue.unsafeUnwrap(),
        },
      });
      clientsTable.grantReadWriteData(credentialMigrationFn);
      this.credentialMigrationHandler = credentialMigrationFn;
      new CfnOutput(this, 'CredentialMigrationFnName', {
        value: credentialMigrationFn.functionName,
      });
      NagSuppressions.addResourceSuppressions(
        credentialMigrationFn,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              '部署期迁移 Lambda 基本执行角色仅用于 CloudWatch Logs；业务权限限定为本栈 Clients 表读写。',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason:
              'Clients 表级/index 通配由 grantReadWriteData 生成，资源限定为本栈单表；迁移需扫描并条件更新历史行。',
          },
        ],
        true,
      );
    }

    const authorityReferenceMigrationFn = new lambda.Function(
      this,
      'AuthorityReferenceMigrationFn',
      {
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        code: lambda.Code.fromAsset(props.credentialMigrationAssetPath),
        memorySize: 256,
        timeout: Duration.minutes(15),
        environment: {
          CREDENTIAL_MIGRATION_MODE: 'authority_refs',
          CODES_TABLE: codesTable.tableName,
          REFRESH_TABLE: refreshTable.tableName,
          AUTH_REFS_TABLE: clientAuthorityRefsTable.tableName,
          AGENT_AUTH_DEPLOYMENT_COMMIT: props.deploymentCommit,
        },
      },
    );
    codesTable.grantReadWriteData(authorityReferenceMigrationFn);
    refreshTable.grantReadWriteData(authorityReferenceMigrationFn);
    clientAuthorityRefsTable.grantReadWriteData(
      authorityReferenceMigrationFn,
    );
    const authorityReferenceMigrationControlPlanePolicy = new iam.Policy(
      this,
      'AuthorityReferenceMigrationControlPlanePolicy',
      {
        statements: [
          new iam.PolicyStatement({
            actions: ['lambda:GetFunctionConfiguration'],
            resources: [authorityReferenceMigrationFn.functionArn],
          }),
        ],
      },
    );
    authorityReferenceMigrationControlPlanePolicy.attachToRole(
      authorityReferenceMigrationFn.role!,
    );
    authorityReferenceMigrationFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:TransactWriteItems'],
        resources: [
          codesTable.tableArn,
          refreshTable.tableArn,
          clientAuthorityRefsTable.tableArn,
        ],
      }),
    );
    this.authorityReferenceMigrationHandler =
      authorityReferenceMigrationFn;
    new CfnOutput(this, 'AuthorityReferenceMigrationFnName', {
      value: authorityReferenceMigrationFn.functionName,
    });
    NagSuppressions.addResourceSuppressions(
      authorityReferenceMigrationFn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'Post-deploy authority-reference migration uses the Lambda basic role only for CloudWatch Logs.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Migration scans the two Region-local source tables and transactionally writes their dedicated reference table; every grant is table-scoped.',
        },
      ],
      true,
    );

    // === client 回收后台任务 Lambda + EventBridge Schedule(spec 005 §9.5,C10.5)===
    // 独立函数(触发源 = EventBridge Schedule,非 API Gateway):跑 run_reclaim_pass —— 扫 last_used_day-index
    // 旧 client → 强一致聚合信号 → tombstone / 硬删+审计。**默认 dry-run**(AGENT_AUTH_RECLAIM_ENABLED 未设 →
    // 只扫描报数不处置,fail-safe 防误配调度删 client);启用须显式设 =1。仅当提供 reclaimAssetPath 才部署。
    if (props.reclaimAssetPath) {
      const reclaimLogGroup = new logs.LogGroup(this, 'ReclaimFnLogGroup', {
        retention: logs.RetentionDays.SEVEN_YEARS,
        removalPolicy: RemovalPolicy.RETAIN,
      });
      const reclaimFn = new lambda.Function(this, 'ReclaimFn', {
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        code: lambda.Code.fromAsset(props.reclaimAssetPath),
        memorySize: 256,
        timeout: Duration.seconds(300), // 扫描 + 逐候选处置,给足;实际低频
        logGroup: reclaimLogGroup,
        environment: {
          ...(!props.saasZone ? { AGENT_AUTH_HOST: runtimeIssuerHost } : {}),
          ...regionFenceEnvironment,
          WEB_BASE_URL: webBaseUrl,
          // 回收任务需读/写的表:Clients(扫描+tombstone+硬删)+ Refresh/Codes(信号只读)。
          CLIENTS_TABLE: clientsTable.tableName,
          INITIAL_ACCESS_TOKENS_TABLE: initialAccessTokensTable.tableName,
          REFRESH_TABLE: refreshTable.tableName,
          CODES_TABLE: codesTable.tableName,
          AUTH_REFS_TABLE: clientAuthorityRefsTable.tableName,
          // from_env_aws 要求的其余表(构造 AppState 需全量;回收任务不实际用签发/会话表,但构造须齐)。
          SESSIONS_TABLE: sessionsTable.tableName,
          MAGICLINK_TABLE: magicLinkTable.tableName,
          INVITATIONS_TABLE: invitationsTable.tableName,
          RECOVERY_TABLE: recoveryTable.tableName,
          AUTHZ_SESSIONS_TABLE: authzSessionsTable.tableName,
          MESSAGES_TABLE: messagesTable.tableName,
          SECURITY_EVENTS_TABLE: securityEventsTable.tableName,
          SSF_DELIVERIES_TABLE: ssfDeliveriesTable.tableName,
          SECURITY_EVENT_INGRESS_QUEUE_URL: securityEventIngressQueue.queueUrl,
          WORKLOAD_TRUST_TABLE: workloadTrustTable.tableName,
          CIBA_TABLE: cibaTable.tableName,
          DEVICE_TABLE: deviceTable.tableName,
          GRANTS_TABLE: grantsTable.tableName,
          FEDERATION_CONFIG_TABLE: federationConfigTable.tableName,
          FEDERATION_FLOW_TABLE: federationFlowTable.tableName,
          ADMIN_AUTH_TABLE: adminAuthTable.tableName,
          ADMIN_AUTH_RUNTIME_TABLE: adminAuthRuntimeTable.tableName,
          GOVERNANCE_TABLE: governanceTable.tableName,
          GOVERNANCE_SUPPRESSION_TABLE: governanceSuppressionTable.tableName,
          GOVERNANCE_QUEUE_URL: governanceWorkerQueue.queueUrl,
          USERS_TABLE: usersTable.tableName,
          SCIM_GROUPS_TABLE: scimGroupsTable.tableName,
          PASSWORD_CREDENTIALS_TABLE: passwordCredentialsTable.tableName,
          RATE_LIMIT_TABLE: rateLimitTable.tableName,
          PASSKEY_TABLE: passkeyTable.tableName,
          PASSKEY_CHALLENGE_TABLE: passkeyChallengeTable.tableName,
          JTI_TABLE: jtiTable.tableName,
          GRACE_TABLE: graceTable.tableName,
          CIBA_KMS: cibaNotificationKeyAlias,
          SIGNING_KEY_ID: activeEcSigningKeyId,
          SIGNING_KEY_IDS_PUBLISHED: publishedEcSigningKeyIds,
          RSA_SIGNING_KEY_ID: idTokenSigningKey.keyId,
          SERVER_SECRET: serverSecret.secretValue.unsafeUnwrap(),
          ...assurancePolicyEnvironment,
          ...runtimeBootstrapEnvironment,
          ...deploymentFormEnvironment,
          ...tenantKeyRuntimeEnvironment,
          AGENT_AUTH_PHASE: props.phase ?? 'p2',
          // 回收策略(缺省保守:闲置 90 天、tombstone 猶予 1 天 ≥ access TTL);默认 **dry-run**(不设 ENABLED)。
          RECLAIM_IDLE_DAYS: '90',
          RECLAIM_MAX_ACCESS_TTL_SECS: '86400',
        },
      });
      runtimeBootstrapConfigSecret.grantRead(reclaimFn);
      governanceHmacSecret.grantRead(reclaimFn);
      // 最小 IAM:Clients 读写(扫描/tombstone/硬删+审计 TransactWriteItems 需 GSI)+ Refresh/Codes 读(信号)。
      clientsTable.grantReadWriteData(reclaimFn);
      initialAccessTokensTable.grantReadData(reclaimFn);
      refreshTable.grantReadData(reclaimFn);
      codesTable.grantReadData(reclaimFn);
      clientAuthorityRefsTable.grantReadData(reclaimFn);
      // from_env_aws 构造 AppState 会连其余表/KMS;授只读兜底(回收任务不签名,但构造期不报错)。
      // 注:回收任务实际只动 Clients/Refresh/Codes;其余授权最小化到"构造 AppState 不失败"。
      sessionsTable.grantReadData(reclaimFn);
      graceTable.grantReadData(reclaimFn);
      governanceTable.grantReadWriteData(reclaimFn);
      reclaimFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactWriteItems'],
          resources: [governanceTable.tableArn],
        }),
      );
      grantRegionControlRead(reclaimFn);
      grantSecurityEventDelivery(reclaimFn);
      addSecurityEventWriterMetrics('ReclaimFn', reclaimLogGroup);
      infrastructureErrorMetrics.reclaim = reclaimFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      });
      reclaimFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:GetPublicKey'],
          resources: [...publishedEcSigningKeyArns, idTokenSigningKey.keyArn],
        }),
      );
      // EventBridge Schedule:每天跑一次(回收是低频维护;真启用前默认 dry-run)。
      const reclaimRule = new events.Rule(this, 'ReclaimSchedule', {
        schedule: events.Schedule.rate(Duration.days(1)),
        description: 'agent-auth client 回收扫描(spec 005 §9.5;默认 dry-run)',
      });
      reclaimRule.addTarget(new targets.LambdaFunction(reclaimFn));
      new CfnOutput(this, 'ReclaimFnName', { value: reclaimFn.functionName });
      // cdk-nag 抑制(同主 AuthFn 口径):IAM4 = Lambda 基本执行角色(CloudWatch Logs 最小托管策略);
      // IAM5 = grantReadWriteData/grantReadData 的表级+index 通配是 DynamoDB 单表访问所需(限定本表 ARN+其 index),非跨资源通配。
      NagSuppressions.addResourceSuppressions(
        reclaimFn,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              '回收任务 Lambda 基本执行角色(AWSLambdaBasicExecutionRole)是 CloudWatch Logs 写入所需最小托管策略;业务权限已最小化(Clients 读写 + Refresh/Codes 只读 + security-event 条件写/fallback + 两 signing key GetPublicKey)。',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason:
              'grantReadWriteData/grantReadData 生成的表级/索引通配是 DynamoDB 单表访问所需(限定到本表 ARN + 其 index,含回收扫描依赖的 last_used_day-index / client_id-index);非跨资源通配。',
          },
        ],
        true,
      );
    }

    // === 策略重算后台任务 Lambda + EventBridge Schedule(spec 005 §7,C10.17)===
    // 独立函数(触发源 = EventBridge Schedule,非 API Gateway):跑 run_recompute_pass —— GSI Query stale
    // Grant(effective_pv < current_pv)→ Cedar 重算 evaluate(授权,当前策略)→ 写 effective / 吊销(CAS)。
    // **默认 dry-run**(AGENT_AUTH_RECOMPUTE_ENABLED 未设 → 只扫描报数,fail-safe 防误配批量改 Grant);
    // 启用须显式设 =1。仅当提供 recomputeAssetPath 才部署。策略集/AUTHZ 开关经 env(与主 Lambda 同源)。
    if (props.recomputeAssetPath) {
      const recomputeLogGroup = new logs.LogGroup(this, 'RecomputeFnLogGroup', {
        retention: logs.RetentionDays.SEVEN_YEARS,
        removalPolicy: RemovalPolicy.RETAIN,
      });
      const recomputeFn = new lambda.Function(this, 'RecomputeFn', {
        runtime: lambda.Runtime.PROVIDED_AL2023,
        architecture: lambda.Architecture.ARM_64,
        handler: 'bootstrap',
        code: lambda.Code.fromAsset(props.recomputeAssetPath),
        memorySize: 256,
        timeout: Duration.seconds(300),
        logGroup: recomputeLogGroup,
        environment: {
          ...(!props.saasZone ? { AGENT_AUTH_HOST: runtimeIssuerHost } : {}),
          ...regionFenceEnvironment,
          WEB_BASE_URL: webBaseUrl,
          // from_env_aws 构造 AppState 需全量表(重算实际只动 Grants + policy_version/工件[同 GRANTS_TABLE])。
          CLIENTS_TABLE: clientsTable.tableName,
          INITIAL_ACCESS_TOKENS_TABLE: initialAccessTokensTable.tableName,
          REFRESH_TABLE: refreshTable.tableName,
          CODES_TABLE: codesTable.tableName,
          AUTH_REFS_TABLE: clientAuthorityRefsTable.tableName,
          SESSIONS_TABLE: sessionsTable.tableName,
          MAGICLINK_TABLE: magicLinkTable.tableName,
          INVITATIONS_TABLE: invitationsTable.tableName,
          RECOVERY_TABLE: recoveryTable.tableName,
          AUTHZ_SESSIONS_TABLE: authzSessionsTable.tableName,
          MESSAGES_TABLE: messagesTable.tableName,
          SECURITY_EVENTS_TABLE: securityEventsTable.tableName,
          SSF_DELIVERIES_TABLE: ssfDeliveriesTable.tableName,
          SECURITY_EVENT_INGRESS_QUEUE_URL: securityEventIngressQueue.queueUrl,
          WORKLOAD_TRUST_TABLE: workloadTrustTable.tableName,
          CIBA_TABLE: cibaTable.tableName,
          DEVICE_TABLE: deviceTable.tableName,
          GRANTS_TABLE: grantsTable.tableName,
          FEDERATION_CONFIG_TABLE: federationConfigTable.tableName,
          FEDERATION_FLOW_TABLE: federationFlowTable.tableName,
          ADMIN_AUTH_TABLE: adminAuthTable.tableName,
          ADMIN_AUTH_RUNTIME_TABLE: adminAuthRuntimeTable.tableName,
          GOVERNANCE_TABLE: governanceTable.tableName,
          GOVERNANCE_SUPPRESSION_TABLE: governanceSuppressionTable.tableName,
          GOVERNANCE_QUEUE_URL: governanceWorkerQueue.queueUrl,
          USERS_TABLE: usersTable.tableName,
          SCIM_GROUPS_TABLE: scimGroupsTable.tableName,
          PASSWORD_CREDENTIALS_TABLE: passwordCredentialsTable.tableName,
          RATE_LIMIT_TABLE: rateLimitTable.tableName,
          PASSKEY_TABLE: passkeyTable.tableName,
          PASSKEY_CHALLENGE_TABLE: passkeyChallengeTable.tableName,
          JTI_TABLE: jtiTable.tableName,
          GRACE_TABLE: graceTable.tableName,
          CIBA_KMS: cibaNotificationKeyAlias,
          SIGNING_KEY_ID: activeEcSigningKeyId,
          SIGNING_KEY_IDS_PUBLISHED: publishedEcSigningKeyIds,
          RSA_SIGNING_KEY_ID: idTokenSigningKey.keyId,
          SERVER_SECRET: serverSecret.secretValue.unsafeUnwrap(),
          ...assurancePolicyEnvironment,
          ...runtimeBootstrapEnvironment,
          ...deploymentFormEnvironment,
          ...tenantKeyRuntimeEnvironment,
          AGENT_AUTH_PHASE: props.phase ?? 'p2',
          // authz + 策略集(重算须 evaluate,故 AUTHZ_ENABLED/POLICY_SET 与主 Lambda 同源注入)。
          ...(props.authzEnabled ? { AGENT_AUTH_AUTHZ_ENABLED: '1' } : {}),
          ...(props.policySet ? { AGENT_AUTH_POLICY_SET: props.policySet } : {}),
          // **启用脚枪防呆(评审 H3)**:authzEnabled 时,RecomputeFn 必须 ENABLED=1 —— 否则 publish 会 bump
          // current_pv(挂 AUTHZ_ENABLED),但常规 stale 处置是 dry-run,存量 Grant 永不追平 → 热路径全 503。
          // publish 本身已在 bin 内跟 seed backfill(与 dry-run 解耦)追平存量;此处再开常规处置保证后续 bump
          // 也被消费。**注**:授权关(默认)时**不设**此值 → RecomputeFn 恒 dry-run(现网零风险)。
          ...(props.authzEnabled ? { AGENT_AUTH_RECOMPUTE_ENABLED: '1' } : {}),
          // SaaS 必须逐已配置 tenant 收敛；自部署缺省 = 仅空 tenant。
          ...(props.saasZone
            ? { AGENT_AUTH_RECOMPUTE_TENANTS: saasTenantIds.join(',') }
            : {}),
        },
      });
      runtimeBootstrapConfigSecret.grantRead(recomputeFn);
      governanceHmacSecret.grantRead(recomputeFn);
      // 最小 IAM:Grants 表读写(扫 stale + 写 effective/吊销 + policy_version/工件同表);其余只读兜底构造。
      grantsTable.grantReadWriteData(recomputeFn);
      clientsTable.grantReadData(recomputeFn);
      initialAccessTokensTable.grantReadData(recomputeFn);
      refreshTable.grantReadData(recomputeFn);
      sessionsTable.grantReadData(recomputeFn);
      graceTable.grantReadData(recomputeFn);
      governanceTable.grantReadWriteData(recomputeFn);
      recomputeFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactWriteItems'],
          resources: [governanceTable.tableArn],
        }),
      );
      grantRegionControlRead(recomputeFn);
      grantSecurityEventDelivery(recomputeFn);
      addSecurityEventWriterMetrics('RecomputeFn', recomputeLogGroup);
      infrastructureErrorMetrics.recompute = recomputeFn.metricErrors({
        statistic: 'Sum',
        period: Duration.minutes(5),
      });
      recomputeFn.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:GetPublicKey'],
          resources: [...publishedEcSigningKeyArns, idTokenSigningKey.keyArn],
        }),
      );
      // EventBridge Schedule:每小时跑一次兜底(有界收敛;bump 即触发另经管理面接线,best-effort)。
      const recomputeRule = new events.Rule(this, 'RecomputeSchedule', {
        schedule: events.Schedule.rate(Duration.hours(1)),
        description: 'agent-auth 策略重算扫描(spec 005 §7;默认 dry-run)',
      });
      recomputeRule.addTarget(new targets.LambdaFunction(recomputeFn));
      new CfnOutput(this, 'RecomputeFnName', { value: recomputeFn.functionName });
      NagSuppressions.addResourceSuppressions(
        recomputeFn,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              '重算任务 Lambda 基本执行角色(AWSLambdaBasicExecutionRole)是 CloudWatch Logs 写入所需最小托管策略;业务权限已最小化(Grants 读写 + 其余只读兜底 + security-event 条件写/fallback + 两 signing key GetPublicKey)。',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason:
              'grantReadWriteData/grantReadData 生成的表级/索引通配是 DynamoDB 单表访问所需(限定本表 ARN + 其 index,含重算依赖的 policy_version-index);非跨资源通配。',
          },
        ],
        true,
      );
    }

    alarm(
      'InfrastructureErrors',
      new cloudwatch.MathExpression({
        expression: Object.keys(infrastructureErrorMetrics).join(' + '),
        usingMetrics: infrastructureErrorMetrics,
        period: Duration.minutes(5),
      }),
      1,
    );

    // `/token` 精确路由到专用 role;其余路径留在 non-token AuthFn。
    const integration = new HttpLambdaIntegration('NonTokenIntegration', fn);
    const tokenIntegration = new HttpLambdaIntegration(
      'TokenIntegration',
      tokenFn,
    );
    const tokenRoutes = httpApi.addRoutes({
      path: '/token',
      methods: [apigw.HttpMethod.POST, apigw.HttpMethod.OPTIONS],
      integration: tokenIntegration,
    });
    const proxyRoutes = httpApi.addRoutes({
      path: '/{proxy+}',
      methods: [apigw.HttpMethod.ANY],
      integration,
    });
    for (const proxyRoute of proxyRoutes) {
      for (const tokenRoute of tokenRoutes) {
        const proxyResource = proxyRoute.node.defaultChild as apigw.CfnRoute;
        const tokenResource = tokenRoute.node.defaultChild as apigw.CfnRoute;
        proxyResource.addDependency(tokenResource);
      }
    }

    // access logging(AwsSolutions-APIG1):默认 stage + 访问日志到 CloudWatch。
    const accessLogs = new logs.LogGroup(this, 'ApiAccessLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const stage = new apigw.HttpStage(this, 'DefaultStage', {
      httpApi,
      stageName: '$default',
      autoDeploy: true,
    });
    // HTTP API access log 经 L1 escape hatch 配置(L2 尚未直接暴露)。
    const cfnStage = stage.node.defaultChild as apigw.CfnStage;
    cfnStage.accessLogSettings = {
      destinationArn: accessLogs.logGroupArn,
      format: JSON.stringify({
        requestId: '$context.requestId',
        ip: '$context.identity.sourceIp',
        method: '$context.httpMethod',
        path: '$context.path',
        status: '$context.status',
        protocol: '$context.protocol',
        responseLength: '$context.responseLength',
      }),
    };

    // === X.509-SVID / mTLS 独立自定义域名(spec 012 §1.4 / C5.7,P3)===
    // 绕过 CloudFront(它不转发客户端证书),直连 API Gateway 连接级双向 TLS。**仅 SelfHosted**(评审 B1)。
    // 该域名映射到**同一 HttpApi/$default**(与 CloudFront 经 execute-api 回源共享;MUST NOT 关 execute-api,
    // 评审 H3);mTLS 只在此域名 TLS 层强制,Lambda 侧 X.509 身份仅当 requestContext.authentication.clientCert
    // 存在才激活(evaluate-api 路径恒空 → 不误触)。truststore=S3 桶存签发 SVID 的 CA bundle(运维 onboarding 上传)。
    if (
      mtlsSvidDeploymentEnabled &&
      props.mtlsDomain &&
      props.mtlsCertArn &&
      props.mtlsZoneId &&
      props.mtlsZoneName &&
      !props.saasZone // 仅 SelfHosted(B1)
    ) {
      // truststore 桶:版本化(轮换 CA 靠上传新版本 + 域名指向新 version)+ 加密 + 强制 SSL + 全私有。
      const truststore = new s3.Bucket(this, 'MtlsTruststore', {
        versioned: true,
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        encryption: s3.BucketEncryption.S3_MANAGED,
        enforceSSL: true,
        removalPolicy: RemovalPolicy.DESTROY,
        autoDeleteObjects: true,
      });
      const mtlsCert = acm.Certificate.fromCertificateArn(this, 'MtlsCert', props.mtlsCertArn);
      // **truststore 必须在 DomainName 创建前就有 `truststore.pem`**(评审 H1:API Gateway CreateDomainName 会
      // 校验该 S3 对象存在,空桶 → CREATE_FAILED 回滚,"运维事后上传"永不可达)。故 deploy 期用 BucketDeployment
      // 播种一份**占位 CA**(assets/mtls-truststore/truststore.pem,自签根,仅让 CreateDomainName 通过);运维/e2e
      // onboarding 时上传**真 CA bundle** 覆盖同 key(版本化桶,轮换 = 新版本)。DomainName 依赖 seed 完成。
      const truststoreSeed = new s3deploy.BucketDeployment(this, 'MtlsTruststoreSeed', {
        sources: [s3deploy.Source.asset(resolveMtlsTruststoreAssetPath())],
        destinationBucket: truststore,
        prune: false, // 不删运维上传的真 CA(仅确保占位存在)
      });
      // API Gateway v2 自定义域名 + mTLS(truststore key 约定 `truststore.pem`)。
      const mtlsDn = new apigw.DomainName(this, 'MtlsDomainName', {
        domainName: props.mtlsDomain,
        certificate: mtlsCert,
        mtls: { bucket: truststore, key: 'truststore.pem' },
      });
      mtlsDn.node.addDependency(truststoreSeed); // 确保 truststore.pem 已存在再建 DomainName(H1)
      // 映射到同一 HttpApi 的 $default stage(不经 CloudFront)。
      new apigw.ApiMapping(this, 'MtlsApiMapping', {
        api: httpApi,
        domainName: mtlsDn,
        stage,
      });
      // Route53 A/AAAA alias → 该 regional 自定义域名。
      const mtlsZone = route53.HostedZone.fromHostedZoneAttributes(this, 'MtlsZone', {
        hostedZoneId: props.mtlsZoneId,
        zoneName: props.mtlsZoneName,
      });
      const mtlsTarget = route53.RecordTarget.fromAlias(
        new route53targets.ApiGatewayv2DomainProperties(
          mtlsDn.regionalDomainName,
          mtlsDn.regionalHostedZoneId,
        ),
      );
      new route53.ARecord(this, 'MtlsDomainA', {
        zone: mtlsZone,
        recordName: props.mtlsDomain,
        target: mtlsTarget,
      });
      new route53.AaaaRecord(this, 'MtlsDomainAAAA', {
        zone: mtlsZone,
        recordName: props.mtlsDomain,
        target: mtlsTarget,
      });
      new CfnOutput(this, 'MtlsDomainUrl', { value: `https://${props.mtlsDomain}` });
      new CfnOutput(this, 'MtlsTruststoreBucket', { value: truststore.bucketName });
      // cdk-nag:truststore 桶已加密/私有/强制 SSL/版本化;server access log 非必需(内部 CA bundle,无对象级读审计需求)。
      NagSuppressions.addResourceSuppressions(truststore, [
        {
          id: 'AwsSolutions-S1',
          reason: 'mTLS truststore 桶存 CA bundle,仅 API Gateway 服务读取;桶私有 + 加密 + 强制 SSL + 版本化,server access log 非必需。',
        },
      ]);
      // CDK 框架托管的 BucketDeployment(播种 truststore.pem)Lambda 角色对**目标桶**有 s3 通配(拷贝所需)——
      // 与 SPA 桶同一 singleton 部署角色(frontend-construct 已抑该路径,但 appliesTo 未含 truststore ARN)。
      // 追加本桶 ARN 的 IAM5 抑制(限于该桶,非跨资源;框架实现,非业务角色)。
      const truststoreLogicalId = this.getLogicalId(
        truststore.node.defaultChild as CfnElement,
      );
      NagSuppressions.addResourceSuppressionsByPath(
        this,
        `${this.stackName}/Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C/ServiceRole/DefaultPolicy/Resource`,
        [
          {
            id: 'AwsSolutions-IAM5',
            reason: 'CDK BucketDeployment 播种 truststore.pem 到本 mTLS truststore 桶所需的 s3 读写通配(框架托管部署角色,限于该桶前缀)。',
            appliesTo: [
              'Action::s3:GetBucket*',
              'Action::s3:GetObject*',
              'Action::s3:List*',
              'Action::s3:Abort*',
              'Action::s3:DeleteObject*',
              `Resource::<${truststoreLogicalId}.Arn>/*`,
            ],
          },
        ],
        true,
      );
    }

    // === 前端 SPA 托管 + CloudFront 统一入口(spec 025)===
    // 统一入口:default→API Gateway、静态→S3,同域(cookie/CSRF 天然正确 + 修复分域登录)。
    // apiDomain = httpApi.apiEndpoint 去掉 scheme(HttpOrigin 只要 host)。
    let frontend: FrontendConstruct | undefined;
    if (props.deployFrontend !== false) {
      const apiDomain = Fn.select(1, Fn.split('://', httpApi.apiEndpoint));
      // BYOD 演示别名(spec 010 §5.4 / C8.1b):把 byodDemoDomain 并入 CloudFront 别名集,使其 CNAME 到
      // 同一 distribution → default→API → well-known PRM handler(ForwardHost 已把 viewer Host 透传)。
      // 复用现有 *.<zone> 通配证书(无新证书);Route53 为它建 A/AAAA alias。合并去重,保持既有单/多域行为。
      const baseDomains =
        props.customDomains && props.customDomains.length > 0
          ? props.customDomains
          : props.customDomain
            ? [props.customDomain]
            : [];
      const mergedDomains = props.byodDemoDomain
        ? Array.from(new Set([...baseDomains, props.byodDemoDomain]))
        : baseDomains;
      frontend = new FrontendConstruct(this, 'Frontend', {
        assetPath: props.frontendAssetPath,
        apiDomain,
        registrationWaf: props.registrationWafEnabled
          ? { deploymentCommit: props.deploymentCommit }
          : undefined,
        apiOriginAuth:
          cloudFrontOriginSecret && cloudFrontOriginSecondarySecret
            ? {
                primarySecret: cloudFrontOriginSecret,
                secondarySecret: cloudFrontOriginSecondarySecret,
                revision: saasOriginAuthRevision,
              }
            : undefined,
        // 自定义域名(联邦真机 redirect_uri 需稳定 host):三者齐备才挂别名+alias。
        // SaaS:customDomains 列全部子域(t1/t2/c.<zone>),回落单个 customDomain;BYOD 演示域名已并入。
        customDomain: props.customDomain,
        customDomains: mergedDomains.length > 0 ? mergedDomains : undefined,
        certArn: props.certArn,
        hostedZoneId: props.hostedZoneId,
        hostedZoneName: props.hostedZoneName,
      });
    }

    new CfnOutput(this, 'ApiUrl', { value: httpApi.apiEndpoint });
    new CfnOutput(this, 'AuthFnName', { value: fn.functionName });
    new CfnOutput(this, 'TokenFnName', { value: tokenFn.functionName });
    if (props.deploymentCommit) {
      new CfnOutput(this, 'DeploymentCommit', { value: props.deploymentCommit });
    }
    if (frontend?.registrationWebAclArn) {
      new CfnOutput(this, 'RegistrationWebAclArn', {
        value: frontend.registrationWebAclArn,
      });
    }
    if (frontend) {
      new CfnOutput(this, 'FrontendDistributionId', {
        value: frontend.distributionId,
      });
    }
    if (frontend?.registrationWafLogGroupName) {
      new CfnOutput(this, 'RegistrationWafLogGroupName', {
        value: frontend.registrationWafLogGroupName,
      });
    }
    new CfnOutput(this, 'SigningKeyId', { value: activeEcSigningKeyId });
    new CfnOutput(this, 'ManagedSigningKeyId', { value: signingKey.keyId });
    new CfnOutput(this, 'IdTokenSigningKeyId', { value: idTokenSigningKey.keyId });
    new CfnOutput(this, 'CodesTableName', { value: codesTable.tableName });
    new CfnOutput(this, 'ClientsTableName', { value: clientsTable.tableName });
    new CfnOutput(this, 'InitialAccessTokensTableName', {
      value: initialAccessTokensTable.tableName,
    });
    new CfnOutput(this, 'RefreshTableName', { value: refreshTable.tableName });
    new CfnOutput(this, 'ClientAuthorityRefsTableName', {
      value: clientAuthorityRefsTable.tableName,
    });
    new CfnOutput(this, 'SessionsTableName', { value: sessionsTable.tableName });
    new CfnOutput(this, 'MagicLinkTableName', { value: magicLinkTable.tableName });
    new CfnOutput(this, 'InvitationsTableName', { value: invitationsTable.tableName });
    new CfnOutput(this, 'RecoveryTableName', { value: recoveryTable.tableName });
    new CfnOutput(this, 'AuthzSessionsTableName', { value: authzSessionsTable.tableName });
    new CfnOutput(this, 'AuthzAuditLogName', { value: authzAuditLog.logGroupName });
    new CfnOutput(this, 'AuthzEventBusName', { value: authzEventBus.eventBusName });
    new CfnOutput(this, 'MessagesTableName', { value: messagesTable.tableName });
    new CfnOutput(this, 'SecurityEventsTableName', {
      value: securityEventsTable.tableName,
    });
    new CfnOutput(this, 'SsfDeliveriesTableName', {
      value: ssfDeliveriesTable.tableName,
    });
    new CfnOutput(this, 'SsfDeliveryFnName', {
      value: ssfDeliveryFn.functionName,
    });
    new CfnOutput(this, 'SsfDeliveryScheduleName', {
      value: ssfDeliveryRule.ruleName,
    });
    new CfnOutput(this, 'SsfStreamFailureBucketName', {
      value: ssfStreamFailureBucket.bucketName,
    });
    new CfnOutput(this, 'SsfStreamFailureReplayQueueUrl', {
      value: ssfStreamFailureReplayQueue.queueUrl,
    });
    new CfnOutput(this, 'SsfStreamFailureReplayDlqUrl', {
      value: ssfStreamFailureReplayDlq.queueUrl,
    });
    if (
      tenantKeysTable &&
      tenantKeyOperationsQueue &&
      tenantKeyOperationsDlq &&
      tenantKeyProvisionerFn &&
      tenantKeyReconcileRule
    ) {
      new CfnOutput(this, 'TenantKeysTableName', {
        value: tenantKeysTable.tableName,
      });
      new CfnOutput(this, 'TenantKeyOperationsQueueUrl', {
        value: tenantKeyOperationsQueue.queueUrl,
      });
      new CfnOutput(this, 'TenantKeyOperationsDlqUrl', {
        value: tenantKeyOperationsDlq.queueUrl,
      });
      new CfnOutput(this, 'TenantKeyProvisionerFnName', {
        value: tenantKeyProvisionerFn.functionName,
      });
      new CfnOutput(this, 'TenantKeyReconcileScheduleName', {
        value: tenantKeyReconcileRule.ruleName,
      });
    }
    new CfnOutput(this, 'SecurityEventArchiveBucketName', {
      value: securityEventArchiveBucket.bucketName,
    });
    new CfnOutput(this, 'SecurityEventArchiveDlqUrl', {
      value: securityEventArchiveDlq.queueUrl,
    });
    new CfnOutput(this, 'SecurityEventIngressQueueUrl', {
      value: securityEventIngressQueue.queueUrl,
    });
    new CfnOutput(this, 'SecurityEventIngressDlqUrl', {
      value: securityEventIngressDlq.queueUrl,
    });
    new CfnOutput(this, 'SecurityEventStreamFailureNotificationQueueUrl', {
      value: securityEventStreamFailureNotificationQueue.queueUrl,
    });
    new CfnOutput(this, 'SecurityEventStreamFailureNotificationDlqUrl', {
      value: securityEventStreamFailureNotificationDlq.queueUrl,
    });
    new CfnOutput(this, 'SecurityEventStreamFailureBucketName', {
      value: securityEventStreamFailureBucket.bucketName,
    });
    new CfnOutput(this, 'SecurityEventIngressFailureBucketName', {
      value: securityEventIngressFailureBucket.bucketName,
    });
    new CfnOutput(this, 'WorkloadTrustTableName', { value: workloadTrustTable.tableName });
    new CfnOutput(this, 'CibaTableName', { value: cibaTable.tableName });
    new CfnOutput(this, 'DeviceTableName', { value: deviceTable.tableName });
    new CfnOutput(this, 'JtiTableName', { value: jtiTable.tableName });
    new CfnOutput(this, 'GraceTableName', { value: graceTable.tableName });
    new CfnOutput(this, 'GrantsTableName', { value: grantsTable.tableName });
    new CfnOutput(this, 'UsersTableName', { value: usersTable.tableName });
    new CfnOutput(this, 'AttributeNamespacesTableName', {
      value: attributeNamespacesTable.tableName,
    });
    new CfnOutput(this, 'FederationAttributeMappingsTableName', {
      value: federationAttributeMappingsTable.tableName,
    });
    new CfnOutput(this, 'ScimGroupsTableName', { value: scimGroupsTable.tableName });
    new CfnOutput(this, 'AdminAuthTableName', { value: adminAuthTable.tableName });
    new CfnOutput(this, 'AdminAuthRuntimeTableName', {
      value: adminAuthRuntimeTable.tableName,
    });
    new CfnOutput(this, 'PasswordCredentialsTableName', {
      value: passwordCredentialsTable.tableName,
    });
    new CfnOutput(this, 'GovernanceTableName', {
      value: governanceTable.tableName,
    });
    new CfnOutput(this, 'GovernanceSuppressionTableName', {
      value: governanceSuppressionTable.tableName,
    });
    new CfnOutput(this, 'GovernanceWorkerQueueUrl', {
      value: governanceWorkerQueue.queueUrl,
    });
    new CfnOutput(this, 'GovernanceWorkerDlqUrl', {
      value: governanceWorkerDlq.queueUrl,
    });
    new CfnOutput(this, 'GovernanceWorkerFnName', {
      value: governanceWorkerFn.functionName,
    });
    new CfnOutput(this, 'TenantResidency', {
      value: JSON.stringify(canonicalTenantResidency),
    });
    new CfnOutput(this, 'DomainMapTableName', { value: domainMapTable.tableName });
    new CfnOutput(this, 'RateLimitTableName', { value: rateLimitTable.tableName });
    if (regionControlTable) {
      new CfnOutput(this, 'RegionId', { value: this.region });
      new CfnOutput(this, 'RegionControlTableName', {
        value: regionControlTable.tableName,
      });
      new CfnOutput(this, 'FailoverReplicaRegions', {
        value: Fn.toJsonString(tenantKeyReplicaRegions),
      });
      new CfnOutput(this, 'ReplicatedAuthorityTableNames', {
        value: Fn.toJsonString(
          Object.fromEntries(
            Object.entries(replicatedAuthorityTables).map(([role, table]) => [
              role,
              table.tableName,
            ]),
          ),
        ),
      });
      new CfnOutput(this, 'ReplicatedRuntimeSecretArns', {
        value: Fn.toJsonString({
          server: serverSecret.secretArn,
          governance_hmac: governanceHmacSecret.secretArn,
          standby_bootstrap_config:
            standbyRuntimeBootstrapConfigSecret!.secretArn,
          platform_admin: adminCredentialSecret.secretArn,
          tenant_admin: tenantAdminTargetArns,
          scim: scimTargetArns,
        }),
      });
      new CfnOutput(this, 'RegionLocalTableNames', {
        value: Fn.toJsonString(regionLocalTables.map((table) => table.tableName)),
      });
      new CfnOutput(this, 'PrimaryApiHost', { value: apiHost });
      if (frontend) {
        new CfnOutput(this, 'FailoverDistributionId', {
          value: frontend.distributionId,
        });
      }
    }
    new CfnOutput(this, 'GraceEnvelopeKeyId', { value: tokenGraceKey.keyId });
    new CfnOutput(this, 'LegacyGraceEnvelopeKeyId', {
      value: legacyGraceKey.keyId,
    });
    new CfnOutput(this, 'CibaNotificationEnvelopeKeyId', {
      value: cibaNotificationKey.keyId,
    });
    // Admin credential-set 的 Secrets Manager ARN(非敏感标识符,真值不入 output/repo)。
    new CfnOutput(this, 'AdminSecretArn', { value: adminCredentialSecret.secretArn });
    new CfnOutput(this, 'AdminUrl', {
      value: `${webBaseUrl}/admin`,
      description: 'Admin console URL on the public CloudFront/custom-domain origin',
    });
    new CfnOutput(this, 'AdminTokenCommand', {
      value:
        `aws secretsmanager get-secret-value --secret-id '${adminCredentialSecret.secretArn}' ` +
        `--region '${this.region}' --query SecretString --output text | jq -er '.current.secret'`,
      description: 'AWS CLI command that prints the current Admin break-glass credential',
    });
    if (saasTenantIds.length > 0) {
      new CfnOutput(this, 'ScimSecretArns', {
        value: Fn.toJsonString(scimTargetArns),
        description: 'Tenant to owner-bound SCIM credential-set target Secret ARN map',
      });
    } else {
      new CfnOutput(this, 'ScimSecretArn', {
        value: scimCredentialSecrets.default.secretArn,
        description: 'Owner-bound SCIM credential-set target Secret ARN',
      });
      new CfnOutput(this, 'ScimTokenCommand', {
        value:
          `aws secretsmanager get-secret-value --secret-id '${scimCredentialSecrets.default.secretArn}' ` +
          `--region '${this.region}' --query SecretString --output text | jq -er '.current.secret'`,
        description: 'AWS CLI command that prints the current SCIM provisioning credential',
      });
    }

    // === cdk-nag 抑制(有据的例外,逐条说明理由)===
    NagSuppressions.addResourceSuppressions(
      fn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason: 'Lambda 基本执行角色(AWSLambdaBasicExecutionRole)是 CloudWatch Logs 写入所需的最小托管策略;业务权限已按最小化内联(仅该 KMS key + 两表)。',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason: 'grantReadWriteData 生成的表级/索引通配是 DynamoDB 单表访问所需(限定到本表 ARN + 其 index);非跨资源通配。',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      tokenFn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'Token Lambda basic execution role is limited to its retained CloudWatch log group; business permissions are explicit and the grace CMK grant is exact.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Token runtime uses the same enumerated DynamoDB tables and bounded indexes as the protocol runtime; route scope and the exact grace-key policy establish the C3.4 boundary.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      securityEventArchiveFn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'Archive Lambda basic execution role is limited to CloudWatch Logs; business access is scoped to one DynamoDB table, one S3 prefix, and one SQS queue.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'DynamoDB stream/index and the deterministic security-events/* object prefix require resource suffix wildcards scoped to this stack resources.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      ssfDeliveryFn,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'SSF Lambda basic execution role is limited to CloudWatch Logs; business access is scoped to one DynamoDB table, a bounded published KMS key set, and one source stream.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'The DynamoDB due index, source stream, and retained failure-bucket objects require resource suffix wildcards scoped to this stack resources.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(securityEventArchiveBucket, [
      {
        id: 'AwsSolutions-S1',
        reason:
          'Archive object access is audited through CloudTrail account controls; a second mutable S3 access-log store would not be the security-event source of truth.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(securityEventStreamFailureBucket, [
      {
        id: 'AwsSolutions-S1',
        reason:
          'This retained bucket is itself the immutable Lambda stream-failure audit destination. CloudTrail account controls audit access without introducing a second mutable log bucket.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(ssfStreamFailureBucket, [
      {
        id: 'AwsSolutions-S1',
        reason:
          'This retained bucket is the immutable SSF stream-failure payload destination. Account-level CloudTrail audits access without adding a second mutable logging bucket.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(securityEventIngressFailureBucket, [
      {
        id: 'AwsSolutions-S1',
        reason:
          'This retained quarantine bucket is the immutable seven-year copy for ingress payloads that cannot enter the hot ledger. CloudTrail account controls audit access.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(securityEventArchiveDlq, [
      {
        id: 'AwsSolutions-SQS3',
        reason:
          'This FIFO queue is the 14-day incident copy for archive failures. The ledger row is retained for seven years and a scheduled worker redrives it to S3; queue depth remains alarmed.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(securityEventIngressDlq, [
      {
        id: 'AwsSolutions-SQS3',
        reason:
          'This 14-day encrypted incident queue holds events that could not enter the hot ledger. The worker first writes the exact payload to a retained seven-year quarantine bucket, and queue depth is alarmed.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(securityEventIngressQueue, [
      {
        id: 'AwsSolutions-SQS3',
        reason:
          'Ingress retries are explicit typed messages with bounded attempts and preserved delivery history. The worker writes terminal payloads to the retained quarantine bucket and dedicated FIFO incident queue instead of relying on an opaque native redrive.',
      },
    ]);
    NagSuppressions.addResourceSuppressionsByPath(
      this,
      `${this.stackName}/BucketNotificationsHandler050a0587b7544547bf325f094a3db834/Role/Resource`,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'The CDK-managed S3 notification provider uses AWSLambdaBasicExecutionRole only to configure the retained stream-failure bucket notification. Business runtime permissions remain on the archive Lambda role.',
        },
      ],
      true,
    );
    const domainMapLogicalId = this.getLogicalId(
      domainMapTable.node.defaultChild as CfnElement,
    );
    const passkeyLogicalId = this.getLogicalId(passkeyTable.node.defaultChild as CfnElement);
    const authzSessionsLogicalId = this.getLogicalId(
      authzSessionsTable.node.defaultChild as CfnElement,
    );
    const sessionsLogicalId = this.getLogicalId(
      sessionsTable.node.defaultChild as CfnElement,
    );
    const deviceLogicalId = this.getLogicalId(
      deviceTable.node.defaultChild as CfnElement,
    );
    const ssfDeliveriesLogicalId = this.getLogicalId(
      ssfDeliveriesTable.node.defaultChild as CfnElement,
    );
    const scimGroupsLogicalId = this.getLogicalId(
      scimGroupsTable.node.defaultChild as CfnElement,
    );
    const usersLogicalId = this.getLogicalId(usersTable.node.defaultChild as CfnElement);
    const grantsLogicalId = this.getLogicalId(grantsTable.node.defaultChild as CfnElement);
    const replicatedIndexWildcardResources = tenantKeyReplicaRegions.flatMap(
      (replicaRegion) =>
        [
          grantsLogicalId,
          scimGroupsLogicalId,
          usersLogicalId,
          domainMapLogicalId,
          passkeyLogicalId,
        ].map(
          (logicalId) =>
            `Resource::arn:<AWS::Partition>:dynamodb:${replicaRegion}:${this.account}:table/<${logicalId}>/index/*`,
        ),
    );
    const governanceRetentionWildcardResources = [
      `Resource::arn:<AWS::Partition>:kms:*:${this.account}:key/*`,
      ...Object.values(replicatedAuthorityTables).map((table) => {
        const logicalId = this.getLogicalId(
          table.node.defaultChild as CfnElement,
        );
        return `Resource::arn:<AWS::Partition>:dynamodb:*:${this.account}:table/<${logicalId}>`;
      }),
      ...[
        securityEventArchiveBucket,
        securityEventStreamFailureBucket,
        securityEventIngressFailureBucket,
        ssfStreamFailureBucket,
      ].map((bucket) => {
        const logicalId = this.getLogicalId(
          bucket.node.defaultChild as CfnElement,
        );
        return `Resource::<${logicalId}.Arn>/*`;
      }),
    ];
    NagSuppressions.addStackSuppressions(this, [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'DynamoDB Query requires the table index suffix. These suffix wildcards are limited to the enumerated authority and Region-local tables, including configured replica Regions where applicable, even when CDK moves grants into an overflow policy.',
        appliesTo: [
          `Resource::<${authzSessionsLogicalId}.Arn>/index/*`,
          `Resource::<${sessionsLogicalId}.Arn>/index/*`,
          `Resource::<${deviceLogicalId}.Arn>/index/*`,
          `Resource::<${grantsLogicalId}.Arn>/index/*`,
          `Resource::<${domainMapLogicalId}.Arn>/index/*`,
          `Resource::<${passkeyLogicalId}.Arn>/index/*`,
          `Resource::<${scimGroupsLogicalId}.Arn>/index/*`,
          `Resource::<${ssfDeliveriesLogicalId}.Arn>/index/*`,
          `Resource::<${usersLogicalId}.Arn>/index/*`,
          ...replicatedIndexWildcardResources,
        ],
      },
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'Retention completion scans the exact replicated authority tables in every configured Region, inspects objects only in four enumerated retained evidence buckets, and describes tenant KMS keys across Regions under the managed-key tag condition. Stack scope is required because CDK materializes IAM overflow policies during synthesis.',
        appliesTo: governanceRetentionWildcardResources,
      },
    ]);
    if (regionControlTable) {
      for (const table of [
        ...Object.values(replicatedAuthorityTables),
        regionControlTable,
      ]) {
        const tableLogicalId = this.getLogicalId(
          table.node.defaultChild as CfnElement,
        );
        NagSuppressions.addResourceSuppressions(
          table,
          [
            {
              id: 'AwsSolutions-IAM5',
              reason:
                "CDK Global Table replication emits this generated table policy and wires it into the replica custom resource's dependencies. The stack detaches these per-table policies from the singleton provider roles and supplies equivalent consolidated inline grants to stay below IAM's managed-policy attachment quota.",
              appliesTo: [
                'Action::dynamodb:*',
                `Resource::<${tableLogicalId}.Arn>/index/*`,
              ],
            },
          ],
          true,
        );
      }
      NagSuppressions.addResourceSuppressionsByPath(
        this,
        `${this.stackName}/@aws-cdk--aws-dynamodb.ReplicaProvider`,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              'The CDK-owned Global Table replica provider uses AWSLambdaBasicExecutionRole only for deployment-time CloudWatch logs; application runtimes use separate least-privilege roles.',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason:
              'The CDK-owned Global Table provider needs generated callback Lambda invoke suffixes and Region-level DynamoDB replica lifecycle operations. Consolidated source-table grants remain scoped to the exact replicated tables.',
          },
          {
            id: 'AwsSolutions-SF1',
            reason:
              'This CDK-owned deployment-time waiter only polls DynamoDB replica creation. CloudFormation records its lifecycle, while application and failover audit events use dedicated retained logs.',
          },
          {
            id: 'AwsSolutions-SF2',
            reason:
              'This CDK-owned deployment-time waiter only polls DynamoDB replica creation and is not part of the request path; X-Ray tracing would not add application observability.',
          },
        ],
        true,
      );
    }

    // AwsSolutions-APIG4:API Gateway 层不套 authorizer 是**有意为之**——这些是 OAuth 2.1/OIDC
    // 协议端点(/authorize、/token、/.well-known/*、/jwks.json),它们**本身即认证/授权机制**:
    // 客户端认证在 /token 内按注册的 token_endpoint_auth_method 校验(C4.2)、PKCE 在协议层强制
    // (C4.1)、DCR 管理端点凭 registration_access_token 应用层鉴权(C4.3);给 /token 套网关
    // authorizer 逻辑上不成立(客户端尚无 token)。discovery/jwks 本就公开只读。故非"匿名可达面",
    // 授权在应用层按 spec 002 / DESIGN §3.1 落地。access logging 已启用(APIG1)。
    NagSuppressions.addResourceSuppressions(
      httpApi,
      [
        {
          id: 'AwsSolutions-APIG4',
          reason:
            'OAuth/OIDC 协议端点自身即授权机制(client auth C4.2 / PKCE C4.1 / DCR token C4.3 在应用层);discovery/jwks 公开只读。网关 authorizer 不适用,非匿名可达面。',
        },
      ],
      true,
    );
  }
}

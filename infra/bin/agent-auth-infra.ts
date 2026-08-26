#!/usr/bin/env node
import * as path from 'node:path';
import * as fs from 'node:fs';
import { App, Aspects } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AgentAuthStack } from '../lib/agent-auth-stack';
import {
  AgentAuthStandbyStack,
  ReplicatedAuthorityTableNames,
  ReplicatedRuntimeSecretArns,
} from '../lib/agent-auth-standby-stack';
import { CredentialMigrationStack } from '../lib/credential-migration-stack';
import { AuthorityReferenceMigrationStack } from '../lib/authority-reference-migration-stack';
import { requireWebBaseUrl } from '../lib/config';
import {
  devAuthConfig,
  devCimdConfig,
  saasAuthConfig,
  saasCimdConfig,
} from '../lib/deployment-auth-config';
import {
  resolveLambdaDeploymentProvenance,
} from '../lib/deployment-provenance';

const app = new App();

// 配置来自环境(账号号走 .env / CDK_DEFAULT_ACCOUNT,不硬编码入 repo)。
const account = process.env.CDK_DEFAULT_ACCOUNT;
const region = process.env.CDK_DEFAULT_REGION ?? 'us-east-1';
const webBaseUrl = requireWebBaseUrl('WEB_BASE_URL', process.env.WEB_BASE_URL);
const repoRoot = path.resolve(__dirname, '..', '..');
const requestedDeploymentCommit = process.env.AGENT_AUTH_DEPLOYMENT_COMMIT;
if (
  !requestedDeploymentCommit ||
  !/^[0-9a-f]{40}$/.test(requestedDeploymentCommit)
) {
  throw new Error(
    'AGENT_AUTH_DEPLOYMENT_COMMIT must be a full lowercase Git SHA',
  );
}

// Rust Lambda 产物(cargo lambda build --release --arm64 --features lambda,aws 输出目录)。
const lambdaAssetPath = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-lambda',
);

const securityEventArchiveAssetPath = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-security-event-archive',
);
if (!fs.existsSync(path.join(securityEventArchiveAssetPath, 'bootstrap'))) {
  throw new Error(
    '缺少 agent-auth-security-event-archive Lambda 产物；请按 docs/INSTALL_DEPLOY.md 构建全部七个 binary',
  );
}

const ssfDeliveryAssetPath = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-ssf-delivery',
);
if (!fs.existsSync(path.join(ssfDeliveryAssetPath, 'bootstrap'))) {
  throw new Error(
    '缺少 agent-auth-ssf-delivery Lambda 产物；请按 docs/INSTALL_DEPLOY.md 构建全部七个 binary',
  );
}

const tenantKeyProvisionerAssetPath = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-tenant-key-provisioner',
);
if (!fs.existsSync(path.join(tenantKeyProvisionerAssetPath, 'bootstrap'))) {
  throw new Error(
    '缺少 agent-auth-tenant-key-provisioner Lambda 产物；请按 docs/INSTALL_DEPLOY.md 构建全部七个 binary',
  );
}

const governanceWorkerAssetPath = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-governance-worker',
);
if (!fs.existsSync(path.join(governanceWorkerAssetPath, 'bootstrap'))) {
  throw new Error(
    '缺少 agent-auth-governance-worker Lambda 产物；请按 docs/INSTALL_DEPLOY.md 构建全部八个 binary',
  );
}

// client 回收后台任务产物(agent-auth-reclaim bin,spec 005 §9.5)。仅当该目录存在时部署回收 Lambda +
// EventBridge Schedule(默认 dry-run);未 build 该 bin(旧流程)则不部署,不破坏既有栈。
const reclaimBootstrap = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-reclaim',
);
const reclaimAssetPath = fs.existsSync(path.join(reclaimBootstrap, 'bootstrap'))
  ? reclaimBootstrap
  : undefined;

// 策略重算后台任务产物(agent-auth-recompute bin,spec 005 §7 / C10.17)。仅当目录存在才部署重算 Lambda +
// EventBridge Schedule(默认 dry-run;发布/激活策略工件亦由该 Lambda 单写者完成)。未 build 则不部署。
const recomputeBootstrap = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-recompute',
);
const recomputeAssetPath = fs.existsSync(path.join(recomputeBootstrap, 'bootstrap'))
  ? recomputeBootstrap
  : undefined;

const credentialMigrationBootstrap = path.resolve(
  __dirname,
  '..',
  '..',
  'target',
  'lambda',
  'agent-auth-migrate-credentials',
);
if (!fs.existsSync(path.join(credentialMigrationBootstrap, 'bootstrap'))) {
  throw new Error(
    '缺少 agent-auth-migrate-credentials Lambda 产物；请按 docs/INSTALL_DEPLOY.md 构建全部七个 binary',
  );
}
const credentialMigrationAssetPath = credentialMigrationBootstrap;
const deploymentProvenance = resolveLambdaDeploymentProvenance(
  repoRoot,
  requestedDeploymentCommit,
  [
    lambdaAssetPath,
    securityEventArchiveAssetPath,
    ssfDeliveryAssetPath,
    tenantKeyProvisionerAssetPath,
    governanceWorkerAssetPath,
    credentialMigrationAssetPath,
    ...(reclaimAssetPath ? [reclaimAssetPath] : []),
    ...(recomputeAssetPath ? [recomputeAssetPath] : []),
  ],
);
const deploymentCommit = deploymentProvenance.commit;

// Cedar 授权引擎(C10.17)开关 + 策略集。默认关(字节等价现网)。开关 AGENT_AUTH_AUTHZ_ENABLED=1;
// 策略文本走文件(AGENT_AUTH_POLICY_SET_FILE 指向 .cedar,避免大文本挤 shell env;绝不硬编码入 repo)。
const authzEnabled = process.env.AGENT_AUTH_AUTHZ_ENABLED === '1';
const policySetFile = process.env.AGENT_AUTH_POLICY_SET_FILE;
const policySet =
  policySetFile && fs.existsSync(policySetFile)
    ? fs.readFileSync(policySetFile, 'utf8')
    : process.env.AGENT_AUTH_POLICY_SET;

function readOptionalConfig(fileVariable: string, inlineVariable: string): string | undefined {
  const file = process.env[fileVariable];
  if (file) {
    if (!fs.existsSync(file)) {
      throw new Error(`${fileVariable} does not exist: ${file}`);
    }
    return fs.readFileSync(file, 'utf8');
  }
  return process.env[inlineVariable];
}

const devEmaPolicies = readOptionalConfig(
  'AGENT_AUTH_EMA_POLICIES_FILE',
  'AGENT_AUTH_EMA_POLICIES',
);
const saasEmaPolicies = readOptionalConfig(
  'SAAS_EMA_POLICIES_FILE',
  'SAAS_EMA_POLICIES',
);
const devEmaEnabled = process.env.AGENT_AUTH_EMA_ENABLED === '1';
const saasEmaEnabled =
  Boolean(process.env.SAAS_ZONE) && process.env.SAAS_EMA_ENABLED === '1';

function ecSigningKeyProps(prefix: 'DEV' | 'SAAS') {
  const activeEcSigningKeyArn = process.env[`${prefix}_EC_SIGNING_KEY_ARN`];
  const published = process.env[`${prefix}_EC_SIGNING_KEY_ARNS_PUBLISHED`];
  const publishedEcSigningKeyArns = published
    ?.split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return {
    activeEcSigningKeyArn,
    publishedEcSigningKeyArns,
  };
}

function requiredJsonObject<T>(name: string): T {
  const raw = process.env[name];
  if (!raw) {
    throw new Error(`${name} is required when SAAS_STANDBY_REGION is set`);
  }
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`${name} must be a JSON object`);
  }
  return parsed as T;
}

function optionalJsonObject<T>(name: string): T | undefined {
  const raw = process.env[name];
  if (!raw) {
    return undefined;
  }
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`${name} must be a JSON object`);
  }
  return parsed as T;
}

function optionalJsonStringArray(name: string): readonly string[] | undefined {
  const raw = process.env[name];
  if (!raw) {
    return undefined;
  }
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.some((value) => typeof value !== 'string')) {
    throw new Error(`${name} must be a JSON array of strings`);
  }
  return parsed;
}

// === 单租户 dev 栈(现网,保留不动;spec 020 D6 回滚基线)===
// 仅读单租户相关 env(CUSTOM_DOMAIN);**绝不**读 SaaS/多子域 env——避免部署 SaaS 栈时误改 dev 栈模板。
const devStack = new AgentAuthStack(app, 'AgentAuthDev', {
  env: { account, region },
  lambdaAssetPath,
  securityEventArchiveAssetPath,
  ssfDeliveryAssetPath,
  tenantKeyProvisionerAssetPath,
  governanceWorkerAssetPath,
  reclaimAssetPath,
  recomputeAssetPath,
  credentialMigrationAssetPath,
  authzEnabled,
  policySet,
  ...ecSigningKeyProps('DEV'),
  // SelfHosted 默认 open;登录占位、DCR mode 与票据 Secret 由同一纯配置映射提供并接受入口级测试。
  ...devAuthConfig(process.env),
  ...devCimdConfig(process.env),
  redirectPrefixAllowedHosts: Object.fromEntries([
    [
      'default',
      optionalJsonStringArray('AGENT_AUTH_REDIRECT_PREFIX_ALLOWED_HOSTS') ?? [],
    ],
  ]),
  // magic-link/浏览器回跳必须使用 CloudFront/自定义域统一入口,与 __Host- cookie 同源。
  webBaseUrl,
  invitationTtlSecs: process.env.AGENT_AUTH_INVITATION_TTL_SECS
    ? Number(process.env.AGENT_AUTH_INVITATION_TTL_SECS)
    : undefined,
  // 发布阶段:缺省 p2(P2 grant 全落地:client_credentials/token-exchange/device/CIBA);
  // AGENT_AUTH_PHASE 可覆盖(如回退 p1)。
  phase: process.env.AGENT_AUTH_PHASE ?? 'p2',
  // 上游 IdP 联邦(spec 003 §4):AGENT_AUTH_FEDERATION_ENABLED=1 时开(真机验收用)。
  federationEnabled: process.env.AGENT_AUTH_FEDERATION_ENABLED === '1',
  registrationWafEnabled: true,
  // Passkey(spec 003 §3):显式开关;表始终部署,端点默认 fail-closed 404。
  passkeyEnabled: process.env.AGENT_AUTH_PASSKEY_ENABLED === '1',
  emaEnabled: devEmaEnabled,
  emaPolicies: devEmaPolicies,
  deploymentCommit,
  // 自定义域名(联邦真机 redirect_uri 需稳定 host):env 齐备才挂 CloudFront 别名 + Route53 alias。
  customDomain: process.env.CUSTOM_DOMAIN,
  certArn: process.env.CUSTOM_DOMAIN_CERT_ARN,
  hostedZoneId: process.env.CUSTOM_DOMAIN_ZONE_ID,
  hostedZoneName: process.env.CUSTOM_DOMAIN_ZONE_NAME,
  // BYOD 投放方式 b(spec 010 §5.4 / C8.1b):AGENT_AUTH_BYOD_ENABLED=1 开数据面 well-known PRM 托管;
  // BYOD_DEMO_DOMAIN(自有 zone 下 host,如 mcp-demo.<zone>)加为 CloudFront 别名 + Route53 alias(复用通配证书)。
  byodEnabled: process.env.AGENT_AUTH_BYOD_ENABLED === '1',
  byodDemoDomain: process.env.BYOD_DEMO_DOMAIN,
  // X.509-SVID / mTLS(spec 012 §1.4 / C5.7,P3):独立 mTLS 域名(绕 CloudFront)。仅 SelfHosted。
  // AGENT_AUTH_MTLS_SVID_ENABLED=1 且 MTLS_DOMAIN/MTLS_CERT_ARN/MTLS_ZONE_ID/NAME 齐备才建;
  // deploy 先播种占位 truststore.pem,运维再上传真实 CA bundle 并 bump 域名 TruststoreVersion。
  mtlsDomain: process.env.MTLS_DOMAIN,
  mtlsCertArn: process.env.MTLS_CERT_ARN,
  mtlsZoneId: process.env.MTLS_ZONE_ID,
  mtlsZoneName: process.env.MTLS_ZONE_NAME,
  mtlsSvidEnabled: process.env.AGENT_AUTH_MTLS_SVID_ENABLED === '1',
  productionRecoveryEnabled: process.env.AGENT_AUTH_PRODUCTION_RECOVERY === '1',
  description: 'Agent Auth P2 dev stack (code/refresh + 2LO/token-exchange/device/CIBA)',
});
if (!devStack.credentialMigrationHandler) {
  throw new Error('AgentAuthDev credential migration handler was not created');
}
new CredentialMigrationStack(app, 'AgentAuthDevCredentialMigration', {
  env: { account, region },
  onEventHandler: devStack.credentialMigrationHandler,
  description:
    'Post-deploy irreversible client credential migration for AgentAuthDev',
});
new AuthorityReferenceMigrationStack(
  app,
  'AgentAuthDevAuthorityReferenceMigration',
  {
    env: { account, region },
    onEventHandler: devStack.authorityReferenceMigrationHandler,
    deploymentCommit,
    description:
      'Post-deploy active Code/Refresh reference backfill for AgentAuthDev',
  },
);

// === SaaS 多租户栈(spec 020 §2.3/§2.5;独立表集,D6:与 dev 栈并存供回滚)===
// **仅当 SAAS_ZONE 设置时才实例化**(否则纯 dev 部署不受影响)。租户走 t{N}.<zone> 子域(每子域独立
// issuer),控制面 SAAS_CONTROL_HOST 派生失败→400;数据面 tenant 物理分区默认开(SaaS 语义要求)。
// 新表集(全新 CDK 逻辑资源)→ 与 AgentAuthDev 的表零共享,dev 栈可随时回滚。
if (process.env.SAAS_ZONE) {
  const saasWebBaseUrl = requireWebBaseUrl(
    'SAAS_WEB_BASE_URL',
    process.env.SAAS_WEB_BASE_URL,
  );
  const saasDomains = (process.env.SAAS_DOMAINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const saasReplicaRegions = (process.env.SAAS_REPLICA_REGIONS ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const tenantSuffix = `.${process.env.SAAS_ZONE}`;
  const saasTenantIds = saasDomains
    .filter((domain) => domain !== process.env.SAAS_CONTROL_HOST)
    .map((domain) => domain.slice(0, -tenantSuffix.length))
    .sort();
  const configuredSaasTenantResidency =
    optionalJsonObject<Readonly<Record<string, {
      readonly jurisdiction: string;
      readonly allowed_regions: readonly string[];
      readonly governance_region?: string;
    }>>>('SAAS_TENANT_RESIDENCY') ??
    Object.fromEntries(
      saasTenantIds.map((tenant) => [
        tenant,
        {
          jurisdiction: region.split('-')[0],
          allowed_regions: [region, ...saasReplicaRegions].sort(),
          governance_region: region,
        },
      ]),
    );
  const saasTenantResidency = Object.fromEntries(
    Object.entries(configuredSaasTenantResidency).map(
      ([tenant, residency]) => [
        tenant,
        {
          ...residency,
          governance_region: residency.governance_region ?? region,
        },
      ],
    ),
  );
  const saasProductionRecoveryEnabled =
    process.env.SAAS_PRODUCTION_RECOVERY !== '0';
  const saasTenantSubjectTypes =
    optionalJsonObject<Readonly<Record<string, 'public' | 'pairwise'>>>(
      'SAAS_TENANT_SUBJECT_TYPES',
    ) ?? {};
  const saasRedirectPrefixAllowedHosts =
    optionalJsonObject<Readonly<Record<string, readonly string[]>>>(
      'SAAS_REDIRECT_PREFIX_ALLOWED_HOSTS',
    ) ?? {};
  const saasOffboardedTenantIds = (process.env.SAAS_OFFBOARDED_TENANTS ?? '')
    .split(',')
    .map((tenant) => tenant.trim())
    .filter(Boolean);
  if (
    new Set(saasOffboardedTenantIds).size !== saasOffboardedTenantIds.length ||
    saasOffboardedTenantIds.some((tenant) => !saasTenantIds.includes(tenant))
  ) {
    throw new Error(
      'SAAS_OFFBOARDED_TENANTS must contain unique configured SaaS tenant IDs',
    );
  }
  let tenantAdminSecretArns: Record<string, string>;
  try {
    const parsed = JSON.parse(process.env.SAAS_TENANT_ADMIN_SECRET_ARNS ?? '{}') as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('must be a JSON object');
    }
    if (Object.values(parsed).some((value) => typeof value !== 'string')) {
      throw new Error('all values must be Secret ARN strings');
    }
    tenantAdminSecretArns = parsed as Record<string, string>;
  } catch (error) {
    throw new Error(`SAAS_TENANT_ADMIN_SECRET_ARNS 非法:${String(error)}`);
  }
  const saasStack = new AgentAuthStack(app, 'AgentAuthSaas', {
    env: { account, region },
    lambdaAssetPath,
    securityEventArchiveAssetPath,
    ssfDeliveryAssetPath,
    tenantKeyProvisionerAssetPath,
    governanceWorkerAssetPath,
    tenantKeyReplicaRegions: saasReplicaRegions,
    tenantResidency: saasTenantResidency,
    reclaimAssetPath,
    recomputeAssetPath,
    credentialMigrationAssetPath,
    authzEnabled,
    policySet,
    ...ecSigningKeyProps('SAAS'),
    // SaaS 不接受部署级 DCR/占位登录配置;DCR 等逐租户控制面,登录只走真实认证。
    ...saasAuthConfig(process.env),
    ...saasCimdConfig(process.env),
    webBaseUrl: saasWebBaseUrl,
    invitationTtlSecs: process.env.AGENT_AUTH_INVITATION_TTL_SECS
      ? Number(process.env.AGENT_AUTH_INVITATION_TTL_SECS)
      : undefined,
    phase: process.env.AGENT_AUTH_PHASE ?? 'p2',
    federationEnabled: false,
    registrationWafEnabled: true,
    passkeyEnabled: process.env.SAAS_PASSKEY_ENABLED === '1',
    saasOriginAuthRevision:
      process.env.SAAS_ORIGIN_AUTH_REVISION ?? '1',
    emaEnabled: saasEmaEnabled,
    emaPolicies: saasEmaPolicies,
    deploymentCommit,
    // 多子域(t1/t2/c.<zone>)全挂 CloudFront 别名 + Route53 alias(通配证书 *.<zone>)。
    customDomains: saasDomains,
    certArn: process.env.SAAS_CERT_ARN,
    hostedZoneId: process.env.SAAS_ZONE_ID,
    hostedZoneName: process.env.SAAS_ZONE_NAME,
    // SaaS 形态 + 数据面分区(SaaS 语义强制开:租户物理隔离)。
    saasZone: process.env.SAAS_ZONE,
    saasControlHost: process.env.SAAS_CONTROL_HOST,
    enableTenantPartitioning: true,
    // 每租户独立 Secret ARN;Stack 校验与租户域名集合一一对应。
    tenantAdminSecretArns,
    tenantSubjectTypes: saasTenantSubjectTypes,
    redirectPrefixAllowedHosts: saasRedirectPrefixAllowedHosts,
    offboardedTenantIds: saasOffboardedTenantIds,
    // 逐租户 Sign 公平闸(C10.14,spec 020 §3.1):SaaS 默认启用,防单 noisy 租户耗尽区域 ECC Sign 配额
    // throttle 他人。容量/补充可经 env 覆盖(据该区实测 KMS Sign 配额标定,Σ 份额 ≤ 全局);默认保守值。
    kmsTenantGateCapacity: process.env.SAAS_KMS_TENANT_GATE_CAPACITY
      ? Number(process.env.SAAS_KMS_TENANT_GATE_CAPACITY)
      : 30,
    kmsTenantGateRefillPerSec: process.env.SAAS_KMS_TENANT_GATE_REFILL_PER_SEC
      ? Number(process.env.SAAS_KMS_TENANT_GATE_REFILL_PER_SEC)
      : 20,
    // BYOD(spec 010 §5.4 / C8.1b):SaaS 栈同款开关;SAAS_BYOD_DEMO_DOMAIN 加为别名(需 *.<zone> 通配证书覆盖)。
    byodEnabled: process.env.AGENT_AUTH_BYOD_ENABLED === '1',
    byodDemoDomain: process.env.SAAS_BYOD_DEMO_DOMAIN,
    // SaaS is the production data profile. Explicit `0` is reserved for disposable
    // test deployments; normal deployments retain authority and schedule backups.
    productionRecoveryEnabled: saasProductionRecoveryEnabled,
    description: 'Agent Auth SaaS multi-tenant stack (spec 020; per-tenant subdomain issuer + data-plane partition)',
  });
  if (!saasStack.credentialMigrationHandler) {
    throw new Error('AgentAuthSaas credential migration handler was not created');
  }
  new CredentialMigrationStack(app, 'AgentAuthSaasCredentialMigration', {
    env: { account, region },
    onEventHandler: saasStack.credentialMigrationHandler,
    description:
      'Post-deploy irreversible client credential migration for AgentAuthSaas',
  });
  new AuthorityReferenceMigrationStack(
    app,
    'AgentAuthSaasAuthorityReferenceMigration',
    {
      env: { account, region },
      onEventHandler: saasStack.authorityReferenceMigrationHandler,
      deploymentCommit,
      description:
        'Post-deploy active Code/Refresh reference backfill for AgentAuthSaas',
    },
  );

  const standbyRegion = process.env.SAAS_STANDBY_REGION;
  if (standbyRegion) {
    if (region !== 'us-east-1' || standbyRegion !== 'us-west-2') {
      throw new Error(
        'multi-Region SaaS supports only primary us-east-1 and standby us-west-2',
      );
    }
    if (
      saasReplicaRegions.length !== 1 ||
      saasReplicaRegions[0] !== standbyRegion
    ) {
      throw new Error(
        'SAAS_STANDBY_REGION requires SAAS_REPLICA_REGIONS to contain exactly the standby Region',
      );
    }
    const authorityTableNames =
      requiredJsonObject<ReplicatedAuthorityTableNames>(
        'SAAS_STANDBY_AUTHORITY_TABLES',
      );
    const runtimeSecretArns =
      requiredJsonObject<ReplicatedRuntimeSecretArns>(
        'SAAS_STANDBY_RUNTIME_SECRET_ARNS',
      );
    const regionControlTableName =
      process.env.SAAS_STANDBY_REGION_CONTROL_TABLE;
    if (!regionControlTableName) {
      throw new Error(
        'SAAS_STANDBY_REGION_CONTROL_TABLE is required when SAAS_STANDBY_REGION is set',
      );
    }
    const standbyStack = new AgentAuthStandbyStack(app, 'AgentAuthSaasStandby', {
      env: { account, region: standbyRegion },
      lambdaAssetPath,
      credentialMigrationAssetPath,
      deploymentCommit,
      webBaseUrl: saasWebBaseUrl,
      saasZone: process.env.SAAS_ZONE,
      saasControlHost: process.env.SAAS_CONTROL_HOST ?? '',
      tenantIds: saasTenantIds,
      tenantSubjectTypes: saasTenantSubjectTypes,
      redirectPrefixAllowedHosts: saasRedirectPrefixAllowedHosts,
      tenantResidency: saasTenantResidency,
      authorityTableNames,
      regionControlTableName,
      runtimeSecretArns,
      cloudFrontOriginSecretName:
        `${saasStack.stackName}/cloudfront-origin-auth`,
      cloudFrontOriginSecondarySecretName:
        `${saasStack.stackName}/cloudfront-origin-auth-secondary`,
      saasOriginAuthRevision:
        process.env.SAAS_ORIGIN_AUTH_REVISION ?? '1',
      phase: process.env.AGENT_AUTH_PHASE ?? 'p2',
      passkeyEnabled: process.env.SAAS_PASSKEY_ENABLED === '1',
      authzEnabled,
      policySet,
      byodEnabled: process.env.AGENT_AUTH_BYOD_ENABLED === '1',
      invitationTtlSecs: process.env.AGENT_AUTH_INVITATION_TTL_SECS
        ? Number(process.env.AGENT_AUTH_INVITATION_TTL_SECS)
        : undefined,
      kmsTenantGateCapacity: process.env.SAAS_KMS_TENANT_GATE_CAPACITY
        ? Number(process.env.SAAS_KMS_TENANT_GATE_CAPACITY)
        : 30,
      kmsTenantGateRefillPerSec:
        process.env.SAAS_KMS_TENANT_GATE_REFILL_PER_SEC
          ? Number(process.env.SAAS_KMS_TENANT_GATE_REFILL_PER_SEC)
          : 20,
      description:
        'Agent Auth SaaS replay-safe standby runtime (no durable authority writers or public edge)',
    });
    standbyStack.addDependency(
      saasStack,
      'The primary stack creates and replicates both SaaS origin-auth Secrets',
    );
    new AuthorityReferenceMigrationStack(
      app,
      'AgentAuthSaasStandbyAuthorityReferenceMigration',
      {
        env: { account, region: standbyRegion },
        onEventHandler: standbyStack.authorityReferenceMigrationHandler,
        deploymentCommit,
        description:
          'Post-deploy active Code/Refresh reference backfill for AgentAuthSaasStandby',
      },
    );
  }
}

// cdk-nag:AWS Solutions 规则集(部署前须过)。
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

import {
  CfnElement,
  CfnOutput,
  Duration,
  Fn,
  RemovalPolicy,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import { createHash } from 'node:crypto';
import { Construct } from 'constructs';
import * as apigw from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as events from 'aws-cdk-lib/aws-events';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import { NagSuppressions } from 'cdk-nag';
import { requireWebBaseUrl } from './config';
import { validateRedirectPrefixAllowedHosts } from './agent-auth-stack';

export interface ReplicatedAuthorityTableNames {
  readonly clients: string;
  readonly workload_trust: string;
  readonly grants: string;
  readonly federation_config: string;
  readonly admin_auth: string;
  readonly passkeys: string;
  readonly security_events: string;
  readonly users: string;
  readonly attribute_namespaces: string;
  readonly federation_attribute_mappings: string;
  readonly scim_groups: string;
  readonly password_credentials: string;
  readonly domain_map: string;
  readonly tenant_keys: string;
  readonly governance: string;
  readonly governance_suppression: string;
}

export interface ReplicatedRuntimeSecretArns {
  readonly server: string;
  readonly governance_hmac: string;
  readonly standby_bootstrap_config: string;
  readonly platform_admin: string;
  readonly tenant_admin: Readonly<Record<string, string>>;
  readonly scim: Readonly<Record<string, string>>;
}

export interface AgentAuthStandbyStackProps extends StackProps {
  readonly lambdaAssetPath: string;
  readonly credentialMigrationAssetPath: string;
  readonly deploymentCommit: string;
  readonly webBaseUrl: string;
  readonly saasZone: string;
  readonly saasControlHost: string;
  readonly tenantIds: readonly string[];
  readonly tenantSubjectTypes?: Readonly<Record<string, 'public' | 'pairwise'>>;
  readonly redirectPrefixAllowedHosts?: Readonly<
    Record<string, readonly string[]>
  >;
  readonly authorityTableNames: ReplicatedAuthorityTableNames;
  readonly regionControlTableName: string;
  readonly runtimeSecretArns: ReplicatedRuntimeSecretArns;
  /** Stable names of the primary stack Secrets replicated into this Region. */
  readonly cloudFrontOriginSecretName: string;
  readonly cloudFrontOriginSecondarySecretName: string;
  readonly saasOriginAuthRevision: string;
  readonly tenantResidency: Readonly<Record<string, {
    readonly jurisdiction: string;
    readonly allowed_regions: readonly string[];
    readonly governance_region: string;
  }>>;
  readonly phase?: string;
  readonly passkeyEnabled?: boolean;
  readonly authzEnabled?: boolean;
  readonly policySet?: string;
  readonly byodEnabled?: boolean;
  readonly invitationTtlSecs?: number;
  readonly kmsTenantGateCapacity?: number;
  readonly kmsTenantGateRefillPerSec?: number;
}

interface RegionLocalTables {
  readonly codes: dynamodb.Table;
  readonly clientAuthorityRefs: dynamodb.Table;
  readonly initialAccessTokens: dynamodb.Table;
  readonly refresh: dynamodb.Table;
  readonly sessions: dynamodb.Table;
  readonly magicLinks: dynamodb.Table;
  readonly invitations: dynamodb.Table;
  readonly recovery: dynamodb.Table;
  readonly authzSessions: dynamodb.Table;
  readonly ciba: dynamodb.Table;
  readonly device: dynamodb.Table;
  readonly grace: dynamodb.Table;
  readonly jti: dynamodb.Table;
  readonly federationFlow: dynamodb.Table;
  readonly adminAuthRuntime: dynamodb.Table;
  readonly passkeyChallenges: dynamodb.Table;
  readonly par: dynamodb.Table;
  readonly rateLimit: dynamodb.Table;
  readonly messages: dynamodb.Table;
  readonly ssfDeliveries: dynamodb.Table;
}

function createRegionLocalTables(scope: Construct): RegionLocalTables {
  const table = (
    id: string,
    partitionKey: dynamodb.Attribute,
    options: {
      readonly sortKey?: dynamodb.Attribute;
      readonly ttl?: string;
      readonly retain?: boolean;
      readonly tableName?: string;
    } = {},
  ) =>
    new dynamodb.Table(scope, id, {
      partitionKey,
      ...(options.sortKey ? { sortKey: options.sortKey } : {}),
      ...(options.tableName ? { tableName: options.tableName } : {}),
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      ...(options.ttl ? { timeToLiveAttribute: options.ttl } : {}),
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: options.retain
        ? RemovalPolicy.RETAIN
        : RemovalPolicy.DESTROY,
    });
  const stringKey = (name: string): dynamodb.Attribute => ({
    name,
    type: dynamodb.AttributeType.STRING,
  });

  const codes = table('CodesTable', stringKey('code'), { ttl: 'expires_at' });
  codes.addGlobalSecondaryIndex({
    indexName: 'client_id-index',
    partitionKey: stringKey('client_id'),
    projectionType: dynamodb.ProjectionType.KEYS_ONLY,
  });
  const initialAccessTokens = table(
    'InitialAccessTokensTable',
    stringKey('token_id'),
    { ttl: 'expires_at' },
  );
  const refresh = table('RefreshTable', stringKey('family_id'));
  refresh.addGlobalSecondaryIndex({
    indexName: 'client_id-index',
    partitionKey: stringKey('client_id'),
    projectionType: dynamodb.ProjectionType.KEYS_ONLY,
  });
  const clientAuthorityRefs = table(
    'ClientAuthorityRefsTable',
    stringKey('client_key'),
    {
      sortKey: stringKey('reference_key'),
      ttl: 'expires_at',
      tableName: `${Stack.of(scope).stackName}-refs`,
    },
  );
  refresh.addGlobalSecondaryIndex({
    indexName: 'user_id-index',
    partitionKey: stringKey('user_id'),
    projectionType: dynamodb.ProjectionType.KEYS_ONLY,
  });
  const sessions = table('SessionsTable', stringKey('session_id'), {
    ttl: 'expires_at',
  });
  sessions.addGlobalSecondaryIndex({
    indexName: 'user_id-index',
    partitionKey: stringKey('user_id'),
    projectionType: dynamodb.ProjectionType.ALL,
  });
  const magicLinks = table('MagicLinkTable', stringKey('pk'), {
    ttl: 'expires_at',
  });
  const invitations = table('InvitationsTable', stringKey('locator'), {
    ttl: 'expires_at',
  });
  const recovery = table('RecoveryTable', stringKey('user_lookup'));
  const authzSessions = table(
    'AuthzSessionsTable',
    stringKey('session_id'),
    { ttl: 'expires_at' },
  );
  authzSessions.addGlobalSecondaryIndex({
    indexName: 'client_id-index',
    partitionKey: stringKey('client_id'),
  });
  const ciba = table('CibaTable', stringKey('auth_req_id'), {
    ttl: 'expires_at',
  });
  const device = table('DeviceTable', stringKey('device_code'), {
    ttl: 'expires_at',
  });
  device.addGlobalSecondaryIndex({
    indexName: 'user_code-index',
    partitionKey: stringKey('user_code'),
  });
  const grace = table('GraceTable', stringKey('family_id'), {
    sortKey: { name: 'version', type: dynamodb.AttributeType.NUMBER },
    ttl: 'expires_at',
  });
  const jti = table('JtiTable', stringKey('pk'), { ttl: 'expires_at' });
  const federationFlow = table(
    'FederationFlowTable',
    stringKey('state'),
    { ttl: 'expires_at' },
  );
  const adminAuthRuntime = table(
    'AdminAuthRuntimeTable',
    stringKey('key'),
    { ttl: 'expires_at' },
  );
  const passkeyChallenges = table(
    'PasskeyChallengeTable',
    stringKey('challenge'),
    { ttl: 'expires_at' },
  );
  const par = table('ParTable', stringKey('request_uri'), {
    ttl: 'expires_at',
  });
  const rateLimit = table('RateLimitTable', stringKey('key'), {
    ttl: 'expires_at',
  });
  const messages = table('MessagesTable', stringKey('message_id'), {
    ttl: 'ttl',
  });
  const ssfDeliveries = table(
    'SsfDeliveriesTable',
    stringKey('tenant_id'),
    {
      sortKey: stringKey('record_key'),
      ttl: 'expires_at',
      retain: true,
    },
  );
  ssfDeliveries.addGlobalSecondaryIndex({
    indexName: 'due-index',
    partitionKey: stringKey('due_partition'),
    sortKey: { name: 'due_at', type: dynamodb.AttributeType.NUMBER },
    projectionType: dynamodb.ProjectionType.ALL,
  });
  ssfDeliveries.addGlobalSecondaryIndex({
    indexName: 'stream-created-at-index',
    partitionKey: stringKey('stream_partition'),
    sortKey: stringKey('stream_created_at'),
    projectionType: dynamodb.ProjectionType.ALL,
  });

  return {
    codes,
    clientAuthorityRefs,
    initialAccessTokens,
    refresh,
    sessions,
    magicLinks,
    invitations,
    recovery,
    authzSessions,
    ciba,
    device,
    grace,
    jti,
    federationFlow,
    adminAuthRuntime,
    passkeyChallenges,
    par,
    rateLimit,
    messages,
    ssfDeliveries,
  };
}

export class AgentAuthStandbyStack extends Stack {
  public readonly authorityReferenceMigrationHandler: lambda.Function;

  constructor(
    scope: Construct,
    id: string,
    props: AgentAuthStandbyStackProps,
  ) {
    super(scope, id, props);

    const webBaseUrl = requireWebBaseUrl('webBaseUrl', props.webBaseUrl);
    if (!/^[0-9a-f]{40}$/.test(props.deploymentCommit)) {
      throw new Error(
        'standby requires AGENT_AUTH_DEPLOYMENT_COMMIT as a full lowercase Git SHA',
      );
    }
    const tenantIds = [...props.tenantIds].sort();
    const invitationTtlSecs = props.invitationTtlSecs ?? 86_400;
    if (
      !Number.isSafeInteger(invitationTtlSecs) ||
      invitationTtlSecs < 300 ||
      invitationTtlSecs > 604_800
    ) {
      throw new Error(
        'invitationTtlSecs must be an integer between 300 and 604800',
      );
    }
    if (
      tenantIds.length === 0 ||
      new Set(tenantIds).size !== tenantIds.length ||
      tenantIds.some((tenant) => !/^[a-z0-9-]{1,32}$/.test(tenant))
    ) {
      throw new Error('standby tenantIds must be non-empty, unique tenant labels');
    }
    if (
      Object.keys(props.tenantSubjectTypes ?? {}).some(
        (tenant) => !tenantIds.includes(tenant),
      ) ||
      Object.values(props.tenantSubjectTypes ?? {}).some(
        (subjectType) => !['public', 'pairwise'].includes(subjectType),
      )
    ) {
      throw new Error(
        'standby tenantSubjectTypes may contain only configured tenants with public or pairwise values',
      );
    }
    validateRedirectPrefixAllowedHosts(
      props.redirectPrefixAllowedHosts ?? {},
      tenantIds,
      false,
    );
    if (
      props.cloudFrontOriginSecondarySecretName !==
      `${props.cloudFrontOriginSecretName}-secondary`
    ) {
      throw new Error(
        'standby secondary CloudFront origin Secret name must derive from the primary name',
      );
    }
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(props.saasOriginAuthRevision)) {
      throw new Error(
        'standby saasOriginAuthRevision must be 1-64 characters from A-Z, a-z, 0-9, dot, underscore, or hyphen',
      );
    }
    for (const [kind, values] of [
      ['tenant_admin', props.runtimeSecretArns.tenant_admin],
      ['scim', props.runtimeSecretArns.scim],
    ] as const) {
      if (
        JSON.stringify(Object.keys(values).sort()) !==
        JSON.stringify(tenantIds)
      ) {
        throw new Error(
          `standby ${kind} Secret tenants must exactly match tenantIds`,
        );
      }
    }
    if (
      JSON.stringify(Object.keys(props.tenantResidency).sort()) !==
        JSON.stringify(tenantIds) ||
      Object.values(props.tenantResidency).some(
        (residency) =>
          !residency.allowed_regions.includes(this.region) ||
          !residency.allowed_regions.includes(residency.governance_region),
      )
    ) {
      throw new Error(
        'standby tenantResidency must exactly match tenants and admit the standby and governance Regions',
      );
    }
    const requiredNames = [
      ...Object.values(props.authorityTableNames),
      props.regionControlTableName,
    ];
    if (
      new Set(requiredNames).size !== requiredNames.length ||
      requiredNames.some((name) => !/^[A-Za-z0-9_.-]{3,255}$/.test(name))
    ) {
      throw new Error(
        'standby authority and Region control table names must be valid and unique',
      );
    }
    const secretArns = [
      props.runtimeSecretArns.server,
      props.runtimeSecretArns.governance_hmac,
      props.runtimeSecretArns.standby_bootstrap_config,
      props.runtimeSecretArns.platform_admin,
      ...Object.values(props.runtimeSecretArns.tenant_admin),
      ...Object.values(props.runtimeSecretArns.scim),
    ];
    if (
      new Set(secretArns).size !== secretArns.length ||
      secretArns.some((arn) => {
        const parts = arn.split(':');
        return (
          parts.length < 7 ||
          parts[2] !== 'secretsmanager' ||
          parts[3] !== this.region ||
          parts[4] !== this.account
        );
      })
    ) {
      throw new Error(
        'standby runtime Secret ARNs must be unique local replicas in the standby account and Region',
      );
    }

    const importedTable = (
      id: string,
      tableName: string,
      globalIndexes: readonly string[] = [],
    ): dynamodb.ITable =>
      dynamodb.Table.fromTableAttributes(this, id, {
        tableName,
        globalIndexes: [...globalIndexes],
      });
    const authority = {
      clients: importedTable(
        'ImportedClientsTable',
        props.authorityTableNames.clients,
        ['last_used_day-index'],
      ),
      workloadTrust: importedTable(
        'ImportedWorkloadTrustTable',
        props.authorityTableNames.workload_trust,
      ),
      grants: importedTable(
        'ImportedGrantsTable',
        props.authorityTableNames.grants,
        ['user_id-index', 'policy_version-index'],
      ),
      federationConfig: importedTable(
        'ImportedFederationConfigTable',
        props.authorityTableNames.federation_config,
      ),
      adminAuth: importedTable(
        'ImportedAdminAuthTable',
        props.authorityTableNames.admin_auth,
      ),
      passkeys: importedTable(
        'ImportedPasskeyTable',
        props.authorityTableNames.passkeys,
        ['user_id-index'],
      ),
      securityEvents: importedTable(
        'ImportedSecurityEventsTable',
        props.authorityTableNames.security_events,
        ['tenant_occurred_at-index', 'delivery_status-index'],
      ),
      users: importedTable(
        'ImportedUsersTable',
        props.authorityTableNames.users,
        ['email-index', 'scim_tenant-index'],
      ),
      attributeNamespaces: importedTable(
        'ImportedAttributeNamespacesTable',
        props.authorityTableNames.attribute_namespaces,
      ),
      federationAttributeMappings: importedTable(
        'ImportedFederationAttributeMappingsTable',
        props.authorityTableNames.federation_attribute_mappings,
      ),
      scimGroups: importedTable(
        'ImportedScimGroupsTable',
        props.authorityTableNames.scim_groups,
        ['tenant_kind-index'],
      ),
      passwordCredentials: importedTable(
        'ImportedPasswordCredentialsTable',
        props.authorityTableNames.password_credentials,
      ),
      domainMap: importedTable(
        'ImportedDomainMapTable',
        props.authorityTableNames.domain_map,
        ['client_id-index'],
      ),
      tenantKeys: importedTable(
        'ImportedTenantKeysTable',
        props.authorityTableNames.tenant_keys,
      ),
      governance: importedTable(
        'ImportedGovernanceTable',
        props.authorityTableNames.governance,
      ),
      governanceSuppression: importedTable(
        'ImportedGovernanceSuppressionTable',
        props.authorityTableNames.governance_suppression,
      ),
    };
    const regionControl = importedTable(
      'ImportedRegionControlTable',
      props.regionControlTableName,
    );
    const local = createRegionLocalTables(this);

    // Preserve the original key as a disabled rollback tombstone. The new
    // TokenGraceEnvelopeKey is the only key granted to the token runtime.
    const legacyGraceKey = new kms.Key(this, 'GraceEnvelopeKey', {
      description: 'agent-auth standby legacy grace-cache envelope key',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const tokenGraceKey = new kms.Key(this, 'TokenGraceEnvelopeKey', {
      description: 'agent-auth standby token-runtime grace-cache envelope key',
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
          'agent-auth standby CIBA notification token envelope key',
        enableKeyRotation: true,
        removalPolicy: RemovalPolicy.RETAIN,
      },
    );
    const securityEventIngressDlq = new sqs.Queue(
      this,
      'SecurityEventIngressDlq',
      {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(2),
      },
    );
    const securityEventIngressQueue = new sqs.Queue(
      this,
      'SecurityEventIngressQueue',
      {
        encryption: sqs.QueueEncryption.SQS_MANAGED,
        enforceSSL: true,
        retentionPeriod: Duration.days(14),
        visibilityTimeout: Duration.minutes(2),
        deadLetterQueue: {
          queue: securityEventIngressDlq,
          maxReceiveCount: 5,
        },
      },
    );
    const authzEventBus = new events.EventBus(this, 'AuthzEventBus', {
      eventBusName: `${this.stackName}-authz-events`,
    });

    const serverSecret = secretsmanager.Secret.fromSecretCompleteArn(
      this,
      'ImportedServerSecret',
      props.runtimeSecretArns.server,
    );
    const governanceHmacSecret = secretsmanager.Secret.fromSecretCompleteArn(
      this,
      'ImportedGovernanceHmacSecret',
      props.runtimeSecretArns.governance_hmac,
    );
    const runtimeBootstrapConfigSecret =
      secretsmanager.Secret.fromSecretCompleteArn(
        this,
        'ImportedRuntimeBootstrapConfig',
        props.runtimeSecretArns.standby_bootstrap_config,
      );
    const cloudFrontOriginSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      'ImportedCloudFrontOriginAuthSecret',
      props.cloudFrontOriginSecretName,
    );
    const cloudFrontOriginSecondarySecret =
      secretsmanager.Secret.fromSecretNameV2(
        this,
        'ImportedCloudFrontOriginAuthSecondarySecret',
        props.cloudFrontOriginSecondarySecretName,
      );
    const platformAdminSecret = secretsmanager.Secret.fromSecretCompleteArn(
      this,
      'ImportedPlatformAdminSecret',
      props.runtimeSecretArns.platform_admin,
    );
    const tenantAdminSecrets = Object.fromEntries(
      tenantIds.map((tenant) => [
        tenant,
        secretsmanager.Secret.fromSecretCompleteArn(
          this,
          `ImportedTenantAdminSecret-${tenant}`,
          props.runtimeSecretArns.tenant_admin[tenant],
        ),
      ]),
    );
    const scimSecrets = Object.fromEntries(
      tenantIds.map((tenant) => [
        tenant,
        secretsmanager.Secret.fromSecretCompleteArn(
          this,
          `ImportedScimSecret-${tenant}`,
          props.runtimeSecretArns.scim[tenant],
        ),
      ]),
    );
    const tenantAdminArns = Object.fromEntries(
      Object.entries(tenantAdminSecrets).map(([tenant, secret]) => [
        tenant,
        secret.secretArn,
      ]),
    );
    const scimArns = Object.fromEntries(
      Object.entries(scimSecrets).map(([tenant, secret]) => [
        tenant,
        secret.secretArn,
      ]),
    );
    const tenantSecretDependencies = Object.fromEntries(
      tenantIds.map((tenant) => [
        tenant,
        [
          {
            purpose: 'tenant_admin',
            secret_ref: tenantAdminArns[tenant],
            ownership: 'product_managed',
            resource_account: this.account,
            resource_region: this.region,
            ownership_revision: 1,
          },
          {
            purpose: 'scim',
            secret_ref: scimArns[tenant],
            ownership: 'product_managed',
            resource_account: this.account,
            resource_region: this.region,
            ownership_revision: 1,
          },
        ],
      ]),
    );
    const runtimeBootstrapDocument = {
      schema_version: 1,
      governance_hmac_secret_arn: governanceHmacSecret.secretArn,
      admin_credential_secret_arn: platformAdminSecret.secretArn,
      passkey_origin_secret_arn: cloudFrontOriginSecret.secretArn,
      saas_tenants: tenantIds,
      tenant_subject_types: props.tenantSubjectTypes ?? {},
      redirect_prefix_allowed_hosts: props.redirectPrefixAllowedHosts ?? {},
      tenant_admin_secret_arns: tenantAdminArns,
      scim_credential_secret_arn: null,
      scim_tenant_secret_arns: scimArns,
      tenant_residency: props.tenantResidency,
      tenant_secret_dependencies: tenantSecretDependencies,
    };
    const runtimeBootstrapDocumentString =
      Fn.toJsonString(runtimeBootstrapDocument);
    const runtimeBootstrapRevision = createHash('sha256')
      .update(JSON.stringify(this.resolve(runtimeBootstrapDocumentString)))
      .digest('hex')
      .slice(0, 16);

    const httpApi = new apigw.HttpApi(this, 'HttpApi', {
      description:
        'agent-auth replay-safe standby API; traffic is admitted by RegionControlTable',
      createDefaultStage: false,
    });
    const apiHost = Fn.select(1, Fn.split('://', httpApi.apiEndpoint));
    const runtimeEnvironment = {
        REGION_CONTROL_TABLE: regionControl.tableName,
        CODES_TABLE: local.codes.tableName,
        AUTH_REFS_TABLE: local.clientAuthorityRefs.tableName,
        CLIENTS_TABLE: authority.clients.tableName,
        INITIAL_ACCESS_TOKENS_TABLE: local.initialAccessTokens.tableName,
        REFRESH_TABLE: local.refresh.tableName,
        SESSIONS_TABLE: local.sessions.tableName,
        MAGICLINK_TABLE: local.magicLinks.tableName,
        INVITATIONS_TABLE: local.invitations.tableName,
        ...(invitationTtlSecs !== 86_400
          ? { AGENT_AUTH_INVITATION_TTL_SECS: String(invitationTtlSecs) }
          : {}),
        RECOVERY_TABLE: local.recovery.tableName,
        AUTHZ_SESSIONS_TABLE: local.authzSessions.tableName,
        AUTHZ_EVENT_BUS: authzEventBus.eventBusName,
        MESSAGES_TABLE: local.messages.tableName,
        SECURITY_EVENTS_TABLE: authority.securityEvents.tableName,
        SSF_DELIVERIES_TABLE: local.ssfDeliveries.tableName,
        AGENT_AUTH_SSF_MANAGEMENT_ENABLED: '0',
        SECURITY_EVENT_INGRESS_QUEUE_URL: securityEventIngressQueue.queueUrl,
        WORKLOAD_TRUST_TABLE: authority.workloadTrust.tableName,
        CIBA_TABLE: local.ciba.tableName,
        DEVICE_TABLE: local.device.tableName,
        GRANTS_TABLE: authority.grants.tableName,
        FEDERATION_CONFIG_TABLE: authority.federationConfig.tableName,
        FEDERATION_FLOW_TABLE: local.federationFlow.tableName,
        ADMIN_AUTH_TABLE: authority.adminAuth.tableName,
        ADMIN_AUTH_RUNTIME_TABLE: local.adminAuthRuntime.tableName,
        GOVERNANCE_TABLE: authority.governance.tableName,
        GOVERNANCE_SUPPRESSION_TABLE:
          authority.governanceSuppression.tableName,
        USERS_TABLE: authority.users.tableName,
        SCIM_GROUPS_TABLE: authority.scimGroups.tableName,
        PASSWORD_CREDENTIALS_TABLE: authority.passwordCredentials.tableName,
        ...(props.passkeyEnabled
          ? { AGENT_AUTH_PASSKEY_ENABLED: '1' }
          : {}),
        PASSKEY_TABLE: authority.passkeys.tableName,
        PASSKEY_CHALLENGE_TABLE: local.passkeyChallenges.tableName,
        PAR_TABLE: local.par.tableName,
        RATE_LIMIT_TABLE: local.rateLimit.tableName,
        AGENT_AUTH_DEPLOYMENT_COMMIT: props.deploymentCommit,
        AGENT_AUTH_PHASE: props.phase ?? 'p2',
        JTI_TABLE: local.jti.tableName,
        GRACE_TABLE: local.grace.tableName,
        CIBA_KMS: cibaNotificationKeyAlias,
        SERVER_SECRET: serverSecret.secretValue.unsafeUnwrap(),
        AGENT_AUTH_BOOTSTRAP_CONFIG_SECRET_ARN:
          runtimeBootstrapConfigSecret.secretArn,
        AGENT_AUTH_BOOTSTRAP_REVISION: runtimeBootstrapRevision,
        WEB_BASE_URL: webBaseUrl,
        AGENT_AUTH_STRONG_MAX_AGE_SECS: '300',
        AGENT_AUTH_HIGH_RISK_RAR_ACTIONS: 'transfer',
        AGENT_AUTH_HIGH_RISK_ADMIN_ACTIONS: 'access.manage',
        AGENT_AUTH_FORM: 'saas',
        AGENT_AUTH_ZONE: props.saasZone,
        AGENT_AUTH_CONTROL_HOST: props.saasControlHost,
        AGENT_AUTH_ENABLE_TENANT_PARTITIONING: '1',
        AGENT_AUTH_ORIGIN_AUTH_REVISION:
          props.saasOriginAuthRevision,
        TENANT_KEYS_TABLE: authority.tenantKeys.tableName,
        AGENT_AUTH_TENANT_KEY_COMMANDS_DISABLED: '1',
        ...(props.kmsTenantGateCapacity !== undefined
          ? {
              AGENT_AUTH_KMS_TENANT_GATE_CAPACITY: String(
                props.kmsTenantGateCapacity,
              ),
              AGENT_AUTH_KMS_TENANT_GATE_REFILL_PER_SEC: String(
                props.kmsTenantGateRefillPerSec ?? 20,
              ),
            }
          : {}),
        ...(props.authzEnabled ? { AGENT_AUTH_AUTHZ_ENABLED: '1' } : {}),
        ...(props.policySet ? { AGENT_AUTH_POLICY_SET: props.policySet } : {}),
        DOMAIN_MAP_TABLE: authority.domainMap.tableName,
        ...(props.byodEnabled ? { AGENT_AUTH_BYOD_ENABLED: '1' } : {}),
    };
    const authFnLogGroup = new logs.LogGroup(this, 'AuthFnLogGroup', {
      retention: logs.RetentionDays.SEVEN_YEARS,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    // 与 primary 相同的新逻辑资源切换，避免原地缩权产生 rolling window。
    const fn = new lambda.Function(this, 'NonTokenFn', {
      runtime: lambda.Runtime.PROVIDED_AL2023,
      architecture: lambda.Architecture.ARM_64,
      handler: 'bootstrap',
      code: lambda.Code.fromAsset(props.lambdaAssetPath),
      memorySize: 512,
      timeout: Duration.seconds(10),
      logGroup: authFnLogGroup,
      environment: {
        ...runtimeEnvironment,
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
        ...runtimeEnvironment,
        SCOPE: 'token',
        GRACE_KMS_KEY_ID: tokenGraceKey.keyId,
      },
    });
    const httpRuntimes = [fn, tokenFn] as const;

    for (const runtime of httpRuntimes) {
      for (const [role, table] of Object.entries(authority)) {
        if (
          role !== 'governanceSuppression' &&
          role !== 'attributeNamespaces' &&
          role !== 'federationAttributeMappings'
        ) {
          table.grantReadWriteData(runtime);
        }
      }
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:GetItem', 'dynamodb:Query'],
          resources: [authority.governanceSuppression.tableArn],
        }),
      );
      for (const [role, table] of Object.entries(local)) {
        if (role !== 'grace') {
          table.grantReadWriteData(runtime);
        }
      }
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactWriteItems'],
          resources: [
            local.codes.tableArn,
            local.refresh.tableArn,
            local.clientAuthorityRefs.tableArn,
            local.authzSessions.tableArn,
          ],
        }),
      );
    }
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['dynamodb:Query', 'dynamodb:DeleteItem'],
        resources: [local.grace.tableArn],
      }),
    );
    local.grace.grantReadWriteData(tokenFn);

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
          CODES_TABLE: local.codes.tableName,
          REFRESH_TABLE: local.refresh.tableName,
          AUTH_REFS_TABLE: local.clientAuthorityRefs.tableName,
          AGENT_AUTH_DEPLOYMENT_COMMIT: props.deploymentCommit,
        },
      },
    );
    local.codes.grantReadWriteData(authorityReferenceMigrationFn);
    local.refresh.grantReadWriteData(authorityReferenceMigrationFn);
    local.clientAuthorityRefs.grantReadWriteData(
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
          local.codes.tableArn,
          local.refresh.tableArn,
          local.clientAuthorityRefs.tableArn,
        ],
      }),
    );
    this.authorityReferenceMigrationHandler =
      authorityReferenceMigrationFn;
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
            'Standby migration scans the two Region-local source tables and writes only the dedicated Region-local reference table.',
        },
      ],
      true,
    );
    for (const runtime of httpRuntimes) {
      regionControl.grantReadData(runtime);
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['dynamodb:TransactGetItems'],
          resources: [regionControl.tableArn],
        }),
      );
      securityEventIngressQueue.grantSendMessages(runtime);
      authzEventBus.grantPutEventsTo(runtime);
      runtimeBootstrapConfigSecret.grantRead(runtime);
      cloudFrontOriginSecret.grantRead(runtime);
      cloudFrontOriginSecondarySecret.grantRead(runtime);
      governanceHmacSecret.grantRead(runtime);
      runtime.addToRolePolicy(
        new iam.PolicyStatement({
          actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
          resources: [cibaNotificationKey.keyArn],
        }),
      );
    }
    tokenFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['kms:GenerateDataKey', 'kms:Decrypt'],
        resources: [tokenGraceKey.keyArn],
      }),
    );
    const managedTenantKeyArn = Stack.of(this).formatArn({
      service: 'kms',
      resource: 'key',
      resourceName: '*',
    });
    const signingKeyRuntimePolicy = new iam.Policy(
      this,
      'SigningKeyRuntimePolicy',
      {
        statements: [
          new iam.PolicyStatement({
            actions: ['kms:Sign', 'kms:GetPublicKey'],
            resources: [managedTenantKeyArn],
            conditions: {
              StringEquals: { 'aws:ResourceTag/agent-auth-managed': 'true' },
            },
          }),
        ],
      },
    );
    for (const runtime of httpRuntimes) {
      signingKeyRuntimePolicy.attachToRole(runtime.role!);
    }
    NagSuppressions.addResourceSuppressions(
      signingKeyRuntimePolicy,
      [
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'Tenant signing keys are created after stack deployment, so their key IDs cannot be enumerated at synthesis. The resource wildcard is limited to KMS keys in this account and Region, requires the managed resource tag, and grants only Sign and GetPublicKey.',
          appliesTo: [
            `Resource::arn:<AWS::Partition>:kms:${this.region}:${this.account}:key/*`,
          ],
        },
      ],
      true,
    );
    const runtimeCredentialSecretArns = [
      platformAdminSecret.secretArn,
      ...Object.values(tenantAdminSecrets).map((secret) => secret.secretArn),
      ...Object.values(scimSecrets).map((secret) => secret.secretArn),
    ];
    const federationSecretPrefixArn =
      `arn:aws:secretsmanager:${this.region}:${this.account}:secret:agent-auth/federation/*`;
    const adminOidcSecretPrefixArn =
      `arn:aws:secretsmanager:${this.region}:${this.account}:secret:agent-auth/admin-oidc/*`;
    const adminCredentialRuntimePolicy = new iam.Policy(
      this,
      'AdminCredentialRuntimePolicy',
      {
        statements: [
          new iam.PolicyStatement({
            actions: [
              'secretsmanager:DescribeSecret',
              'secretsmanager:GetSecretValue',
            ],
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
            'Federation and Admin OIDC client secrets are selected from tenant configuration at runtime. Access is restricted to two dedicated Secrets Manager prefixes; Admin OIDC additionally requires the exact agent-auth/admin-oidc/<tenant> reference before any read.',
          appliesTo: [
            `Resource::${federationSecretPrefixArn}`,
            `Resource::${adminOidcSecretPrefixArn}`,
          ],
        },
      ],
      true,
    );

    const integration = new HttpLambdaIntegration(
      'StandbyNonTokenIntegration',
      fn,
    );
    const tokenIntegration = new HttpLambdaIntegration(
      'StandbyTokenIntegration',
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
    const accessLogs = new logs.LogGroup(this, 'ApiAccessLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const stage = new apigw.HttpStage(this, 'DefaultStage', {
      httpApi,
      stageName: '$default',
      autoDeploy: true,
    });
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

    new CfnOutput(this, 'ApiUrl', { value: httpApi.apiEndpoint });
    new CfnOutput(this, 'ApiHost', { value: apiHost });
    new CfnOutput(this, 'AuthFnName', { value: fn.functionName });
    new CfnOutput(this, 'TokenFnName', { value: tokenFn.functionName });
    new CfnOutput(this, 'GraceEnvelopeKeyId', { value: tokenGraceKey.keyId });
    new CfnOutput(this, 'LegacyGraceEnvelopeKeyId', {
      value: legacyGraceKey.keyId,
    });
    new CfnOutput(this, 'CibaNotificationEnvelopeKeyId', {
      value: cibaNotificationKey.keyId,
    });
    new CfnOutput(this, 'DeploymentCommit', {
      value: props.deploymentCommit,
    });
    new CfnOutput(this, 'AuthorityReferenceMigrationFnName', {
      value: authorityReferenceMigrationFn.functionName,
    });
    new CfnOutput(this, 'RegionId', { value: this.region });
    new CfnOutput(this, 'RegionControlTableName', {
      value: regionControl.tableName,
    });
    new CfnOutput(this, 'SecurityEventIngressQueueUrl', {
      value: securityEventIngressQueue.queueUrl,
    });
    new CfnOutput(this, 'SecurityEventIngressDlqUrl', {
      value: securityEventIngressDlq.queueUrl,
    });
    new CfnOutput(this, 'ImportedAuthorityTableNames', {
      value: Fn.toJsonString(props.authorityTableNames),
    });
    new CfnOutput(this, 'RegionLocalTableNames', {
      value: Fn.toJsonString(
        Object.fromEntries(
          Object.entries(local).map(([role, table]) => [role, table.tableName]),
        ),
      ),
    });
    const importedIndexWildcardResources = [
      authority.clients,
      authority.grants,
      authority.passkeys,
      authority.securityEvents,
      authority.users,
      authority.scimGroups,
      authority.domainMap,
    ].map(
      (table) =>
        `Resource::arn:<AWS::Partition>:dynamodb:${this.region}:${this.account}:table/${table.tableName}/index/*`,
    );
    const localIndexWildcardResources = [
      local.codes,
      local.refresh,
      local.sessions,
      local.authzSessions,
      local.device,
      local.ssfDeliveries,
    ].map((table) => {
      const logicalId = this.getLogicalId(
        table.node.defaultChild as CfnElement,
      );
      return `Resource::<${logicalId}.Arn>/index/*`;
    });
    NagSuppressions.addStackSuppressions(this, [
      {
        id: 'AwsSolutions-IAM5',
        reason:
          'DynamoDB Query requires index suffix access. Every listed wildcard is scoped to one imported authority or Region-local table that declares an index; CDK may move these grants into generated overflow policies.',
        appliesTo: [
          ...importedIndexWildcardResources,
          ...localIndexWildcardResources,
        ],
      },
    ]);
    for (const runtime of httpRuntimes) {
      NagSuppressions.addResourceSuppressions(
        runtime.role!,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason:
              'The standby HTTP Lambda basic role writes only its retained CloudWatch log group; business access is explicit and route-scoped.',
            appliesTo: [
              'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
            ],
          },
        ],
      );
    }
    NagSuppressions.addResourceSuppressions(securityEventIngressDlq, [
      {
        id: 'AwsSolutions-SQS3',
        reason:
          'This encrypted 14-day queue is the terminal incident destination for standby security-event ingress failures; chaining another dead-letter queue would not improve recoverability.',
      },
    ]);
    NagSuppressions.addResourceSuppressions(
      httpApi,
      [
        {
          id: 'AwsSolutions-APIG4',
          reason:
            'OAuth/OIDC protocol endpoints enforce client authentication, PKCE, bearer authorization, and tenant Admin authorization in the application layer. Discovery and JWKS are intentionally public read-only endpoints, so an API Gateway authorizer is not applicable.',
        },
      ],
      true,
    );
  }
}

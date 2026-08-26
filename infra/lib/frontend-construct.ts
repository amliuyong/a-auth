import * as path from 'node:path';
import { RemovalPolicy, Duration, CfnOutput } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53targets from 'aws-cdk-lib/aws-route53-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
import { Stack, CfnElement } from 'aws-cdk-lib';
import { NagSuppressions } from 'cdk-nag';

export const FORWARD_HOST_FUNCTION_CODE =
  'function handler(event){ var h=event.request.headers; if(h.host){ h["x-forwarded-host"]={value:h.host.value}; } return event.request; }';

/**
 * 前端 SPA 托管 + **CloudFront 统一入口**(spec 025):私有 S3(OAC)静态 + API Gateway origin 同域。
 *
 * 路由策略(spec 025,防 API 404 被 SPA fallback 吞 + 同-path 异-method 冲突):
 * - **default behavior(`*`)→ API Gateway origin**,**无** error-response fallback(API 的 404/400 是
 *   合法业务响应,原样返回 JSON)。
 * - **静态 SPA 路径显式 behavior → S3**:精确 `/`、`/login`、`/invite`、`/consent`、`/recover`、
 *   `/account`、`/approve`、`/admin`,加 `/assets/*`、`/favicon.ico`。页面 behavior 由
 *   viewer-request function 重写到 `/index.html`,API 错误不参与 history fallback。
 * - 冲突已在后端消除:批准/验码动作改挂 `/consent/decision`、`/recovery/verify`(落 default→API);
 *   授权管理/批准动作走 `/grants`、`/device`、`/bc-approve`(API),SPA 页用 `/account`、`/approve`
 *   (与页/动作分离一致);admin SPA 只用 `/admin` 单 path(tab 走组件 state)。
 *
 * 同源收益:cookie(`__Host-`)/consent anti-CSRF 天然正确(C10.21/C10.9),且修复前后端分域导致的
 * "登录页调 API 失败"。未传 apiOrigin 时退化为纯静态托管(仅 S3 default,兼容旧行为)。
 * 决策真相源:spec 025「同一 CloudFront 统一入口」+ DESIGN §8 架构图。clickjacking 头见 C10.9b。
 */
export class FrontendConstruct extends Construct {
  readonly distributionDomain: string;
  readonly distributionId: string;
  readonly registrationWebAclArn?: string;
  readonly registrationWafLogGroupName?: string;

  constructor(
    scope: Construct,
    id: string,
    props: {
      assetPath?: string;
      apiDomain?: string;
      /**
       * Dual-slot SaaS edge credentials. Lambda@Edge injects their current
       * values so the distribution configuration never stores either secret.
       */
      apiOriginAuth?: {
        primarySecret: secretsmanager.ISecret;
        secondarySecret: secretsmanager.ISecret;
        revision: string;
      };
      registrationWaf?: {
        deploymentCommit: string;
        ipLimit?: number;
        hostLimit?: number;
        asnLimit?: number;
      };
      // 自定义域名(spec 003 §4 联邦真机 / spec 025):CloudFront 别名 + ACM 证书(us-east-1)+ Route53 alias。
      // 三者齐备才启用;缺任一则退化为 *.cloudfront.net 默认域(不破坏既有部署)。
      customDomain?: string;
      // SaaS 多子域(spec 020):CloudFront 别名要覆盖的全部 host(t1/t2/c.<zone>);为每个建 Route53 alias。
      // 留空则回落到单个 customDomain。证书(certArn)须覆盖这里每一个 host(SAN 或通配)。
      customDomains?: string[];
      certArn?: string;
      hostedZoneId?: string;
      hostedZoneName?: string;
    },
  ) {
    super(scope, id);

    const stack = Stack.of(this);
    const assetPath =
      props.assetPath ?? path.resolve(__dirname, '..', '..', 'web', 'dist');

    // 私有桶:仅 CloudFront(OAC)可读,不公开、强制 SSL。
    const bucket = new s3.Bucket(this, 'SpaBucket', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: RemovalPolicy.DESTROY, // dev 栈可拆
      autoDeleteObjects: true,
    });

    // 安全响应头(C10.9b clickjacking + 纵深):所有交互页响应都带。
    const securityHeaders = new cloudfront.ResponseHeadersPolicy(this, 'SecurityHeaders', {
      securityHeadersBehavior: {
        frameOptions: {
          frameOption: cloudfront.HeadersFrameOption.DENY, // X-Frame-Options: DENY
          override: true,
        },
        contentSecurityPolicy: {
          // 交互页 CSP:禁 iframe 嵌套(frame-ancestors 'none',C10.9b);限制资源来源。
          contentSecurityPolicy:
            "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; " +
            "img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; " +
            "connect-src 'self'",
          override: true,
        },
        contentTypeOptions: { override: true }, // X-Content-Type-Options: nosniff
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
          override: true,
        },
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(365),
          includeSubdomains: true,
          override: true,
        },
      },
    });

    // S3 静态 behavior(OAC 私有桶 + 安全头 + 缓存优化)。
    const s3Origin = origins.S3BucketOrigin.withOriginAccessControl(bucket);
    const s3Behavior: cloudfront.BehaviorOptions = {
      origin: s3Origin,
      viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      responseHeadersPolicy: securityHeaders,
      cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
    };

    const hasApi = !!props.apiDomain;

    // SPA 页面路径重写函数(viewer-request):S3 无 `/login` 等对象(SPA 客户端路由),把这些**页面
    // path** 重写到 `/index.html`(SPA 壳),客户端再解析路由。仅挂在页面 behavior 上——`/assets/*`、
    // `/favicon.ico` 是真实对象不重写。**不能**用 distribution 级 errorResponses(那是全局,会把
    // default→API 的 404/400 也改写成 index.html,吞掉 API 错误,spec 025)。
    const spaRewrite = hasApi
      ? new cloudfront.Function(this, 'SpaRewrite', {
          code: cloudfront.FunctionCode.fromInline(
            'function handler(event){ event.request.uri = "/index.html"; return event.request; }',
          ),
          comment: 'rewrite SPA page paths to /index.html (client-side routing)',
        })
      : undefined;
    const pageBehavior: cloudfront.BehaviorOptions = spaRewrite
      ? {
          ...s3Behavior,
          functionAssociations: [
            { function: spaRewrite, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST },
          ],
        }
      : s3Behavior;

    // 统一入口:default→API Gateway(不缓存、转发全部;API 自带认证);无 apiDomain 时退化为 S3 default。
    let defaultBehavior: cloudfront.BehaviorOptions;
    const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {};
    if (hasApi) {
      const apiOrigin = new origins.HttpOrigin(props.apiDomain!, {
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
      });
      // ⚠️ issuer host 透传(spec 025 H1):后端从 host 派生 OIDC issuer(C1.6a),但转发到 API Gateway
      // 时 `Host` MUST = API Gateway 自身域名(否则 $default stage 路由不到)。默认 CloudFront 域和
      // 自定义域都把 viewer `Host` 复制进 `X-Forwarded-Host`,并覆盖 viewer 自带值防伪造。
      const forwardHost = new cloudfront.Function(this, 'ForwardHost', {
        code: cloudfront.FunctionCode.fromInline(FORWARD_HOST_FUNCTION_CODE),
        comment: 'copy viewer Host to X-Forwarded-Host for backend issuer derivation',
      });
      const originAuthEdgeRole = props.apiOriginAuth
        ? new iam.Role(this, 'OriginAuthEdgeRole', {
            assumedBy: new iam.CompositePrincipal(
              new iam.ServicePrincipal('lambda.amazonaws.com'),
              new iam.ServicePrincipal('edgelambda.amazonaws.com'),
            ),
            description:
              'Least-privilege execution role for SaaS origin authentication at Lambda@Edge',
          })
        : undefined;
      if (originAuthEdgeRole) {
        originAuthEdgeRole.addToPolicy(
          new iam.PolicyStatement({
            actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
            resources: [
              `arn:${stack.partition}:logs:*:${stack.account}:log-group:/aws/lambda/*`,
              `arn:${stack.partition}:logs:*:${stack.account}:log-group:/aws/lambda/*:*`,
            ],
          }),
        );
        NagSuppressions.addResourceSuppressions(
          originAuthEdgeRole,
          [
            {
              id: 'AwsSolutions-IAM5',
              reason:
                'Lambda@Edge replicas execute in viewer Regions chosen by CloudFront, so log-group ARNs require a Region and function-name wildcard; access remains limited to this account and /aws/lambda/* logs.',
              appliesTo: [
                `Resource::arn:<AWS::Partition>:logs:*:${stack.account}:log-group:/aws/lambda/*`,
                `Resource::arn:<AWS::Partition>:logs:*:${stack.account}:log-group:/aws/lambda/*:*`,
              ],
            },
          ],
          true,
        );
      }
      const originAuthEdge = props.apiOriginAuth
        ? new cloudfront.experimental.EdgeFunction(this, 'OriginAuthEdge', {
            runtime: lambda.Runtime.NODEJS_24_X,
            handler: 'index.handler',
            code: lambda.Code.fromInline(
              originAuthEdgeCode(
                props.apiOriginAuth.primarySecret.secretArn,
                props.apiOriginAuth.secondarySecret.secretArn,
                props.apiOriginAuth.revision,
              ),
            ),
            timeout: Duration.seconds(5),
            memorySize: 128,
            role: originAuthEdgeRole,
            description:
              'Inject managed SaaS origin credentials without storing them in CloudFront',
          })
        : undefined;
      if (originAuthEdge && props.apiOriginAuth) {
        props.apiOriginAuth.primarySecret.grantRead(originAuthEdge);
        props.apiOriginAuth.secondarySecret.grantRead(originAuthEdge);
      }
      const functionAssociations = [
        { function: forwardHost, eventType: cloudfront.FunctionEventType.VIEWER_REQUEST },
      ];
      const edgeLambdas = originAuthEdge
        ? [
            {
              functionVersion: originAuthEdge,
              eventType: cloudfront.LambdaEdgeEventType.ORIGIN_REQUEST,
            },
          ]
        : undefined;
      // API 端点:全转发(含 Authorization/Cookie/查询串)、不缓存;API 的 404/400 原样返回 JSON。
      const apiBehavior: cloudfront.BehaviorOptions = {
        origin: apiOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: securityHeaders,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        // 转发除 Host 外的头(Host 须为 origin 自身域名,否则 API Gateway $default 路由不到);
        // ALL_VIEWER_EXCEPT_HOST_HEADER 带上 Authorization/Cookie/查询串,同源 cookie 生效。
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL, // 含 POST/PUT/PATCH/DELETE
        functionAssociations,
        ...(edgeLambdas ? { edgeLambdas } : {}),
      };
      defaultBehavior = apiBehavior; // default(`*`)→ API,天然覆盖所有未列举 API path(含未来 /revoke)
      const jwksCachePolicy = new cloudfront.CachePolicy(this, 'JwksCachePolicy', {
        comment: 'C10.16 frozen five-minute JWKS cache with tenant-host isolation',
        minTtl: Duration.seconds(300),
        defaultTtl: Duration.seconds(300),
        maxTtl: Duration.seconds(300),
        headerBehavior: cloudfront.CacheHeaderBehavior.allowList('x-forwarded-host'),
        cookieBehavior: cloudfront.CacheCookieBehavior.none(),
        queryStringBehavior: cloudfront.CacheQueryStringBehavior.none(),
        enableAcceptEncodingGzip: true,
        enableAcceptEncodingBrotli: true,
      });
      additionalBehaviors['/jwks.json'] = {
        origin: apiOrigin,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy: securityHeaders,
        cachePolicy: jwksCachePolicy,
        originRequestPolicy: cloudfront.OriginRequestPolicy.CORS_CUSTOM_ORIGIN,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD,
        functionAssociations,
        ...(edgeLambdas ? { edgeLambdas } : {}),
      };
      // 静态 SPA 页面 path 显式列举 → S3 + 重写到 index.html(SPA 各页面为扁平精确 path)。
      // 含根路径 `/`(裸域名进 SPA;defaultRootObject 只在源对象查找起作用,不改 behavior 选择,
      // 故 `/` MUST 显式挂 S3 否则落 default→API,spec 025 M5)。
      for (const p of ['/', '/login', '/invite', '/consent', '/recover', '/account', '/approve', '/admin', '/error']) {
        additionalBehaviors[p] = pageBehavior;
      }
      additionalBehaviors['/index.html'] = s3Behavior;
      additionalBehaviors['/assets/*'] = s3Behavior; // 打包资源(真实对象,不重写)
      additionalBehaviors['/favicon.ico'] = s3Behavior;
    } else {
      defaultBehavior = s3Behavior; // 纯静态托管(旧行为)
    }

    // 自定义域名:证书 + 至少一个 host 才挂(alias + ACM 证书);证书 MUST us-east-1(CloudFront 约束)。
    // SaaS:customDomains 列全部子域(t1/t2/c.<zone>);否则回落单个 customDomain。
    const domainList = (
      props.customDomains && props.customDomains.length > 0
        ? props.customDomains
        : props.customDomain
          ? [props.customDomain]
          : []
    ).filter((d): d is string => !!d);
    const useCustomDomain = !!(domainList.length > 0 && props.certArn);
    const domainCert = useCustomDomain
      ? acm.Certificate.fromCertificateArn(this, 'CustomCert', props.certArn!)
      : undefined;

    const registrationWaf = props.registrationWaf;
    if (registrationWaf && stack.region !== 'us-east-1') {
      throw new Error('CloudFront registration WAF must be created in us-east-1');
    }
    if (
      registrationWaf &&
      !/^[0-9a-f]{40}$/.test(registrationWaf.deploymentCommit)
    ) {
      throw new Error(
        'registrationWaf.deploymentCommit must be a full lowercase Git SHA',
      );
    }
    const registerRequestStatements: wafv2.CfnWebACL.StatementProperty[] = [
      {
        byteMatchStatement: {
          fieldToMatch: { method: {} },
          positionalConstraint: 'EXACTLY',
          searchString: 'POST',
          textTransformations: [{ priority: 0, type: 'NONE' }],
        },
      },
      {
        byteMatchStatement: {
          fieldToMatch: { uriPath: {} },
          positionalConstraint: 'EXACTLY',
          searchString: '/register',
          textTransformations: [{ priority: 0, type: 'NONE' }],
        },
      },
    ];
    const visibility = (metricName: string): wafv2.CfnWebACL.VisibilityConfigProperty => ({
      cloudWatchMetricsEnabled: true,
      metricName,
      sampledRequestsEnabled: false,
    });
    const webAcl = registrationWaf
      ? new wafv2.CfnWebACL(this, 'RegistrationWebAcl', {
          defaultAction: { allow: {} },
          scope: 'CLOUDFRONT',
          visibilityConfig: visibility('AgentAuthRegistrationWaf'),
          rules: [
            {
              name: 'RegistrationProbe',
              priority: 0,
              action: { block: {} },
              statement: {
                andStatement: {
                  statements: [
                    ...registerRequestStatements,
                    {
                      byteMatchStatement: {
                        fieldToMatch: {
                          singleHeader: { Name: 'x-agent-auth-waf-probe' },
                        },
                        positionalConstraint: 'EXACTLY',
                        searchString: `c10-8-${registrationWaf.deploymentCommit}`,
                        textTransformations: [{ priority: 0, type: 'NONE' }],
                      },
                    },
                  ],
                },
              },
              visibilityConfig: visibility('AgentAuthRegistrationProbe'),
            },
            {
              name: 'RegistrationIpRateLimit',
              priority: 10,
              action: { block: {} },
              statement: {
                rateBasedStatement: {
                  aggregateKeyType: 'IP',
                  evaluationWindowSec: 60,
                  limit: registrationWaf.ipLimit ?? 100,
                  scopeDownStatement: {
                    andStatement: { statements: registerRequestStatements },
                  },
                },
              },
              visibilityConfig: visibility('AgentAuthRegistrationIpRate'),
            },
            {
              name: 'RegistrationHostRateLimit',
              priority: 20,
              action: { block: {} },
              statement: {
                rateBasedStatement: {
                  aggregateKeyType: 'CUSTOM_KEYS',
                  customKeys: [
                    {
                      header: {
                        name: 'host',
                        textTransformations: [{ priority: 0, type: 'LOWERCASE' }],
                      },
                    },
                  ],
                  evaluationWindowSec: 60,
                  limit: registrationWaf.hostLimit ?? 300,
                  scopeDownStatement: {
                    andStatement: { statements: registerRequestStatements },
                  },
                },
              },
              visibilityConfig: visibility('AgentAuthRegistrationHostRate'),
            },
            {
              name: 'RegistrationAsnRateLimit',
              priority: 30,
              action: { block: {} },
              statement: {
                rateBasedStatement: {
                  aggregateKeyType: 'CUSTOM_KEYS',
                  customKeys: [{ asn: {} }],
                  evaluationWindowSec: 60,
                  limit: registrationWaf.asnLimit ?? 1000,
                  scopeDownStatement: {
                    andStatement: { statements: registerRequestStatements },
                  },
                },
              },
              visibilityConfig: visibility('AgentAuthRegistrationAsnRate'),
            },
          ],
        })
      : undefined;
    if (webAcl) {
      const wafLogGroup = new logs.LogGroup(this, 'RegistrationWafLogGroup', {
        logGroupName: `aws-waf-logs-${stack.stackName}-register`,
        retention: logs.RetentionDays.ONE_MONTH,
        removalPolicy: RemovalPolicy.DESTROY,
      });
      new wafv2.CfnLoggingConfiguration(this, 'RegistrationWafLogging', {
        resourceArn: webAcl.attrArn,
        logDestinationConfigs: [wafLogGroup.logGroupArn],
        loggingFilter: {
          DefaultBehavior: 'DROP',
          Filters: [
            {
              Behavior: 'KEEP',
              Requirement: 'MEETS_ANY',
              Conditions: [{ ActionCondition: { Action: 'BLOCK' } }],
            },
          ],
        },
        redactedFields: [
          { singleHeader: { Name: 'authorization' } },
          { singleHeader: { Name: 'cookie' } },
          { singleHeader: { Name: 'proxy-authorization' } },
          { singleHeader: { Name: 'x-api-key' } },
          { queryString: {} },
        ],
      });
      this.registrationWebAclArn = webAcl.attrArn;
      this.registrationWafLogGroupName = wafLogGroup.logGroupName;
    }

    const distribution = new cloudfront.Distribution(this, 'SpaDistribution', {
      defaultBehavior,
      additionalBehaviors,
      defaultRootObject: 'index.html',
      ...(webAcl ? { webAclId: webAcl.attrArn } : {}),
      ...(useCustomDomain
        ? { domainNames: domainList, certificate: domainCert }
        : {}),
      // history fallback:仅**纯静态**(default=S3)时用全局 errorResponses(403/404→index.html)。
      // 统一入口下 default=API,404/403 是合法 API 响应,MUST NOT 全局改写(否则吞 API 错误);SPA 页面
      // 的 index.html 回退改由 spaRewrite 函数按页面 behavior 精确处理(spec 025)。
      errorResponses: hasApi
        ? []
        : [
            {
              httpStatus: 403,
              responseHttpStatus: 200,
              responsePagePath: '/index.html',
              ttl: Duration.seconds(0),
            },
            {
              httpStatus: 404,
              responseHttpStatus: 200,
              responsePagePath: '/index.html',
              ttl: Duration.seconds(0),
            },
          ],
      comment: hasApi
        ? 'agent-auth unified entry (default→API, static→S3, security headers)'
        : 'agent-auth SPA (history fallback + security headers)',
    });

    // 部署 web/dist → 桶,并失效 CloudFront 缓存。
    new s3deploy.BucketDeployment(this, 'DeploySpa', {
      sources: [s3deploy.Source.asset(assetPath)],
      destinationBucket: bucket,
      distribution,
      distributionPaths: ['/*'],
    });

    this.distributionDomain = distribution.distributionDomainName;
    this.distributionId = distribution.distributionId;
    new CfnOutput(this, 'SpaUrl', { value: `https://${distribution.distributionDomainName}` });

    // 自定义域名 → CloudFront 的 Route53 A/AAAA alias(域名 zone 齐备才建)。
    // SaaS:为 domainList 里**每个**子域(t1/t2/c.<zone>)各建一组 A/AAAA alias 指向同一 distribution。
    if (useCustomDomain && props.hostedZoneId && props.hostedZoneName) {
      const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'FedZone', {
        hostedZoneId: props.hostedZoneId,
        zoneName: props.hostedZoneName,
      });
      const target = route53.RecordTarget.fromAlias(
        new route53targets.CloudFrontTarget(distribution),
      );
      domainList.forEach((domain, i) => {
        // 构造 id 用子域首标签(t1/t2/c),稳定且互不冲突。
        const label = domain.split('.')[0] || `d${i}`;
        new route53.ARecord(this, `CustomDomainA-${label}`, {
          zone,
          recordName: domain,
          target,
        });
        new route53.AaaaRecord(this, `CustomDomainAAAA-${label}`, {
          zone,
          recordName: domain,
          target,
        });
        new CfnOutput(this, `CustomDomainUrl-${label}`, { value: `https://${domain}` });
      });
    }

    // cdk-nag 有据抑制。
    NagSuppressions.addResourceSuppressions(
      bucket,
      [
        {
          id: 'AwsSolutions-S1',
          reason: 'SPA 静态资源桶:访问经 CloudFront(有 access log 可在分发层开);桶本身私有 OAC、无直接公网面,S3 server access log 非必需。',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      distribution,
      [
        {
          id: 'AwsSolutions-CFR1',
          reason: 'P0 dev:未做地理限制(SPA 全球可访问是预期);生产按需加 geo restriction。',
        },
        ...(!webAcl
          ? [
              {
                id: 'AwsSolutions-CFR2',
                reason:
                  'Pure-static/test deployments may omit the registration WAF; deployable Dev and SaaS stacks enable it explicitly.',
              },
            ]
          : []),
        {
          id: 'AwsSolutions-CFR4',
          reason: 'CloudFront 默认证书 (*.cloudfront.net) 强制 TLSv1.2+(REDIRECT_TO_HTTPS);自定义域名+更高 TLS 策略随生产域名接入。',
        },
        {
          id: 'AwsSolutions-CFR3',
          reason: 'P0 dev:CloudFront access log 未开(静态 SPA;OAuth 端点 access log 在 API Gateway 侧已开)。生产按需开。',
        },
      ],
      true,
    );

    // BucketDeployment / AutoDeleteObjects 是 **CDK 框架托管的自定义资源**(把 asset 拷进桶 / destroy
    // 时清桶),其 Lambda 角色的 IAM4(basic execution)/IAM5(s3:GetObject*/List* 等通配,限于
    // CDK asset 桶 + 本 SPA 桶)/ L1(运行时由框架钉)均属框架实现、非业务角色,按路径抑制并说明。
    // SPA 桶的 CFN 逻辑 id(用于匹配 cdk-nag finding 里的 `<...Bucket....Arn>/*` token)。
    const bucketLogicalId = stack.getLogicalId(bucket.node.defaultChild as CfnElement);
    for (const p of [
      `${stack.stackName}/Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C`,
      `${stack.stackName}/Custom::S3AutoDeleteObjectsCustomResourceProvider`,
    ]) {
      NagSuppressions.addResourceSuppressionsByPath(
        stack,
        p,
        [
          {
            id: 'AwsSolutions-IAM4',
            reason: 'CDK 框架托管的部署/清桶 Lambda,用 AWSLambdaBasicExecutionRole 写 CloudWatch Logs(框架实现,非业务角色)。',
          },
          {
            id: 'AwsSolutions-IAM5',
            reason: 'CDK BucketDeployment/AutoDelete 的通配限于 CDK asset 桶 + 本 SPA 桶(拷贝/清理所需),框架控制、非跨资源。',
            // 具体 Resource 通配从运行时 token 拼(不把账号号硬编码进源码):CDK asset 桶(bootstrap
            // 命名 cdk-<qualifier>-assets-<account>-<region>)+ 本 SPA 桶,均限于拷贝/清理所需前缀。
            appliesTo: [
              'Action::s3:GetBucket*',
              'Action::s3:GetObject*',
              'Action::s3:List*',
              'Action::s3:Abort*',
              'Action::s3:DeleteObject*',
              'Resource::*',
              `Resource::arn:<AWS::Partition>:s3:::cdk-hnb659fds-assets-${stack.account}-${stack.region}/*`,
              `Resource::<${bucketLogicalId}.Arn>/*`,
            ],
          },
          {
            id: 'AwsSolutions-L1',
            reason: 'CDK 框架托管自定义资源的运行时由 aws-cdk-lib 版本钉定,随 CDK 升级,非业务可控。',
          },
        ],
        true,
      );
    }
  }
}

export function originAuthEdgeCode(
  primarySecretId: string,
  secondarySecretId: string,
  revision: string,
): string {
  return `'use strict';
const { GetSecretValueCommand, SecretsManagerClient } = require('@aws-sdk/client-secrets-manager');
const client = new SecretsManagerClient({ region: 'us-east-1' });
const secretIds = ${JSON.stringify([primarySecretId, secondarySecretId])};
const revision = ${JSON.stringify(revision)};
const cacheTtlMs = 30000;
let cached;
let expiresAt = 0;

async function credentials() {
  const now = Date.now();
  if (cached && now < expiresAt) return cached;
  const values = await Promise.all(secretIds.map(async (SecretId) => {
    const result = await client.send(new GetSecretValueCommand({ SecretId }));
    if (typeof result.SecretString !== 'string' || result.SecretString.length < 32) {
      throw new Error('managed origin credential is missing or too short');
    }
    return result.SecretString;
  }));
  if (values[0] === values[1]) throw new Error('managed origin credentials must be distinct');
  cached = values;
  expiresAt = now + cacheTtlMs;
  return values;
}

exports.handler = async (event) => {
  const request = event.Records[0].cf.request;
  const [primary, secondary] = await credentials();
  request.headers['x-agent-auth-origin-auth'] =
    [{ key: 'X-Agent-Auth-Origin-Auth', value: primary }];
  request.headers['x-agent-auth-origin-auth-primary'] =
    [{ key: 'X-Agent-Auth-Origin-Auth-Primary', value: primary }];
  request.headers['x-agent-auth-origin-auth-secondary'] =
    [{ key: 'X-Agent-Auth-Origin-Auth-Secondary', value: secondary }];
  request.headers['x-agent-auth-origin-auth-revision'] =
    [{ key: 'X-Agent-Auth-Origin-Auth-Revision', value: revision }];
  return request;
};
`;
}

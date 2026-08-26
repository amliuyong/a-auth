import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as apigw from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { NagSuppressions } from 'cdk-nag';

const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const ASSERTION_CLIENT_ID = 'agent-auth-ema-simulator-client';
const BROKER_CLIENT_ID = 'agent-auth-ema-simulator-broker';
const TEST_USERNAME = 'ema-simulator-user';

export interface EmaSimulatorStackProps extends StackProps {
  readonly agentAuthIssuers: readonly string[];
  readonly simulatorCommit: string;
}

function normalizedHttpsIssuer(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`invalid Agent Auth issuer: ${value}`);
  }
  if (
    url.protocol !== 'https:' ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(`Agent Auth issuer must be an absolute HTTPS URL: ${value}`);
  }
  return url.href.replace(/\/$/, '');
}

function addAccessLogs(scope: Construct, api: apigw.HttpApi, id: string): void {
  const logGroup = new logs.LogGroup(scope, `${id}AccessLogs`, {
    retention: logs.RetentionDays.ONE_MONTH,
    removalPolicy: RemovalPolicy.DESTROY,
  });
  const stage = new apigw.HttpStage(scope, `${id}DefaultStage`, {
    httpApi: api,
    stageName: '$default',
    autoDeploy: true,
  });
  const cfnStage = stage.node.defaultChild as apigw.CfnStage;
  cfnStage.accessLogSettings = {
    destinationArn: logGroup.logGroupArn,
    format: JSON.stringify({
      requestId: '$context.requestId',
      ip: '$context.identity.sourceIp',
      method: '$context.httpMethod',
      path: '$context.path',
      status: '$context.status',
      responseLength: '$context.responseLength',
    }),
  };
}

export class EmaSimulatorStack extends Stack {
  constructor(
    scope: Construct,
    id: string,
    props: EmaSimulatorStackProps,
  ) {
    super(scope, id, props);

    if (!COMMIT_PATTERN.test(props.simulatorCommit)) {
      throw new Error('simulatorCommit must be a full lowercase Git SHA');
    }
    const agentAuthIssuers = [
      ...new Set(props.agentAuthIssuers.map(normalizedHttpsIssuer)),
    ];
    if (agentAuthIssuers.length === 0) {
      throw new Error('agentAuthIssuers must not be empty');
    }

    const userPool = new cognito.UserPool(this, 'IdentitySource', {
      selfSignUpEnabled: false,
      signInAliases: { username: true },
      passwordPolicy: {
        minLength: 16,
        requireDigits: true,
        requireLowercase: true,
        requireSymbols: true,
        requireUppercase: true,
      },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const userPoolClient = userPool.addClient('IdentitySourceClient', {
      authFlows: { userPassword: true },
      generateSecret: false,
      preventUserExistenceErrors: true,
      idTokenValidity: Duration.minutes(60),
      accessTokenValidity: Duration.minutes(60),
      refreshTokenValidity: Duration.days(1),
    });

    const testUserPassword = new secretsmanager.Secret(
      this,
      'TestUserPassword',
      {
        generateSecretString: {
          secretStringTemplate: JSON.stringify({ username: TEST_USERNAME }),
          generateStringKey: 'password',
          passwordLength: 32,
          excludeCharacters: '"\'\\`$',
        },
        removalPolicy: RemovalPolicy.DESTROY,
      },
    );
    const brokerSecret = new secretsmanager.Secret(this, 'BrokerSecret', {
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          client_id: BROKER_CLIENT_ID,
        }),
        generateStringKey: 'client_secret',
        passwordLength: 48,
        excludePunctuation: true,
      },
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const signingKey = new kms.Key(this, 'IdJagSigningKey', {
      keySpec: kms.KeySpec.ECC_NIST_P256,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
      enableKeyRotation: false,
      removalPolicy: RemovalPolicy.DESTROY,
      pendingWindow: Duration.days(7),
      description:
        'Temporary ES256 key for transparent Agent Auth EMA simulator evidence',
    });

    const issuerApi = new apigw.HttpApi(this, 'IssuerApi', {
      description:
        'Authenticated test-only ID-JAG issuer backed by Cognito identity',
      createDefaultStage: false,
    });
    const resourceApi = new apigw.HttpApi(this, 'ResourceApi', {
      description:
        'Bearer-protected test-only resource server for EMA acceptance',
      createDefaultStage: false,
    });
    addAccessLogs(this, issuerApi, 'IssuerApi');
    addAccessLogs(this, resourceApi, 'ResourceApi');

    const cognitoIssuer = `https://cognito-idp.${this.region}.${this.urlSuffix}/${userPool.userPoolId}`;
    const functionAsset = [
      path.resolve(__dirname, '..', 'functions', 'ema-simulator'),
      path.resolve(__dirname, '..', '..', 'functions', 'ema-simulator'),
    ].find((candidate) => fs.existsSync(candidate));
    if (!functionAsset) {
      throw new Error('EMA simulator Lambda source directory is missing');
    }
    const issuerLogGroup = new logs.LogGroup(this, 'IssuerFunctionLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const issuerRole = new iam.Role(this, 'IssuerFunctionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    issuerLogGroup.grantWrite(issuerRole);
    const issuerFunction = new lambda.Function(this, 'IssuerFunction', {
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      handler: 'issuer.handler',
      code: lambda.Code.fromAsset(functionAsset),
      memorySize: 256,
      timeout: Duration.seconds(15),
      logGroup: issuerLogGroup,
      role: issuerRole,
      environment: {
        ISSUER: issuerApi.apiEndpoint,
        RESOURCE: resourceApi.apiEndpoint,
        ASSERTION_CLIENT_ID,
        ALLOWED_AGENT_AUTH_ISSUERS: agentAuthIssuers.join(','),
        ALLOWED_SCOPES: 'mcp:read',
        COGNITO_ISSUER: cognitoIssuer,
        COGNITO_JWKS_URI: `${cognitoIssuer}/.well-known/jwks.json`,
        COGNITO_CLIENT_ID: userPoolClient.userPoolClientId,
        BROKER_SECRET_ARN: brokerSecret.secretArn,
        KMS_KEY_ID: signingKey.keyId,
      },
    });
    brokerSecret.grantRead(issuerFunction);
    signingKey.grant(issuerFunction, 'kms:Sign', 'kms:GetPublicKey');

    const resourceLogGroup = new logs.LogGroup(this, 'ResourceFunctionLogs', {
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: RemovalPolicy.DESTROY,
    });
    const resourceRole = new iam.Role(this, 'ResourceFunctionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    resourceLogGroup.grantWrite(resourceRole);
    const resourceFunction = new lambda.Function(this, 'ResourceFunction', {
      runtime: lambda.Runtime.NODEJS_24_X,
      architecture: lambda.Architecture.ARM_64,
      handler: 'rs.handler',
      code: lambda.Code.fromAsset(functionAsset),
      memorySize: 256,
      timeout: Duration.seconds(10),
      logGroup: resourceLogGroup,
      role: resourceRole,
      environment: {
        RESOURCE: resourceApi.apiEndpoint,
        ALLOWED_AGENT_AUTH_ISSUERS: agentAuthIssuers.join(','),
      },
    });

    const issuerIntegration = new HttpLambdaIntegration(
      'IssuerIntegration',
      issuerFunction,
    );
    issuerApi.addRoutes({
      path: '/token',
      methods: [apigw.HttpMethod.POST],
      integration: issuerIntegration,
    });
    issuerApi.addRoutes({
      path: '/jwks.json',
      methods: [apigw.HttpMethod.GET],
      integration: issuerIntegration,
    });
    const resourceIntegration = new HttpLambdaIntegration(
      'ResourceIntegration',
      resourceFunction,
    );
    for (const route of ['/allow', '/deny']) {
      resourceApi.addRoutes({
        path: route,
        methods: [apigw.HttpMethod.GET],
        integration: resourceIntegration,
      });
    }

    for (const api of [issuerApi, resourceApi]) {
      NagSuppressions.addResourceSuppressions(
        api,
        [
          {
            id: 'AwsSolutions-APIG4',
            reason:
              'The test issuer authenticates /token with HTTP Basic and the test RS authenticates with Agent Auth bearer tokens. JWKS is intentionally public protocol metadata.',
          },
        ],
        true,
      );
    }
    NagSuppressions.addResourceSuppressions(
      signingKey,
      [
        {
          id: 'AwsSolutions-KMS5',
          reason:
            'Automatic rotation is not supported for asymmetric KMS keys. This simulator stack is temporary and uses a dedicated signing key.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      userPool,
      [
        {
          id: 'AwsSolutions-COG2',
          reason:
            'This disposable pool has one generated automation-only user. MFA would make the non-interactive ID-JAG acquisition gate impossible and would not represent a product authentication control.',
        },
        {
          id: 'AwsSolutions-COG8',
          reason:
            'This disposable non-production pool has one generated test user and exists only for protocol acceptance. Cognito Plus threat protection is not a meaningful control for this simulator.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressions(
      [testUserPassword, brokerSecret],
      [
        {
          id: 'AwsSolutions-SMG4',
          reason:
            'These credentials belong to a temporary acceptance simulator. The stack is destroyed after use instead of rotating long-lived credentials.',
        },
      ],
      true,
    );

    new CfnOutput(this, 'SimulatorCommit', {
      value: props.simulatorCommit,
    });
    new CfnOutput(this, 'IdentitySourceUserPoolId', {
      value: userPool.userPoolId,
    });
    new CfnOutput(this, 'IdentitySourceClientId', {
      value: userPoolClient.userPoolClientId,
    });
    new CfnOutput(this, 'IdentitySourceIssuer', {
      value: cognitoIssuer,
    });
    new CfnOutput(this, 'TestUsername', { value: TEST_USERNAME });
    new CfnOutput(this, 'TestUserPasswordSecretArn', {
      value: testUserPassword.secretArn,
    });
    new CfnOutput(this, 'BrokerSecretArn', {
      value: brokerSecret.secretArn,
    });
    new CfnOutput(this, 'IssuerUrl', {
      value: issuerApi.apiEndpoint,
    });
    new CfnOutput(this, 'JwksUrl', {
      value: `${issuerApi.apiEndpoint}/jwks.json`,
    });
    new CfnOutput(this, 'AssertionClientId', {
      value: ASSERTION_CLIENT_ID,
    });
    new CfnOutput(this, 'ResourceUrl', {
      value: resourceApi.apiEndpoint,
    });
    new CfnOutput(this, 'RsAllowUrl', {
      value: `${resourceApi.apiEndpoint}/allow`,
    });
    new CfnOutput(this, 'RsDenyUrl', {
      value: `${resourceApi.apiEndpoint}/deny`,
    });
    new CfnOutput(this, 'IssuerFunctionName', {
      value: issuerFunction.functionName,
    });
    new CfnOutput(this, 'ResourceFunctionName', {
      value: resourceFunction.functionName,
    });
  }
}

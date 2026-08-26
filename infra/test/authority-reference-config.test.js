const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { App, Aspects } = require('aws-cdk-lib');
const { Annotations, Match, Template } = require('aws-cdk-lib/assertions');
const { AwsSolutionsChecks } = require('cdk-nag');

const {
  AuthorityReferenceMigrationStack,
} = require('../dist/lib/authority-reference-migration-stack');
const { AgentAuthStack } = require('../dist/lib/agent-auth-stack');
const MIGRATION_SOURCE = fs.readFileSync(
  path.resolve(
    __dirname,
    '../../crates/http/src/bin/migrate_credentials.rs',
  ),
  'utf8',
);

const DEPLOYMENT_COMMIT = '0123456789abcdef0123456789abcdef01234567';

function resourceByPrefix(template, prefix, type) {
  const matches = Object.entries(template.Resources).filter(
    ([logicalId, resource]) =>
      logicalId.startsWith(prefix) && resource.Type === type,
  );
  assert.equal(matches.length, 1, `expected one ${type} with prefix ${prefix}`);
  return matches[0];
}

function policyStatementsForFunction(template, fn) {
  const roleId = fn.Properties.Role['Fn::GetAtt'][0];
  return Object.values(template.Resources)
    .filter(
      (resource) =>
        ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'].includes(
          resource.Type,
        ) &&
        resource.Properties.Roles?.some((role) => role.Ref === roleId),
    )
    .flatMap((resource) => resource.Properties.PolicyDocument.Statement);
}

function makeStack(app = new App()) {
  const assetPath = path.resolve(__dirname);
  const stack = new AgentAuthStack(app, 'AuthorityReferenceConfigTest', {
    env: { account: '123456789012', region: 'us-east-1' },
    webBaseUrl: 'https://auth.example.com',
    lambdaAssetPath: assetPath,
    securityEventArchiveAssetPath: assetPath,
    ssfDeliveryAssetPath: assetPath,
    governanceWorkerAssetPath: assetPath,
    reclaimAssetPath: assetPath,
    credentialMigrationAssetPath: assetPath,
    deployFrontend: false,
    deploymentCommit: DEPLOYMENT_COMMIT,
  });
  return { app, stack };
}

function synth() {
  const { app, stack } = makeStack();
  return { app, stack, template: Template.fromStack(stack).toJSON() };
}

test('client authority references use a Region-local compound-key table', () => {
  const { template } = synth();
  const [tableId, table] = resourceByPrefix(
    template,
    'ClientAuthorityRefsTable',
    'AWS::DynamoDB::Table',
  );

  assert.deepEqual(table.Properties.KeySchema, [
    { AttributeName: 'client_key', KeyType: 'HASH' },
    { AttributeName: 'reference_key', KeyType: 'RANGE' },
  ]);
  assert.equal(table.Properties.BillingMode, 'PAY_PER_REQUEST');
  assert.deepEqual(table.Properties.TimeToLiveSpecification, {
    AttributeName: 'expires_at',
    Enabled: true,
  });
  assert.equal(
    table.Properties.PointInTimeRecoverySpecification
      .PointInTimeRecoveryEnabled,
    true,
  );
  assert.equal(table.DeletionPolicy, 'Delete');
  assert.equal(table.UpdateReplacePolicy, 'Delete');
  assert.doesNotMatch(
    JSON.stringify(template.Resources),
    new RegExp(`"TableName":\\{"Ref":"${tableId}"\\}[\\s\\S]*"Replica"`),
  );
});

test('runtime roles receive only the authority-reference access they need', () => {
  const { template } = synth();
  const [tableId] = resourceByPrefix(
    template,
    'ClientAuthorityRefsTable',
    'AWS::DynamoDB::Table',
  );
  const functions = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::Lambda::Function',
  );

  const findFunction = (prefix) => {
    const matches = functions.filter(([logicalId]) =>
      logicalId.startsWith(prefix),
    );
    assert.equal(matches.length, 1, `expected one Lambda with prefix ${prefix}`);
    return matches[0];
  };
  const findHttpFunction = (scope) => {
    const matches = functions.filter(
      ([, resource]) =>
        resource.Properties?.Environment?.Variables?.SCOPE === scope,
    );
    assert.equal(matches.length, 1, `expected one ${scope} HTTP Lambda`);
    return matches[0];
  };

  const runtimes = [
    ['non_token', findHttpFunction('non_token')],
    ['token', findHttpFunction('token')],
    ['GovernanceWorkerFn', findFunction('GovernanceWorkerFn')],
    ['ReclaimFn', findFunction('ReclaimFn')],
  ];
  for (const [name, [, fn]] of runtimes) {
    assert.deepEqual(
      fn.Properties.Environment.Variables.AUTH_REFS_TABLE,
      { Ref: tableId },
    );
    const statements = policyStatementsForFunction(template, fn);
    const tableStatements = statements.filter((statement) =>
      JSON.stringify(statement.Resource).includes(tableId),
    );
    assert.ok(tableStatements.length > 0, `${name} must reference the table`);

    const actions = new Set(
      tableStatements.flatMap((statement) =>
        Array.isArray(statement.Action)
          ? statement.Action
          : [statement.Action],
      ),
    );
    assert.ok(actions.has('dynamodb:GetItem'));
    assert.ok(actions.has('dynamodb:Query'));
    if (name === 'ReclaimFn') {
      assert.equal(actions.has('dynamodb:PutItem'), false);
      assert.equal(actions.has('dynamodb:DeleteItem'), false);
      assert.equal(actions.has('dynamodb:TransactWriteItems'), false);
    } else {
      assert.ok(
        statements.some(
          (statement) =>
            (Array.isArray(statement.Action)
              ? statement.Action
              : [statement.Action]
            ).includes('dynamodb:TransactWriteItems') &&
            JSON.stringify(statement.Resource).includes(tableId),
        ),
        `${name} must transact with the source and reference tables`,
      );
    }
  }
});

test('post-deploy migration is table-scoped and commit-versioned', () => {
  const { app, stack } = makeStack();
  const migrationStack = new AuthorityReferenceMigrationStack(
    app,
    'AuthorityReferenceMigrationConfigTest',
    {
      env: { account: '123456789012', region: 'us-east-1' },
      onEventHandler: stack.authorityReferenceMigrationHandler,
      deploymentCommit: DEPLOYMENT_COMMIT,
    },
  );
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
  const template = Template.fromStack(stack).toJSON();
  const [tableId] = resourceByPrefix(
    template,
    'ClientAuthorityRefsTable',
    'AWS::DynamoDB::Table',
  );
  const [migrationId, migration] = resourceByPrefix(
    template,
    'AuthorityReferenceMigrationFn',
    'AWS::Lambda::Function',
  );
  assert.equal(
    migration.Properties.Environment.Variables.CREDENTIAL_MIGRATION_MODE,
    'authority_refs',
  );
  assert.deepEqual(
    migration.Properties.Environment.Variables.AUTH_REFS_TABLE,
    { Ref: tableId },
  );
  const statements = policyStatementsForFunction(template, migration);
  assert.ok(
    statements.some(
      (statement) =>
        (Array.isArray(statement.Action)
          ? statement.Action
          : [statement.Action]
        ).includes('dynamodb:TransactWriteItems') &&
        JSON.stringify(statement.Resource).includes(tableId),
    ),
  );
  assert.ok(
    statements.some(
      (statement) =>
        (Array.isArray(statement.Action)
          ? statement.Action
          : [statement.Action]
        ).includes('lambda:GetFunctionConfiguration') &&
        JSON.stringify(statement.Resource).includes(migrationId),
    ),
    'migration must verify its current Lambda control-plane generation',
  );

  const migrationTemplate = Template.fromStack(migrationStack).toJSON();
  Annotations.fromStack(migrationStack).hasNoError('*', Match.anyValue());
  const customResources = Object.values(migrationTemplate.Resources).filter(
    (resource) => resource.Type === 'AWS::CloudFormation::CustomResource',
  );
  assert.equal(customResources.length, 1);
  assert.equal(
    customResources[0].Properties.MigrationVersion,
    `client-authority-refs-v1:${DEPLOYMENT_COMMIT}`,
  );
  assert.match(
    JSON.stringify(migrationTemplate.Resources),
    new RegExp(migrationId),
  );
  assert.equal(
    Object.values(migrationTemplate.Resources).filter(
      (resource) => resource.Type === 'AWS::StepFunctions::StateMachine',
    ).length,
    1,
  );
  const waiter = Object.values(migrationTemplate.Resources).find(
    (resource) => resource.Type === 'AWS::StepFunctions::StateMachine',
  );
  assert.equal(waiter.Properties.LoggingConfiguration.Level, 'ALL');
  assert.equal(waiter.Properties.LoggingConfiguration.IncludeExecutionData, true);
  assert.match(MIGRATION_SOURCE, /LEGACY_MUTATOR_DRAIN_SECS: i64 = 315/);
  assert.match(
    MIGRATION_SOURCE,
    /\.begin\(\s*migration_id,\s*previous_migration_id,\s*request_id,\s*invocation_started_at_ms,\s*drain_until,?\s*\)/,
  );
  assert.match(MIGRATION_SOURCE, /\.step\(migration_id, now\)/);
  assert.match(MIGRATION_SOURCE, /authority_reference_migration_version/);
  assert.match(
    MIGRATION_SOURCE,
    /OldResourceProperties\/MigrationVersion/,
  );
  assert.match(MIGRATION_SOURCE, /authority reference migration RequestId is required/);
  assert.match(
    MIGRATION_SOURCE,
    /migration_id != expected_migration_version/,
  );
  assert.match(
    MIGRATION_SOURCE,
    /verify_current_authority_reference_migration_deployment\([\s\S]*?\.await\?;/,
  );
  assert.match(
    MIGRATION_SOURCE,
    /\.get_function_configuration\(\)[\s\S]*?AGENT_AUTH_DEPLOYMENT_COMMIT[\s\S]*?authority_refs/,
  );
  assert.match(
    MIGRATION_SOURCE,
    /validate_deployment_commit\(&deployment_commit\)\?/,
  );
  assert.match(
    MIGRATION_SOURCE,
    /must be a full lowercase Git SHA/,
  );
  assert.doesNotMatch(MIGRATION_SOURCE, /tokio::time::sleep/);
  assert.match(
    fs.readFileSync(
      path.resolve(
        __dirname,
        '../lib/authority-reference-migration-stack.ts',
      ),
      'utf8',
    ),
    /isCompleteHandler: props\.onEventHandler[\s\S]*queryInterval: Duration\.seconds\(2\)[\s\S]*totalTimeout: Duration\.minutes\(55\)[\s\S]*addPropertyOverride\('ServiceTimeout', 3600\)/,
  );
  assert.equal(
    resourceByPrefix(
      template,
      'GovernanceWorkerFn',
      'AWS::Lambda::Function',
    )[1].Properties.Timeout,
    300,
  );
});

test('authority-reference migration rejects unversioned deployments', () => {
  const { app, stack } = makeStack();
  assert.throws(
    () =>
      new AuthorityReferenceMigrationStack(
        app,
        'UnversionedAuthorityReferenceMigration',
        {
          env: { account: '123456789012', region: 'us-east-1' },
          onEventHandler: stack.authorityReferenceMigrationHandler,
          deploymentCommit: 'unversioned',
        },
      ),
    /full lowercase deployment commit/,
  );
  assert.throws(
    () =>
      new AgentAuthStack(new App(), 'MissingDeploymentCommit', {
        webBaseUrl: 'https://auth.example.com',
        lambdaAssetPath: path.resolve(__dirname),
        securityEventArchiveAssetPath: path.resolve(__dirname),
        ssfDeliveryAssetPath: path.resolve(__dirname),
        credentialMigrationAssetPath: path.resolve(__dirname),
        deployFrontend: false,
      }),
    /full lowercase Git SHA/,
  );
});

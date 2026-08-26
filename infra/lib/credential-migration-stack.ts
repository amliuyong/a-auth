import { CustomResource, Stack, StackProps } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cr from 'aws-cdk-lib/custom-resources';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';

export interface CredentialMigrationStackProps extends StackProps {
  readonly onEventHandler: lambda.IFunction;
}

/**
 * Post-deploy stack for irreversible client credential migration.
 *
 * This stack is deployed only after the serving stack reaches UPDATE_COMPLETE.
 * A migration failure can roll back this stack without rolling the serving
 * Lambda back to code that depends on the removed plaintext attributes.
 */
export class CredentialMigrationStack extends Stack {
  constructor(scope: Construct, id: string, props: CredentialMigrationStackProps) {
    super(scope, id, props);

    const provider = new cr.Provider(this, 'CredentialMigrationProvider', {
      onEventHandler: props.onEventHandler,
    });
    new CustomResource(this, 'CredentialMigration', {
      serviceToken: provider.serviceToken,
      properties: { MigrationVersion: 'credential-verifier-v1' },
    });

    NagSuppressions.addResourceSuppressions(
      provider,
      [
        {
          id: 'AwsSolutions-IAM4',
          reason:
            'CDK Provider framework Lambda uses AWSLambdaBasicExecutionRole for CloudFormation callbacks.',
        },
        {
          id: 'AwsSolutions-IAM5',
          reason:
            'CDK Provider framework invokes only the migration handler; framework-generated wildcard permissions are scoped to that function.',
        },
      ],
      true,
    );
  }
}

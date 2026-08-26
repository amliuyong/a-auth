import {
  CfnResource,
  CustomResource,
  Duration,
  Stack,
  StackProps,
} from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sfn from 'aws-cdk-lib/aws-stepfunctions';
import * as cr from 'aws-cdk-lib/custom-resources';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';

export interface AuthorityReferenceMigrationStackProps extends StackProps {
  readonly onEventHandler: lambda.IFunction;
  readonly deploymentCommit: string;
}

/**
 * Post-deploy backfill and coverage publication for the Region-local
 * per-client Code/Refresh reference table.
 */
export class AuthorityReferenceMigrationStack extends Stack {
  constructor(
    scope: Construct,
    id: string,
    props: AuthorityReferenceMigrationStackProps,
  ) {
    super(scope, id, props);
    if (!/^[0-9a-f]{40}$/.test(props.deploymentCommit)) {
      throw new Error(
        'authority-reference migration requires a full lowercase deployment commit',
      );
    }

    const provider = new cr.Provider(this, 'AuthorityReferenceMigrationProvider', {
      onEventHandler: props.onEventHandler,
      isCompleteHandler: props.onEventHandler,
      queryInterval: Duration.seconds(2),
      totalTimeout: Duration.minutes(55),
      waiterStateMachineLogOptions: {
        includeExecutionData: true,
        level: sfn.LogLevel.ALL,
      },
      disableWaiterStateMachineLogging: false,
    });
    const migration = new CustomResource(this, 'AuthorityReferenceMigration', {
      serviceToken: provider.serviceToken,
      properties: {
        MigrationVersion: `client-authority-refs-v1:${props.deploymentCommit}`,
      },
    });
    const cfnMigration = migration.node.defaultChild as CfnResource;
    cfnMigration.addPropertyOverride('ServiceTimeout', 3600);

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
            'CDK Provider framework invokes only the table-scoped authority-reference migration handler.',
        },
      ],
      true,
    );
    NagSuppressions.addResourceSuppressionsByPath(
      this,
      `${this.stackName}/AuthorityReferenceMigrationProvider/waiter-state-machine`,
      [
        {
          id: 'AwsSolutions-SF2',
          reason:
            'This deployment-only waiter invokes the table-scoped migration handler; durable phase, cursor, request, and completion evidence is stored in DynamoDB, while ALL execution events are retained in CloudWatch Logs.',
        },
      ],
      true,
    );
  }
}

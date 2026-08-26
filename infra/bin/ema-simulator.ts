#!/usr/bin/env node
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { App, Aspects } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { EmaSimulatorStack } from '../lib/ema-simulator-stack';
import { requireCleanGitWorktree } from '../lib/deployment-provenance';

const app = new App();
const repoRoot = path.resolve(__dirname, '..', '..');
const simulatorCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
  cwd: repoRoot,
  encoding: 'utf8',
}).trim();
requireCleanGitWorktree(repoRoot);

const explicitIssuers = process.env.EMA_SIMULATOR_AGENT_AUTH_ISSUERS
  ?.split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const derivedIssuers = [
  process.env.WEB_BASE_URL,
  process.env.SAAS_ZONE
    ? `https://${process.env.EMA_SIMULATOR_SAAS_TENANT ?? 't1'}.${process.env.SAAS_ZONE}`
    : undefined,
].filter((value): value is string => Boolean(value));
const agentAuthIssuers = explicitIssuers?.length
  ? explicitIssuers
  : derivedIssuers;

new EmaSimulatorStack(app, 'AgentAuthEmaSimulator', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
  agentAuthIssuers,
  simulatorCommit,
  description:
    'Transparent Cognito-backed ID-JAG simulator and RS for Agent Auth EMA acceptance',
});

Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

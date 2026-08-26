import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

const COMMIT_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const PROVENANCE_SCHEMA = 'agent-auth-lambda-provenance-v1';

export interface DeploymentProvenance {
  readonly schema: string;
  readonly commit: string;
  readonly bootstrap_sha256: string;
}

export function requireCleanGitWorktree(repoRoot: string): void {
  const status = execFileSync(
    'git',
    [
      'status',
      '--porcelain',
      '--untracked-files=normal',
      '--ignore-submodules=dirty',
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
    },
  );
  if (status.length > 0) {
    throw new Error('Lambda deployment requires a clean Git worktree');
  }
}

export function validateLambdaDeploymentProvenance(
  lambdaAssetPath: string,
  expectedCommit: string,
): DeploymentProvenance {
  if (!COMMIT_PATTERN.test(expectedCommit)) {
    throw new Error('EMA deployment commit must be a full lowercase Git SHA');
  }
  const manifestPath = path.join(
    lambdaAssetPath,
    'deployment-provenance.json',
  );
  const bootstrapPath = path.join(lambdaAssetPath, 'bootstrap');
  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (error) {
    throw new Error(
      `Lambda deployment requires a readable provenance manifest: ${String(error)}`,
    );
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('Lambda provenance manifest must be a JSON object');
  }
  const provenance = parsed as Record<string, unknown>;
  const keys = Object.keys(provenance).sort();
  if (
    keys.join(',') !== 'bootstrap_sha256,commit,schema' ||
    provenance.schema !== PROVENANCE_SCHEMA ||
    typeof provenance.commit !== 'string' ||
    !COMMIT_PATTERN.test(provenance.commit) ||
    typeof provenance.bootstrap_sha256 !== 'string' ||
    !SHA256_PATTERN.test(provenance.bootstrap_sha256)
  ) {
    throw new Error('Lambda provenance manifest has an invalid shape');
  }
  if (provenance.commit !== expectedCommit) {
    throw new Error('Lambda provenance commit does not match Git HEAD');
  }
  let bootstrap: Buffer;
  try {
    bootstrap = fs.readFileSync(bootstrapPath);
  } catch (error) {
    throw new Error(`Lambda deployment requires a bootstrap: ${String(error)}`);
  }
  const actualSha256 = createHash('sha256').update(bootstrap).digest('hex');
  if (provenance.bootstrap_sha256 !== actualSha256) {
    throw new Error('Lambda provenance bootstrap SHA-256 does not match the artifact');
  }
  return {
    schema: provenance.schema,
    commit: provenance.commit,
    bootstrap_sha256: provenance.bootstrap_sha256,
  };
}

export function resolveLambdaDeploymentProvenance(
  repoRoot: string,
  requestedCommit: string,
  lambdaAssetPaths: readonly string[],
): DeploymentProvenance {
  if (!COMMIT_PATTERN.test(requestedCommit)) {
    throw new Error(
      'AGENT_AUTH_DEPLOYMENT_COMMIT must be a full lowercase Git SHA',
    );
  }
  if (lambdaAssetPaths.length === 0) {
    throw new Error('Lambda deployment requires at least one artifact');
  }
  const head = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }).trim();
  if (!COMMIT_PATTERN.test(head)) {
    throw new Error('git rev-parse HEAD did not return a full lowercase Git SHA');
  }
  if (requestedCommit !== head) {
    throw new Error(
      'AGENT_AUTH_DEPLOYMENT_COMMIT does not match the checked-out Git HEAD',
    );
  }
  requireCleanGitWorktree(repoRoot);
  const provenances = lambdaAssetPaths.map((assetPath) =>
    validateLambdaDeploymentProvenance(assetPath, head),
  );
  const verifiedHead = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: repoRoot,
    encoding: 'utf8',
  }).trim();
  if (verifiedHead !== head) {
    throw new Error('Git HEAD changed while Lambda deployment provenance was verified');
  }
  requireCleanGitWorktree(repoRoot);
  return provenances[0];
}

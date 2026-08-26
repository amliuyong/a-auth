const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const test = require('node:test');

const {
  requireCleanGitWorktree,
  resolveLambdaDeploymentProvenance,
  validateLambdaDeploymentProvenance,
} = require('../dist/lib/deployment-provenance');

const COMMIT = 'a'.repeat(40);
const INFRA_ENTRY = fs.readFileSync(
  path.resolve(__dirname, '../bin/agent-auth-infra.ts'),
  'utf8',
);

function artifactFixture(commit = COMMIT) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-provenance-'));
  const bootstrap = Buffer.from('reviewed Lambda artifact');
  fs.writeFileSync(path.join(directory, 'bootstrap'), bootstrap);
  fs.writeFileSync(
    path.join(directory, 'deployment-provenance.json'),
    JSON.stringify({
      schema: 'agent-auth-lambda-provenance-v1',
      commit,
      bootstrap_sha256: crypto.createHash('sha256').update(bootstrap).digest('hex'),
    }),
  );
  return directory;
}

function repositoryFixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-auth-git-'));
  execFileSync('git', ['init', '--quiet'], { cwd: directory });
  execFileSync('git', ['config', 'user.name', 'Agent Auth Test'], { cwd: directory });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: directory });
  fs.writeFileSync(path.join(directory, 'tracked'), 'clean');
  execFileSync('git', ['add', 'tracked'], { cwd: directory });
  execFileSync('git', ['commit', '--quiet', '-m', 'fixture'], { cwd: directory });
  const commit = execFileSync('git', ['rev-parse', 'HEAD'], {
    cwd: directory,
    encoding: 'utf8',
  }).trim();
  return { directory, commit };
}

test('accepts a deployment manifest bound to HEAD and the Auth bootstrap', (t) => {
  const directory = artifactFixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const provenance = validateLambdaDeploymentProvenance(directory, COMMIT);
  assert.equal(provenance.commit, COMMIT);
});

test('rejects stale commits, modified artifacts, and malformed manifests', (t) => {
  const directory = artifactFixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  assert.throws(
    () => validateLambdaDeploymentProvenance(directory, 'b'.repeat(40)),
    /commit does not match/,
  );
  fs.appendFileSync(path.join(directory, 'bootstrap'), 'changed');
  assert.throws(
    () => validateLambdaDeploymentProvenance(directory, COMMIT),
    /SHA-256 does not match/,
  );
  fs.writeFileSync(
    path.join(directory, 'deployment-provenance.json'),
    JSON.stringify({ commit: COMMIT }),
  );
  assert.throws(
    () => validateLambdaDeploymentProvenance(directory, COMMIT),
    /invalid shape/,
  );
});

test('rejects a dirty deployment worktree', (t) => {
  const { directory } = repositoryFixture();
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  requireCleanGitWorktree(directory);
  fs.writeFileSync(path.join(directory, 'tracked'), 'dirty');
  assert.throws(() => requireCleanGitWorktree(directory), /clean Git worktree/);
});

test('resolves deployment commit only from clean HEAD-bound Lambda artifacts', (t) => {
  const repository = repositoryFixture();
  const authArtifact = artifactFixture(repository.commit);
  const workerArtifact = artifactFixture(repository.commit);
  t.after(() => {
    fs.rmSync(repository.directory, { recursive: true, force: true });
    fs.rmSync(authArtifact, { recursive: true, force: true });
    fs.rmSync(workerArtifact, { recursive: true, force: true });
  });

  const provenance = resolveLambdaDeploymentProvenance(
    repository.directory,
    repository.commit,
    [authArtifact, workerArtifact],
  );

  assert.equal(provenance.commit, repository.commit);
});

test('rejects caller-reported, dirty, or mixed-artifact deployment provenance', (t) => {
  const repository = repositoryFixture();
  const authArtifact = artifactFixture(repository.commit);
  const staleArtifact = artifactFixture('b'.repeat(40));
  t.after(() => {
    fs.rmSync(repository.directory, { recursive: true, force: true });
    fs.rmSync(authArtifact, { recursive: true, force: true });
    fs.rmSync(staleArtifact, { recursive: true, force: true });
  });

  assert.throws(
    () =>
      resolveLambdaDeploymentProvenance(
        repository.directory,
        'c'.repeat(40),
        [authArtifact],
      ),
    /does not match the checked-out Git HEAD/,
  );
  assert.throws(
    () =>
      resolveLambdaDeploymentProvenance(
        repository.directory,
        repository.commit,
        [authArtifact, staleArtifact],
      ),
    /commit does not match Git HEAD/,
  );
  fs.writeFileSync(path.join(repository.directory, 'tracked'), 'dirty');
  assert.throws(
    () =>
      resolveLambdaDeploymentProvenance(
        repository.directory,
        repository.commit,
        [authArtifact],
      ),
    /clean Git worktree/,
  );
});

test('CDK entry derives stack deployment commit from all deployable artifacts', () => {
  assert.match(
    INFRA_ENTRY,
    /const deploymentProvenance = resolveLambdaDeploymentProvenance\(/,
  );
  assert.match(
    INFRA_ENTRY,
    /const deploymentCommit = deploymentProvenance\.commit;/,
  );
  for (const asset of [
    'lambdaAssetPath',
    'securityEventArchiveAssetPath',
    'ssfDeliveryAssetPath',
    'tenantKeyProvisionerAssetPath',
    'governanceWorkerAssetPath',
    'credentialMigrationAssetPath',
    'reclaimAssetPath',
    'recomputeAssetPath',
  ]) {
    assert.ok(INFRA_ENTRY.includes(asset), `${asset} must be provenance-bound`);
  }
});

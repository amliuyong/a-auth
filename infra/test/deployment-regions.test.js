const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { RegionInfo } = require('aws-cdk-lib/region-info');
const regions = require('../config/commercial-regions.json');
const {
  requireCommercialRegion,
  requireStandbyRegion,
} = require('../dist/lib/deployment-regions');

test('deployment and drill share the locked CDK commercial Region inventory', () => {
  const expected = RegionInfo.regions
    .filter((region) => region.partition === 'aws')
    .map((region) => region.name)
    .sort();
  assert.deepEqual(regions, expected);
  for (const region of regions) {
    assert.equal(requireCommercialRegion('Region', region), region);
  }
});

test('commercial pair selection rejects unknown Regions and other partitions', () => {
  assert.doesNotThrow(() => requireStandbyRegion('eu-west-1', 'ap-southeast-2'));
  for (const region of [
    'cn-north-1', 'us-gov-east-1', 'us-iso-east-1', 'eusc-de-east-1',
    'zz-west-1', '', 'EU-WEST-1',
  ]) {
    assert.throws(() => requireStandbyRegion(region, 'us-west-2'));
    assert.throws(() => requireStandbyRegion('us-east-1', region));
  }
  assert.throws(() => requireStandbyRegion('eu-west-1', 'eu-west-1'));
});

test('operational scripts use the same commercial Region validation', () => {
  const library = path.resolve(__dirname, '../../e2e/lib/aws_regions.sh');
  const run = (...selected) => spawnSync('bash', [
    '-c', 'source "$1"; shift; require_commercial_regions "$@"', '--',
    library, ...selected,
  ], { encoding: 'utf8' });
  for (const pair of [
    ['eu-west-1'],
    ['ap-southeast-2'],
    ['eu-west-1', 'ap-southeast-2'],
  ]) {
    const result = run(...pair);
    assert.equal(result.status, 0, result.stderr);
  }
  for (const pair of [
    ['cn-north-1'],
    ['us-gov-west-1'],
    ['eu-isoe-west-1'],
    ['zz-west-1'],
    ['eu-west-1', 'eu-west-1'],
    [],
  ]) {
    assert.notEqual(run(...pair).status, 0);
  }
});

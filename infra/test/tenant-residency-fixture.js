const { Aws } = require('aws-cdk-lib');

function tenantResidency(
  tenantIds = ['default'],
  { primaryRegion, replicaRegions = [] } = {},
) {
  const governanceRegion = primaryRegion ?? Aws.REGION;
  const allowedRegions = [governanceRegion, ...replicaRegions];
  return Object.fromEntries(
    tenantIds.map((tenantId) => [
      tenantId,
      {
        jurisdiction: 'us',
        allowed_regions: allowedRegions,
        governance_region: governanceRegion,
      },
    ]),
  );
}

module.exports = { tenantResidency };

import commercialRegions from '../config/commercial-regions.json';

/** Shared with the failover drill; refreshed from the locked CDK Region metadata. */
export function requireCommercialRegion(name: string, region: string): string {
  if (!commercialRegions.includes(region)) {
    throw new Error(`${name} must be a known AWS commercial Region (aws partition)`);
  }
  return region;
}

export function requireStandbyRegion(primary: string, standby: string): void {
  requireCommercialRegion('primary Region', primary);
  requireCommercialRegion('standby Region', standby);
  if (primary === standby) {
    throw new Error('standby Region must differ from the primary Region');
  }
}

export type AdminMode = 'tenant' | 'control';
export type TenantProbeResult = 'tenant' | 'probe-control';

export class AdminProbeError extends Error {
  readonly status: number;

  constructor(status: number) {
    super(`Admin API probe failed with HTTP ${status}`);
    this.status = status;
  }
}

function isSuccessful(status: number): boolean {
  return status >= 200 && status < 300;
}

function isAdminDomainMiss(status: number): boolean {
  return status === 401 || status === 404;
}

export function classifyTenantProbe(status: number): TenantProbeResult {
  if (isSuccessful(status)) return 'tenant';
  if (isAdminDomainMiss(status)) return 'probe-control';
  throw new AdminProbeError(status);
}

export function classifyControlProbe(status: number): AdminMode | null {
  if (isSuccessful(status) || status === 503) return 'control';
  if (isAdminDomainMiss(status)) return null;
  throw new AdminProbeError(status);
}

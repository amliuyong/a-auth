import type { AgentAuthStackProps, DcrMode } from './agent-auth-stack';
import { normalizeCimdDomains } from './cimd-config';

type Env = Readonly<Record<string, string | undefined>>;
type AuthConfig = Pick<
  AgentAuthStackProps,
  'allowLoginPlaceholder' | 'dcrMode'
>;
type CimdConfig = Pick<
  AgentAuthStackProps,
  'cimdEnabled' | 'cimdAllowedDomains' | 'cimdTenantAllowedDomains'
>;

function readDcrMode(env: Env, name: string, fallback?: DcrMode): DcrMode | undefined {
  const value = env[name] ?? fallback;
  if (value !== undefined && value !== 'open' && value !== 'initial_access_token') {
    throw new Error(`${name} 非法或尚未实现:${value}`);
  }
  return value;
}

export function devAuthConfig(env: Env): AuthConfig {
  return {
    allowLoginPlaceholder: env.AGENT_AUTH_ALLOW_LOGIN_PLACEHOLDER === '1',
    dcrMode: readDcrMode(env, 'AGENT_AUTH_DCR_MODE', 'open'),
  };
}

export function saasAuthConfig(_env: Env): AuthConfig {
  return {};
}

function cimdAllowedDomains(env: Env): string[] {
  const domains = (env.AGENT_AUTH_CIMD_ALLOWED_DOMAINS ?? '')
    .split(',')
    .map((domain) => domain.trim())
    .filter(Boolean);
  return normalizeCimdDomains(domains, 'AGENT_AUTH_CIMD_ALLOWED_DOMAINS');
}

export function devCimdConfig(env: Env): CimdConfig {
  const allowedDomains = cimdAllowedDomains(env);
  const enabled =
    env.AGENT_AUTH_CIMD_ENABLED === '1' &&
    (allowedDomains.length > 0 || !env.SAAS_ZONE);
  return {
    cimdEnabled: enabled,
    cimdAllowedDomains: allowedDomains,
  };
}

export function saasCimdConfig(env: Env): CimdConfig {
  let tenantDomains: Record<string, string[]>;
  try {
    const parsed = JSON.parse(
      env.AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS ?? '{}',
    ) as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('must be a JSON object');
    }
    if (
      Object.values(parsed).some(
        (domains) =>
          !Array.isArray(domains) ||
          domains.some((domain) => typeof domain !== 'string'),
      )
    ) {
      throw new Error('values must be string arrays');
    }
    tenantDomains = Object.fromEntries(
      Object.entries(parsed as Record<string, string[]>).map(([tenant, domains]) => {
        if (!tenant || tenant.trim() !== tenant) {
          throw new Error('tenant policy keys must be non-empty canonical tenant IDs');
        }
        return [
          tenant,
          normalizeCimdDomains(
            domains,
            `AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS.${tenant}`,
          ),
        ];
      }),
    );
  } catch (error) {
    throw new Error(
      `AGENT_AUTH_CIMD_TENANT_ALLOWED_DOMAINS invalid:${String(error)}`,
    );
  }
  return {
    cimdEnabled: env.AGENT_AUTH_CIMD_ENABLED === '1',
    cimdAllowedDomains: cimdAllowedDomains(env),
    cimdTenantAllowedDomains: tenantDomains,
  };
}

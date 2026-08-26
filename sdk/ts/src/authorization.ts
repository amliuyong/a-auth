import type { ScopeImplications, ScopeResolver } from "./types.js";

const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
const DOT_SEGMENT = /^(?:\.|%2e){1,2}$/i;
const URI_PATH = /^(?:[a-z0-9\-._~!$&'()*+,;=:@/]|%[0-9a-f]{2})*$/i;
const URI_QUERY = /^(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*$/i;
const PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource";

function validateHostname(hostname: string, label: string): void {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return;
  const withoutFinalDot = hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
  const labels = withoutFinalDot.split(".");
  if (
    labels.some(
      (part) =>
        part.length === 0 ||
        part.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(part),
    )
  ) {
    throw new TypeError(`${label} must use a valid DNS host`);
  }
}

function explicitPort(rawAuthority: string): string | undefined {
  if (rawAuthority.startsWith("[")) {
    const suffix = rawAuthority.slice(rawAuthority.indexOf("]") + 1);
    return suffix.startsWith(":") && suffix.length > 1 ? suffix.slice(1) : undefined;
  }
  const separator = rawAuthority.lastIndexOf(":");
  return separator >= 0 && separator < rawAuthority.length - 1
    ? rawAuthority.slice(separator + 1)
    : undefined;
}

function parseHttpsUrl(value: string, label: string, allowQuery: boolean): URL {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !/^[\x21-\x7e]+$/.test(value) ||
    value.includes('"') ||
    value.includes("\\")
  ) {
    throw new TypeError(`${label} must contain only safe printable URI characters`);
  }
  const absoluteMatch = /^https:\/\/([^/?#]*)/i.exec(value);
  if (!absoluteMatch) {
    throw new TypeError(`${label} must be an absolute HTTPS URL`);
  }
  const rawAuthority = absoluteMatch[1] as string;
  if (rawAuthority.includes("%")) {
    throw new TypeError(`${label} must not contain an encoded authority`);
  }
  const remainder = value.slice(absoluteMatch[0].length);
  const querySeparator = remainder.indexOf("?");
  const rawPath = querySeparator < 0 ? remainder : remainder.slice(0, querySeparator);
  const rawQuery = querySeparator < 0 ? "" : remainder.slice(querySeparator + 1);
  if (!URI_PATH.test(rawPath) || !URI_QUERY.test(rawQuery)) {
    throw new TypeError(`${label} path and query must use valid RFC 3986 characters`);
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new TypeError(`${label} must be an absolute HTTPS URL`);
  }
  if (parsed.protocol !== "https:" || !parsed.hostname) {
    throw new TypeError(`${label} must be an absolute HTTPS URL`);
  }
  if (parsed.username || parsed.password) {
    throw new TypeError(`${label} must not contain userinfo`);
  }
  if (value.includes("#")) {
    throw new TypeError(`${label} must not contain a fragment`);
  }
  if (!allowQuery && value.includes("?")) {
    throw new TypeError(`${label} must not contain a query`);
  }
  if (!allowQuery) {
    if (rawPath.split("/").some((segment) => DOT_SEGMENT.test(segment))) {
      throw new TypeError(`${label} must not contain dot path segments`);
    }
  }

  const rawHost = rawAuthority.startsWith("[")
    ? rawAuthority.slice(0, rawAuthority.indexOf("]") + 1)
    : rawAuthority.replace(/:\d*$/, "");
  if (
    !rawHost.startsWith("[") &&
    rawHost.toLowerCase() !== parsed.hostname.toLowerCase()
  ) {
    throw new TypeError(`${label} must use a canonical host`);
  }
  validateHostname(parsed.hostname, label);
  return parsed;
}

/** Validate and normalize the resource identifier used for exact audience checks. */
export function normalizeResourceId(resourceId: string): string {
  parseHttpsUrl(resourceId, "resourceId", false);
  return resourceId.replace(/\/+$/, "");
}

/** Derive the RFC 9728 endpoint-path protected-resource metadata URL. */
export function deriveResourceMetadataUrl(resourceId: string): string {
  const normalized = normalizeResourceId(resourceId);
  const resource = new URL(normalized);
  const resourcePath = resource.pathname === "/" ? "" : resource.pathname.replace(/\/+$/, "");
  const rawAuthority = /^https:\/\/([^/?#]*)/i.exec(normalized)?.[1] as string;
  const port = explicitPort(rawAuthority);
  const authority = `${resource.hostname}${port ? `:${Number(port)}` : ""}`;
  return `https://${authority}${PROTECTED_RESOURCE_WELL_KNOWN}${resourcePath}`;
}

/** Validate an explicit challenge URL while preserving its exact configured spelling. */
export function validateResourceMetadataUrl(resourceMetadataUrl: string): string {
  parseHttpsUrl(resourceMetadataUrl, "resourceMetadataUrl", true);
  return resourceMetadataUrl;
}

/** Validate one RFC 6749 scope-token before using it in policy or a response header. */
export function validateScopeToken(scope: string): string {
  if (typeof scope !== "string" || !SCOPE_TOKEN.test(scope)) {
    throw new TypeError(
      "scope values must be non-empty ASCII scope-token values without whitespace, quotes, or backslashes",
    );
  }
  return scope;
}

export function normalizeRequiredScopes(scopes: readonly string[]): string[] {
  return scopes.map(validateScopeToken);
}

/**
 * Build a resolver from explicit broader -> narrower declarations.
 *
 * Exact equality always satisfies a requirement. Declarations are transitive, and
 * cyclic declarations are rejected rather than assigned surprising semantics.
 */
export function createScopeResolver(
  implications: ScopeImplications = {},
): ScopeResolver {
  const graph = new Map<string, Set<string>>();
  for (const [broader, narrowerScopes] of Object.entries(implications)) {
    validateScopeToken(broader);
    const narrower = new Set<string>();
    for (const scope of narrowerScopes) {
      narrower.add(validateScopeToken(scope));
    }
    graph.set(broader, narrower);
  }

  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (scope: string): void => {
    if (visiting.has(scope)) {
      throw new TypeError(`scope implication cycle includes ${scope}`);
    }
    if (visited.has(scope)) return;
    visiting.add(scope);
    for (const implied of graph.get(scope) ?? []) visit(implied);
    visiting.delete(scope);
    visited.add(scope);
  };
  for (const scope of graph.keys()) visit(scope);

  return (grantedScope: string, requiredScope: string): boolean => {
    if (grantedScope === requiredScope) return true;
    const pending = [...(graph.get(grantedScope) ?? [])];
    const seen = new Set<string>();
    while (pending.length > 0) {
      const candidate = pending.pop();
      if (candidate === undefined || seen.has(candidate)) continue;
      if (candidate === requiredScope) return true;
      seen.add(candidate);
      pending.push(...(graph.get(candidate) ?? []));
    }
    return false;
  };
}

/**
 * Validate the public SPA origin used for browser redirects and __Host- cookies.
 * A raw API Gateway hostname is never the browser-facing unified entry.
 */
export function requireWebBaseUrl(name: string, value: string | undefined): string {
  if (!value || value.trim().length === 0) {
    throw new Error(`${name} is required and must be the public CloudFront/custom-domain origin`);
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS origin`);
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== '/' ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error(`${name} must be an HTTPS origin without path, query, or fragment`);
  }
  if (parsed.hostname.includes('.execute-api.') && parsed.hostname.endsWith('.amazonaws.com')) {
    throw new Error(`${name} must use the public CloudFront/custom-domain origin, not API Gateway`);
  }
  return parsed.origin;
}

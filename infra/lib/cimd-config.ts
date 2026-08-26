import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';

export function normalizeCimdDomains(
  domains: readonly string[],
  source: string,
): string[] {
  const normalized = domains.map((value) => {
    const domain = value.trim().replace(/\.+$/, '').toLowerCase();
    if (
      !domain ||
      /\s/u.test(domain) ||
      /[/:@*?#]/u.test(domain) ||
      isIP(domain) !== 0
    ) {
      throw new Error(`${source} contains invalid CIMD domain:${value}`);
    }
    const ascii = domainToASCII(domain);
    if (!ascii || ascii !== domain) {
      throw new Error(`${source} requires canonical ASCII CIMD domains:${value}`);
    }
    let parsed: URL;
    try {
      parsed = new URL(`https://${domain}/metadata`);
    } catch {
      throw new Error(`${source} contains invalid CIMD domain:${value}`);
    }
    if (parsed.hostname !== domain || parsed.port) {
      throw new Error(`${source} contains invalid CIMD domain:${value}`);
    }
    return domain;
  });
  return [...new Set(normalized)];
}

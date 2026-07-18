/**
 * Enforced registrable-domain blocklist and domain-removal checks.
 * Domains on this list (e.g., cloud metadata endpoints, prohibited domains, domains requesting opt-out via DOMAIN-REMOVAL.md)
 * are rejected before any network request or crawling activity occurs.
 */

export const DOMAIN_BLOCKLIST: ReadonlySet<string> = new Set([
  // Cloud metadata domains
  '169.254.169.254',
  'instance-data',
  'metadata.google.internal',
  'metadata.tencentyun.com',
  '100.100.100.200',
  'fd00:ec2::254',
  // Domains that requested removal via DOMAIN-REMOVAL.md (placeholder/examples for test verification)
  'optout-example-domain.com',
  'removed-customer-site.org'
]);

/**
 * Checks whether a hostname or registrable domain is on the enforced blocklist.
 */
export function isBlockedDomain(hostnameOrDomain: string): { blocked: boolean; reason?: string } {
  const cleanHost = hostnameOrDomain.toLowerCase().trim().replace(/\.$/, '');
  
  if (DOMAIN_BLOCKLIST.has(cleanHost)) {
    return { blocked: true, reason: `Domain '${cleanHost}' is explicitly prohibited by the enforced blocklist.` };
  }

  for (const blockedItem of DOMAIN_BLOCKLIST) {
    if (cleanHost === blockedItem || cleanHost.endsWith(`.${blockedItem}`)) {
      return { blocked: true, reason: `Host '${cleanHost}' matches blocked domain pattern '${blockedItem}'.` };
    }
  }

  return { blocked: false };
}

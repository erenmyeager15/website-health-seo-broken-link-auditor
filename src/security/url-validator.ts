import { URL } from 'node:url';
import net from 'node:net';
import { getDomain } from 'tldts';
import { isBlockedDomain } from './blocklist.js';

const blockedIpv4Ranges = new net.BlockList();
const blockedIpv6Ranges = new net.BlockList();

for (const [address, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blockedIpv4Ranges.addSubnet(address, prefix, 'ipv4');
}

for (const [address, prefix] of [
  ['::', 96],
  ['::ffff:0:0', 96],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 32],
  ['2001:2::', 48],
  ['2001:10::', 28],
  ['2001:20::', 28],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  blockedIpv6Ranges.addSubnet(address, prefix, 'ipv6');
}

/**
 * Checks if the given URL is the built-in example.com demo domain.
 */
export function isExampleComDemo(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    return host === 'example.com' || host === 'www.example.com';
  } catch {
    return false;
  }
}

/**
 * Validates startUrl authorization check (`confirmAuthorizedUse`).
 */
export function validateAuthorization(startUrl: string, confirmAuthorizedUse: boolean): void {
  if (!confirmAuthorizedUse && !isExampleComDemo(startUrl)) {
    throw new Error(
      `Unauthorized: confirmAuthorizedUse=true is required for auditing '${startUrl}'. ` +
      `Checking the box confirms existing authorization to scan the target website; it does not grant permission. ` +
      `Only the built-in demo domain example.com may be audited without checking this option.`
    );
  }
}

/**
 * Parses and decodes encoded/Punycode/hex/octal/decimal IP representations into standardized strings.
 */
export function parseAndNormalizeHostname(hostname: string): string {
  let clean = hostname.trim().toLowerCase().replace(/\.$/, '');

  // URL-decode any %-encoded characters (%31%32%37 -> 127)
  try {
    while (clean.includes('%')) {
      const decoded = decodeURIComponent(clean);
      if (decoded === clean) break;
      clean = decoded.toLowerCase();
    }
  } catch {
    // Malformed encoding
  }

  // Strip brackets from IPv6
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  return clean;
}

/**
 * Checks whether an IP address (IPv4 or IPv6 or representation) falls into private/loopback/reserved/metadata ranges.
 */
export function isPrivateOrBlockedIp(ipOrHost: string): { blocked: boolean; reason?: string } {
  const normalized = parseAndNormalizeHostname(ipOrHost);

  if (normalized === 'localhost' || normalized.endsWith('.localhost') || normalized === 'localhost.localdomain') {
    return { blocked: true, reason: `Host '${normalized}' resolves to loopback/localhost.` };
  }

  // Convert decimal/hex/octal/mixed IPv4 to standard dotted quad if possible
  const ipv4Quad = tryParseIpv4Representation(normalized);
  if (ipv4Quad) {
    return checkIpv4Ranges(ipv4Quad, ipOrHost);
  }

  // Check IPv6 / IPv4-mapped IPv6
  return checkIpv6Ranges(normalized, ipOrHost);
}

/**
 * Attempts to parse unusual IPv4 formats: decimal (`2130706433`), hex (`0x7f000001`), octal (`0177.0.0.1`), mixed parts (`127.1`).
 * Returns standard `A.B.C.D` string if valid IPv4 or null if not an IPv4 format.
 */
function tryParseIpv4Representation(host: string): string | null {
  // Pure decimal number (e.g. 2130706433 for 127.0.0.1)
  if (/^\d+$/.test(host)) {
    const num = BigInt(host);
    if (num >= 0n && num <= 4294967295n) {
      const a = Number((num >> 24n) & 255n);
      const b = Number((num >> 16n) & 255n);
      const c = Number((num >> 8n) & 255n);
      const d = Number(num & 255n);
      return `${a}.${b}.${c}.${d}`;
    }
  }

  // Hex host (0x7f000001)
  if (/^0x[0-9a-f]{1,8}$/i.test(host)) {
    const num = parseInt(host, 16);
    if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
      const a = (num >> 24) & 255;
      const b = (num >> 16) & 255;
      const c = (num >> 8) & 255;
      const d = num & 255;
      return `${a}.${b}.${c}.${d}`;
    }
  }

  // Dotted parts (could be octal, hex parts, or shortened like 127.1)
  const parts = host.split('.');
  if (parts.length >= 1 && parts.length <= 4) {
    let allNumeric = true;
    const parsedParts: number[] = [];

    for (const part of parts) {
      if (!part) {
        allNumeric = false;
        break;
      }
      let val: number;
      if (/^0x[0-9a-f]+$/i.test(part)) {
        val = parseInt(part, 16);
      } else if (/^0\d+$/.test(part)) {
        // Octal notation (e.g. 0177 -> 127)
        val = parseInt(part, 8);
      } else if (/^\d+$/.test(part)) {
        val = parseInt(part, 10);
      } else {
        allNumeric = false;
        break;
      }
      if (isNaN(val) || val < 0) {
        allNumeric = false;
        break;
      }
      parsedParts.push(val);
    }

    if (allNumeric && parsedParts.length > 0) {
      // Handle shortened notation (e.g., 127.1 -> 127.0.0.1)
      if (parsedParts.length === 4) {
        if (parsedParts.every(p => p <= 255)) {
          return parsedParts.join('.');
        }
      } else if (parsedParts.length === 1) {
        const num = parsedParts[0];
        if (num <= 0xffffffff) {
          return `${(num >> 24) & 255}.${(num >> 16) & 255}.${(num >> 8) & 255}.${num & 255}`;
        }
      } else if (parsedParts.length === 2) {
        const [a, d] = parsedParts;
        if (a <= 255 && d <= 0xffffff) {
          return `${a}.${(d >> 16) & 255}.${(d >> 8) & 255}.${d & 255}`;
        }
      } else if (parsedParts.length === 3) {
        const [a, b, d] = parsedParts;
        if (a <= 255 && b <= 255 && d <= 0xffff) {
          return `${a}.${b}.${(d >> 8) & 255}.${d & 255}`;
        }
      }
    }
  }

  return null;
}

function checkIpv4Ranges(ipv4: string, originalRepresentation: string): { blocked: boolean; reason?: string } {
  if (blockedIpv4Ranges.check(ipv4, 'ipv4')) {
    return {
      blocked: true,
      reason: `IP '${originalRepresentation}' (${ipv4}) belongs to a private, loopback, link-local, metadata-capable, benchmarking, documentation, multicast, or reserved IPv4 range.`,
    };
  }

  return { blocked: false };
}

function checkIpv6Ranges(host: string, originalRepresentation: string): { blocked: boolean; reason?: string } {
  if (net.isIP(host) !== 6) return { blocked: false };

  if (blockedIpv6Ranges.check(host, 'ipv6')) {
    return {
      blocked: true,
      reason: `IPv6 '${originalRepresentation}' belongs to a loopback, mapped, translation, private, link-local, documentation, tunneling, multicast, or reserved range.`,
    };
  }

  return { blocked: false };
}

/**
 * Full URL validation against SSRF, prohibited protocols, credentials, ports, blocklist, and private IPs.
 * Throws an Error if the URL is dangerous or invalid.
 */
export function validateUrlSafety(urlStr: string): { url: URL; hostname: string; registrableDomain: string } {
  let u: URL;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error(`Malformed URL: '${urlStr}' cannot be parsed.`);
  }

  // Protocol check
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error(`Prohibited protocol '${u.protocol}' in URL '${urlStr}'. Only HTTP and HTTPS are permitted.`);
  }

  // Credential check
  if (u.username || u.password) {
    throw new Error(`Security violation: URL credentials are strictly prohibited ('${urlStr}').`);
  }

  // Port check
  if (u.port && u.port !== '80' && u.port !== '443') {
    throw new Error(`Security violation: Custom port '${u.port}' in URL '${urlStr}' is prohibited. Only ports 80 and 443 are permitted.`);
  }

  const hostname = parseAndNormalizeHostname(u.hostname);

  // Blocklist check
  const blockCheck = isBlockedDomain(hostname);
  if (blockCheck.blocked) {
    throw new Error(`Blocked domain: ${blockCheck.reason}`);
  }

  // Private/Loopback/Metadata IP range check
  const ipCheck = isPrivateOrBlockedIp(hostname);
  if (ipCheck.blocked) {
    throw new Error(`SSRF security check failed: ${ipCheck.reason}`);
  }

  const registrableDomain = getDomain(hostname) || hostname;

  return { url: u, hostname, registrableDomain };
}

/**
 * Checks whether a target URL is within the authorized scope of the start URL.
 */
export function isSameScope(targetUrl: string, startRegistrableDomain: string): boolean {
  try {
    const validated = validateUrlSafety(targetUrl);
    return validated.registrableDomain === startRegistrableDomain;
  } catch {
    return false;
  }
}

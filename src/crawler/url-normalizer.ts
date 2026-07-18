import { URL } from 'node:url';

const TRACKING_PARAMS = new Set([
  'utm_source',
  'utm_medium',
  'utm_campaign',
  'utm_term',
  'utm_content',
  'gclid',
  'fbclid',
  'msclkid',
  '_ga',
  'mc_cid',
  'mc_eid',
  'ref',
  'source',
]);

/**
 * Normalizes a URL deterministically:
 * - Converts hostname and scheme to lowercase.
 * - Strips URL fragments (#hash).
 * - Strips common tracking query parameters.
 * - Sorts remaining query parameters alphabetically.
 * - Removes trailing slash from path unless root ('/').
 */
export function normalizeUrl(urlStr: string): string {
  try {
    const u = new URL(urlStr);
    u.hash = ''; // Strip fragment

    // Clean query params
    const params = Array.from(u.searchParams.entries());
    const filtered = params
      .filter(([key]) => !TRACKING_PARAMS.has(key.toLowerCase()))
      .sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]));

    u.search = '';
    for (const [key, value] of filtered) {
      u.searchParams.append(key, value);
    }

    // Normalize path trailing slash (except root)
    if (u.pathname !== '/' && u.pathname.endsWith('/')) {
      u.pathname = u.pathname.slice(0, -1);
    }

    return u.href;
  } catch {
    return urlStr;
  }
}

/**
 * Checks whether a URL exhibits signs of a crawl trap:
 * - Calendar / infinite date progressions (e.g. `/events/2026/07/18/next/next/next...` or repeated year/month paths).
 * - Excessive path depth (> 15 directory segments).
 * - Repeated identical directory segments (e.g. `/dir/dir/dir/dir`).
 * - Excessive query parameters (> 6 unique params or long query permutations).
 */
export function isCrawlTrap(urlStr: string): { isTrap: boolean; reason?: string } {
  try {
    const u = new URL(urlStr);
    const pathname = u.pathname;

    // Check directory depth
    const segments = pathname.split('/').filter(Boolean);
    if (segments.length > 15) {
      return { isTrap: true, reason: `Excessive directory path depth (${segments.length} segments).` };
    }

    // Check repeated identical directory segments (4 or more occurrences of the exact same segment)
    const segmentCounts = new Map<string, number>();
    for (const seg of segments) {
      const count = (segmentCounts.get(seg) || 0) + 1;
      if (count >= 4 && seg.length > 1) {
        return { isTrap: true, reason: `Repeated path segment '${seg}' found ${count} times in path.` };
      }
      segmentCounts.set(seg, count);
    }

    // Check calendar / infinite date progression loops (e.g. 3 or more date patterns like YYYY or MM/DD in path)
    const yearMatches = pathname.match(/\b(19|20)\d\d\b/g);
    if (yearMatches && yearMatches.length >= 3) {
      return { isTrap: true, reason: `Multiple year strings detected in path, indicating calendar progression trap.` };
    }

    const datePattern = /\b(19|20)\d\d[\/-](0[1-9]|1[0-2])[\/-](0[1-9]|[12]\d|3[01])\b/g;
    const dateMatches = pathname.match(datePattern);
    if (dateMatches && dateMatches.length >= 2) {
      return { isTrap: true, reason: `Multiple full dates detected in path, indicating calendar/event loop trap.` };
    }

    // Check query parameter count and permutations
    const paramKeys = Array.from(u.searchParams.keys());
    if (paramKeys.length > 6) {
      return { isTrap: true, reason: `Excessive query parameter count (${paramKeys.length} params).` };
    }

    // Check query value lengths or excessive permutations
    if (u.search.length > 300) {
      return { isTrap: true, reason: `Query string length exceeds 300 characters.` };
    }

    return { isTrap: false };
  } catch {
    return { isTrap: true, reason: `Malformed URL string.` };
  }
}

import http from 'node:http';
import https from 'node:https';
import { createRequire } from 'node:module';
import { URL } from 'node:url';
import { XMLParser } from 'fast-xml-parser';
import { createSecureAgents, resolveAndValidateHost } from '../security/dns-guard.js';
import { isSameScope, validateUrlSafety } from '../security/url-validator.js';

export const AUDITOR_USER_AGENT = 'WebsiteHealthSEOBrokenLinkAuditor';

interface RobotsParserInstance {
  isAllowed(url: string, userAgent?: string): boolean | undefined;
}

const require = createRequire(import.meta.url);
const robotsParser = require('robots-parser') as (url: string, text: string) => RobotsParserInstance;

export interface RobotsTxtData {
  parser: RobotsParserInstance;
  sitemapUrls: string[];
}

export interface SitemapFetchOptions {
  authorizedRegistrableDomain?: string;
  maxUrls?: number;
  maxSitemaps?: number;
  maxTotalBytes?: number;
}

interface BoundedTextResponse {
  text: string;
  finalUrl: string;
  bytes: number;
}

/**
 * Parses robots.txt with the maintained robots-parser package. We conservatively
 * require both the Actor-specific and wildcard policies to allow a URL.
 */
export function parseRobotsTxt(rawText: string, robotsUrl = 'https://example.com/robots.txt'): RobotsTxtData {
  const parser = robotsParser(robotsUrl, rawText);
  const sitemapUrls = rawText
    .split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, '').trim())
    .filter((line) => /^sitemap\s*:/i.test(line))
    .map((line) => line.slice(line.indexOf(':') + 1).trim())
    .filter(Boolean);

  return { parser, sitemapUrls: [...new Set(sitemapUrls)] };
}

/**
 * Robots rules cannot be disabled by input. `false` from either the exact
 * Actor user-agent or the wildcard policy is treated as disallowed.
 */
export function isAllowedByRobotsTxt(urlStr: string, robotsData: RobotsTxtData): boolean {
  try {
    const exact = robotsData.parser.isAllowed(urlStr, AUDITOR_USER_AGENT);
    const wildcard = robotsData.parser.isAllowed(urlStr, '*');
    return exact !== false && wildcard !== false;
  } catch {
    return false;
  }
}

/** Fetch robots.txt with connection-time DNS validation and a 1 MiB body cap. */
export async function fetchRobotsTxt(startUrl: string): Promise<RobotsTxtData> {
  const validated = validateUrlSafety(startUrl);
  const robotsUrl = `${validated.url.protocol}//${validated.url.host}/robots.txt`;
  const response = await fetchSecureBounded(
    robotsUrl,
    1 * 1024 * 1024,
    validated.registrableDomain,
  );

  return parseRobotsTxt(response?.text ?? '', robotsUrl);
}

/**
 * Fetches a bounded, in-scope sitemap graph. This caps recursion width, total
 * response bytes, and URL count across the whole graph rather than per file.
 */
export async function fetchAndParseSitemap(
  sitemapUrl: string,
  options: SitemapFetchOptions = {},
): Promise<Set<string>> {
  const initial = validateUrlSafety(sitemapUrl);
  const authorizedDomain = options.authorizedRegistrableDomain ?? initial.registrableDomain;
  const maxUrls = Math.min(Math.max(options.maxUrls ?? 10_000, 1), 50_000);
  const maxSitemaps = Math.min(Math.max(options.maxSitemaps ?? 25, 1), 100);
  const maxTotalBytes = Math.min(Math.max(options.maxTotalBytes ?? 25 * 1024 * 1024, 1), 100 * 1024 * 1024);
  const queue = [sitemapUrl];
  const seenSitemaps = new Set<string>();
  const urls = new Set<string>();
  let totalBytes = 0;

  const parser = new XMLParser({
    ignoreAttributes: false,
    processEntities: false,
    parseTagValue: false,
    trimValues: true,
  });

  while (queue.length > 0 && seenSitemaps.size < maxSitemaps && urls.size < maxUrls && totalBytes < maxTotalBytes) {
    const current = queue.shift();
    if (!current || seenSitemaps.has(current)) continue;
    seenSitemaps.add(current);

    if (!isSameScope(current, authorizedDomain)) continue;
    const remainingBytes = Math.min(10 * 1024 * 1024, maxTotalBytes - totalBytes);
    const response = await fetchSecureBounded(current, remainingBytes, authorizedDomain);
    if (!response) continue;
    totalBytes += response.bytes;

    let parsed: unknown;
    try {
      parsed = parser.parse(response.text);
    } catch {
      continue;
    }

    const sitemapEntries = toArray(getNested(parsed, ['sitemapindex', 'sitemap']));
    for (const entry of sitemapEntries) {
      const location = extractLocation(entry, response.finalUrl);
      if (location && isSameScope(location, authorizedDomain) && !seenSitemaps.has(location) && queue.length + seenSitemaps.size < maxSitemaps) {
        queue.push(location);
      }
    }

    const urlEntries = toArray(getNested(parsed, ['urlset', 'url']));
    for (const entry of urlEntries) {
      const location = extractLocation(entry, response.finalUrl);
      if (location && isSameScope(location, authorizedDomain)) {
        urls.add(location);
        if (urls.size >= maxUrls) break;
      }
    }
  }

  return urls;
}

function getNested(value: unknown, path: string[]): unknown {
  let cursor: unknown = value;
  for (const key of path) {
    if (!cursor || typeof cursor !== 'object' || !(key in cursor)) return undefined;
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor;
}

function toArray(value: unknown): unknown[] {
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function extractLocation(entry: unknown, baseUrl: string): string | undefined {
  if (!entry || typeof entry !== 'object') return undefined;
  const raw = (entry as Record<string, unknown>).loc;
  if (typeof raw !== 'string' || !raw.trim()) return undefined;
  try {
    return new URL(raw.trim(), baseUrl).href;
  } catch {
    return undefined;
  }
}

async function fetchSecureBounded(
  urlStr: string,
  maxBytes: number,
  allowedRegistrableDomain: string,
): Promise<BoundedTextResponse | null> {
  const agents = createSecureAgents();
  try {
    return await fetchSecureBoundedInternal(urlStr, maxBytes, allowedRegistrableDomain, agents, 0, new Set());
  } finally {
    agents.httpAgent.destroy();
    agents.httpsAgent.destroy();
  }
}

async function fetchSecureBoundedInternal(
  urlStr: string,
  maxBytes: number,
  allowedRegistrableDomain: string,
  agents: ReturnType<typeof createSecureAgents>,
  redirectDepth: number,
  visited: Set<string>,
): Promise<BoundedTextResponse | null> {
  if (redirectDepth > 5 || visited.has(urlStr) || !isSameScope(urlStr, allowedRegistrableDomain)) return null;
  visited.add(urlStr);

  const validated = validateUrlSafety(urlStr);
  await resolveAndValidateHost(validated.hostname);

  return await new Promise<BoundedTextResponse | null>((resolve) => {
    const isHttps = validated.url.protocol === 'https:';
    const requestFunc = isHttps ? https.request : http.request;
    const agent = isHttps ? agents.httpsAgent : agents.httpAgent;
    let settled = false;

    const finish = (value: BoundedTextResponse | null): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const request = requestFunc(
      validated.url,
      {
        method: 'GET',
        agent,
        maxHeaderSize: 32 * 1024,
        headers: {
          'User-Agent': `${AUDITOR_USER_AGENT}/1.0 (+https://apify.com)`,
          Accept: 'text/plain, application/xml, text/xml;q=0.9, */*;q=0.1',
          'Accept-Encoding': 'identity',
        },
      },
      (response) => {
        const statusCode = response.statusCode ?? 0;
        const location = response.headers.location;
        if (statusCode >= 300 && statusCode < 400 && location) {
          response.destroy();
          let nextUrl: string;
          try {
            nextUrl = new URL(location, urlStr).href;
            validateUrlSafety(nextUrl);
          } catch {
            finish(null);
            return;
          }
          void fetchSecureBoundedInternal(
            nextUrl,
            maxBytes,
            allowedRegistrableDomain,
            agents,
            redirectDepth + 1,
            visited,
          ).then(finish, () => finish(null));
          return;
        }

        if (statusCode < 200 || statusCode >= 300) {
          response.destroy();
          finish(null);
          return;
        }

        const declaredLength = Number(response.headers['content-length'] ?? 0);
        if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
          response.destroy();
          finish(null);
          return;
        }

        let receivedBytes = 0;
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => {
          receivedBytes += chunk.length;
          if (receivedBytes > maxBytes) {
            response.destroy();
            finish(null);
            return;
          }
          chunks.push(chunk);
        });
        response.once('end', () => {
          finish({ text: Buffer.concat(chunks).toString('utf8'), finalUrl: urlStr, bytes: receivedBytes });
        });
        response.once('error', () => finish(null));
      },
    );

    request.setTimeout(15_000, () => request.destroy(new Error('Request timed out after 15000ms.')));
    request.once('error', () => finish(null));
    request.end();
  });
}

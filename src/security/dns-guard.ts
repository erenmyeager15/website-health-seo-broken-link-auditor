import dns from 'node:dns/promises';
import type { LookupAddress, LookupOptions } from 'node:dns';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import zlib from 'node:zlib';
import { URL } from 'node:url';
import { isPrivateOrBlockedIp, isSameScope, validateUrlSafety } from './url-validator.js';

/**
 * Resolves all DNS A and AAAA records for a hostname and validates them against private/prohibited IP ranges.
 * Throws an Error if any resolved address belongs to a private/reserved/cloud-metadata range.
 */
export async function resolveAndValidateHost(hostname: string): Promise<string[]> {
  // First verify if the hostname itself is already an IP literal or blocked representation
  const directCheck = isPrivateOrBlockedIp(hostname);
  if (directCheck.blocked) {
    throw new Error(`DNS safety check check blocked hostname '${hostname}': ${directCheck.reason}`);
  }

  // If it's already an IP literal (IPv4 or IPv6), return it directly if valid
  if (net.isIP(hostname)) {
    return [hostname];
  }

  let records: LookupAddress[] = [];
  try {
    records = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(`DNS resolution failed for host '${hostname}': ${(err as Error).message}`);
  }

  if (!records || records.length === 0) {
    throw new Error(`DNS resolution returned zero addresses for host '${hostname}'.`);
  }

  const resolvedIps: string[] = [];
  for (const record of records) {
    const ipCheck = isPrivateOrBlockedIp(record.address);
    if (ipCheck.blocked) {
      throw new Error(
        `DNS Rebinding / SSRF protection triggered: Host '${hostname}' resolved to prohibited IP '${record.address}' (${ipCheck.reason}).`
      );
    }
    resolvedIps.push(record.address);
  }

  return resolvedIps;
}

/**
 * Validates redirect targets before following: verifies protocol, credentials, ports, blocklist, and pre-resolves DNS.
 */
export async function validateRedirectTarget(redirectUrlStr: string): Promise<void> {
  const { hostname } = validateUrlSafety(redirectUrlStr);
  await resolveAndValidateHost(hostname);
}

/**
 * Custom lookup hook for Node http/https agents (`lookup` option).
 * This ensures that immediately before the TCP socket connects, DNS resolution is performed and every
 * returned IP address is checked against private/prohibited IP ranges. This prevents DNS rebinding attacks
 * where a domain resolves to a safe public IP during initial check but to 127.0.0.1 / 169.254.169.254 during connection.
 */
export function secureLookupHook(
  hostname: string,
  options: LookupOptions | any,
  callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[] | any, family?: number) => void
): void {
  dns.lookup(hostname, { all: true, verbatim: true })
    .then((records) => {
      if (!records || records.length === 0) {
        return callback(new Error(`DNS lookup returned no records for ${hostname}`) as NodeJS.ErrnoException, '', 4);
      }

      for (const rec of records) {
        const ipCheck = isPrivateOrBlockedIp(rec.address);
        if (ipCheck.blocked) {
          const secError = new Error(
            `DNS Rebinding / SSRF connection blocked: Host '${hostname}' resolved to prohibited IP '${rec.address}' right before socket connect.`
          ) as NodeJS.ErrnoException;
          secError.code = 'ERR_SSRF_BLOCKED';
          return callback(secError, '', rec.family);
        }
      }

      // If options.all was requested, pass all records; otherwise pass the first safe address and family
      if (options.all) {
        return callback(null, records);
      } else {
        return callback(null, records[0].address, records[0].family);
      }
    })
    .catch((err) => {
      callback(err as NodeJS.ErrnoException, '', 4);
    });
}

/**
 * Creates custom HTTP and HTTPS agents with `secureLookupHook` enabled.
 * These agents can be passed into requests or used for safe external checks and HEAD requests.
 */
export function createSecureAgents(): { httpAgent: http.Agent; httpsAgent: https.Agent } {
  const httpAgent = new http.Agent({
    keepAlive: true,
    lookup: secureLookupHook as unknown as http.AgentOptions['lookup'],
    timeout: 15000,
  });

  const httpsAgent = new https.Agent({
    keepAlive: true,
    lookup: secureLookupHook as unknown as https.AgentOptions['lookup'],
    timeout: 15000,
  });

  return { httpAgent, httpsAgent };
}

export interface SecurePageResponse {
  statusCode: number;
  headers: http.IncomingHttpHeaders;
  body: string;
  finalUrl: string;
  redirectChain: string[];
}

export interface SecurePageFetchOptions {
  allowedRegistrableDomain: string;
  agents: ReturnType<typeof createSecureAgents>;
  maxBytes?: number;
  maxRedirects?: number;
  timeoutMs?: number;
}

/**
 * Fetches one authorized HTML page with manual, in-scope redirects and strict
 * compressed/decompressed body limits. Connection-time lookup uses the secure
 * agents, so DNS rebinding is checked immediately before the socket connects.
 */
export async function secureFetchPage(urlStr: string, options: SecurePageFetchOptions): Promise<SecurePageResponse> {
  const maxBytes = Math.min(Math.max(options.maxBytes ?? 5 * 1024 * 1024, 64 * 1024), 10 * 1024 * 1024);
  const maxRedirects = Math.min(Math.max(options.maxRedirects ?? 5, 0), 10);
  const timeoutMs = Math.min(Math.max(options.timeoutMs ?? 20_000, 1_000), 60_000);

  return await fetchPageInternal(urlStr, {
    ...options,
    maxBytes,
    maxRedirects,
    timeoutMs,
  }, [], new Set());
}

interface InternalPageFetchOptions extends SecurePageFetchOptions {
  maxBytes: number;
  maxRedirects: number;
  timeoutMs: number;
}

async function fetchPageInternal(
  urlStr: string,
  options: InternalPageFetchOptions,
  redirectChain: string[],
  visited: Set<string>,
): Promise<SecurePageResponse> {
  if (visited.has(urlStr)) throw new Error(`Redirect loop detected at '${urlStr}'.`);
  if (redirectChain.length > options.maxRedirects) {
    throw new Error(`Redirect limit of ${options.maxRedirects} exceeded.`);
  }
  visited.add(urlStr);

  const validated = validateUrlSafety(urlStr);
  if (!isSameScope(urlStr, options.allowedRegistrableDomain)) {
    throw new Error(`URL left the authorized registrable domain '${options.allowedRegistrableDomain}'.`);
  }
  await resolveAndValidateHost(validated.hostname);

  return await new Promise<SecurePageResponse>((resolve, reject) => {
    const isHttps = validated.url.protocol === 'https:';
    const requestFunc = isHttps ? https.request : http.request;
    const agent = isHttps ? options.agents.httpsAgent : options.agents.httpAgent;
    let settled = false;

    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const finish = (value: SecurePageResponse): void => {
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
          'User-Agent': 'WebsiteHealthSEOBrokenLinkAuditor/1.0 (+https://apify.com)',
          Accept: 'text/html, application/xhtml+xml;q=0.9, */*;q=0.1',
          'Accept-Encoding': 'gzip, deflate, br',
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
            if (!isSameScope(nextUrl, options.allowedRegistrableDomain)) {
              throw new Error(`Redirect left the authorized registrable domain '${options.allowedRegistrableDomain}'.`);
            }
          } catch (error) {
            fail(new Error(`Unsafe redirect from '${urlStr}': ${(error as Error).message}`));
            return;
          }
          void fetchPageInternal(nextUrl, options, [...redirectChain, nextUrl], visited).then(finish, fail);
          return;
        }

        const declaredLength = Number(response.headers['content-length'] ?? 0);
        if (Number.isFinite(declaredLength) && declaredLength > options.maxBytes) {
          response.destroy();
          fail(new Error(`Response exceeded the ${options.maxBytes}-byte body limit.`));
          return;
        }

        let receivedBytes = 0;
        const chunks: Buffer[] = [];
        response.on('data', (chunk: Buffer) => {
          receivedBytes += chunk.length;
          if (receivedBytes > options.maxBytes) {
            response.destroy();
            fail(new Error(`Response exceeded the ${options.maxBytes}-byte compressed body limit.`));
            return;
          }
          chunks.push(chunk);
        });
        response.once('error', (error) => fail(error));
        response.once('end', () => {
          if (settled) return;
          try {
            const compressed = Buffer.concat(chunks);
            const contentEncoding = response.headers['content-encoding'];
            const decoded = decodeResponseBody(
              compressed,
              Array.isArray(contentEncoding) ? contentEncoding[0] : contentEncoding,
              options.maxBytes,
            );
            finish({
              statusCode,
              headers: response.headers,
              body: decoded.toString('utf8'),
              finalUrl: urlStr,
              redirectChain,
            });
          } catch (error) {
            fail(error as Error);
          }
        });
      },
    );

    request.setTimeout(options.timeoutMs, () => request.destroy(new Error(`Request timed out after ${options.timeoutMs}ms.`)));
    request.once('error', fail);
    request.end();
  });
}

function decodeResponseBody(body: Buffer, contentEncoding: string | undefined, maxBytes: number): Buffer {
  const encoding = contentEncoding?.split(',')[0]?.trim().toLowerCase();
  const zlibOptions = { maxOutputLength: maxBytes };
  if (!encoding || encoding === 'identity') return body;
  if (encoding === 'gzip' || encoding === 'x-gzip') return zlib.gunzipSync(body, zlibOptions);
  if (encoding === 'deflate') return zlib.inflateSync(body, zlibOptions);
  if (encoding === 'br') return zlib.brotliDecompressSync(body, zlibOptions);
  throw new Error(`Unsupported content encoding '${contentEncoding}'.`);
}

export interface TlsInspectionResult {
  checked: boolean;
  valid?: boolean;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  error?: string;
}

/** Performs a real certificate handshake using the same connection-time DNS guard. */
export async function inspectTlsCertificate(urlStr: string, timeoutMs = 15_000): Promise<TlsInspectionResult> {
  try {
    const validated = validateUrlSafety(urlStr);
    if (validated.url.protocol !== 'https:') return { checked: false };
    await resolveAndValidateHost(validated.hostname);

    return await new Promise<TlsInspectionResult>((resolve) => {
      let settled = false;
      const finish = (value: TlsInspectionResult): void => {
        if (settled) return;
        settled = true;
        resolve(value);
      };

      const socket = tls.connect({
        host: validated.hostname,
        port: 443,
        servername: net.isIP(validated.hostname) ? undefined : validated.hostname,
        lookup: secureLookupHook as tls.ConnectionOptions['lookup'],
        rejectUnauthorized: true,
      });

      socket.setTimeout(timeoutMs, () => socket.destroy(new Error(`TLS handshake timed out after ${timeoutMs}ms.`)));
      socket.once('secureConnect', () => {
        const certificate = socket.getPeerCertificate();
        const validFromDate = certificate.valid_from ? new Date(certificate.valid_from) : undefined;
        const validToDate = certificate.valid_to ? new Date(certificate.valid_to) : undefined;
        const now = Date.now();
        const daysRemaining = validToDate && Number.isFinite(validToDate.getTime())
          ? Math.floor((validToDate.getTime() - now) / 86_400_000)
          : undefined;
        const valid = socket.authorized
          && Boolean(validFromDate && validToDate)
          && validFromDate!.getTime() <= now
          && validToDate!.getTime() >= now;
        const rawIssuer = certificate.issuer?.O || certificate.issuer?.CN;
        const issuer = Array.isArray(rawIssuer) ? rawIssuer.join(', ') : rawIssuer;

        socket.end();
        finish({
          checked: true,
          valid,
          issuer,
          validFrom: validFromDate && Number.isFinite(validFromDate.getTime()) ? validFromDate.toISOString() : undefined,
          validTo: validToDate && Number.isFinite(validToDate.getTime()) ? validToDate.toISOString() : undefined,
          daysRemaining,
          error: socket.authorized ? undefined : socket.authorizationError?.toString(),
        });
      });
      socket.once('error', (error) => finish({ checked: true, valid: false, error: error.message }));
    });
  } catch (error) {
    return { checked: true, valid: false, error: (error as Error).message };
  }
}

/**
 * Performs a secure HEAD request (or GET fallback) to check the status code of an external or internal link.
 * Automatically validates URL safety, DNS records, and enforces redirect revalidation.
 */
export interface SecureStatusCheckOptions {
  maxRedirects?: number;
  allowedRegistrableDomain?: string;
  agents?: ReturnType<typeof createSecureAgents>;
}

export interface SecureStatusResult {
  statusCode: number;
  contentType?: string;
  finalUrl: string;
  redirectChain: string[];
  errorMessage?: string;
}

export async function secureCheckUrlStatus(
  urlStr: string,
  method: 'HEAD' | 'GET' = 'HEAD',
  options: SecureStatusCheckOptions = {},
): Promise<SecureStatusResult> {
  const ownsAgents = !options.agents;
  const agents = options.agents ?? createSecureAgents();
  const maxRedirects = Math.min(Math.max(options.maxRedirects ?? 5, 0), 10);
  const visited = new Set<string>();

  try {
    return await requestStatus(urlStr, method, {
      agents,
      maxRedirects,
      allowedRegistrableDomain: options.allowedRegistrableDomain,
      visited,
      redirectChain: [],
    });
  } finally {
    if (ownsAgents) {
      agents.httpAgent.destroy();
      agents.httpsAgent.destroy();
    }
  }
}

interface InternalStatusOptions {
  agents: ReturnType<typeof createSecureAgents>;
  maxRedirects: number;
  allowedRegistrableDomain?: string;
  visited: Set<string>;
  redirectChain: string[];
}

async function requestStatus(
  urlStr: string,
  method: 'HEAD' | 'GET',
  options: InternalStatusOptions,
): Promise<SecureStatusResult> {
  const visitKey = `${method}:${urlStr}`;
  if (options.visited.has(visitKey)) {
    return {
      statusCode: 0,
      finalUrl: urlStr,
      redirectChain: options.redirectChain,
      errorMessage: 'Redirect loop detected.',
    };
  }
  options.visited.add(visitKey);

  try {
    const validated = validateUrlSafety(urlStr);
    if (options.allowedRegistrableDomain && !isSameScope(urlStr, options.allowedRegistrableDomain)) {
      throw new Error(`Redirect left the authorized registrable domain '${options.allowedRegistrableDomain}'.`);
    }
    await resolveAndValidateHost(validated.hostname);

    return await new Promise<SecureStatusResult>((resolve) => {
      const isHttps = validated.url.protocol === 'https:';
      const requestFunc = isHttps ? https.request : http.request;
      const agent = isHttps ? options.agents.httpsAgent : options.agents.httpAgent;

      const req = requestFunc(
        validated.url,
        {
          method,
          agent,
          maxHeaderSize: 32 * 1024,
          headers: {
            'User-Agent': 'WebsiteHealthSEOBrokenLinkAuditor/1.0 (+https://apify.com)',
            Accept: '*/*',
          },
        },
        (res) => {
          const statusCode = res.statusCode ?? 0;
          const contentType = res.headers['content-type'] || undefined;
          const location = res.headers.location;

          if (statusCode >= 300 && statusCode < 400 && location) {
            res.destroy();
            if (options.redirectChain.length >= options.maxRedirects) {
              resolve({
                statusCode: 0,
                finalUrl: urlStr,
                redirectChain: options.redirectChain,
                errorMessage: `Redirect limit of ${options.maxRedirects} exceeded.`,
              });
              return;
            }

            let nextUrl: string;
            try {
              nextUrl = new URL(location, urlStr).href;
              validateUrlSafety(nextUrl);
              if (options.allowedRegistrableDomain && !isSameScope(nextUrl, options.allowedRegistrableDomain)) {
                throw new Error(`Redirect left the authorized registrable domain '${options.allowedRegistrableDomain}'.`);
              }
            } catch (error) {
              resolve({
                statusCode: 0,
                finalUrl: urlStr,
                redirectChain: options.redirectChain,
                errorMessage: `Unsafe redirect target: ${(error as Error).message}`,
              });
              return;
            }

            void requestStatus(nextUrl, method, {
              ...options,
              redirectChain: [...options.redirectChain, nextUrl],
            }).then(resolve);
            return;
          }

          if (method === 'HEAD' && (statusCode === 405 || statusCode === 501)) {
            res.destroy();
            void requestStatus(urlStr, 'GET', options).then(resolve);
            return;
          }

          res.destroy();
          resolve({ statusCode, contentType, finalUrl: urlStr, redirectChain: options.redirectChain });
        },
      );

      req.setTimeout(15_000, () => req.destroy(new Error('Request timed out after 15000ms.')));
      req.once('error', (error) => {
        resolve({
          statusCode: 0,
          finalUrl: urlStr,
          redirectChain: options.redirectChain,
          errorMessage: error.message || 'Connection error.',
        });
      });
      req.end();
    });
  } catch (error) {
    return {
      statusCode: 0,
      finalUrl: urlStr,
      redirectChain: options.redirectChain,
      errorMessage: (error as Error).message,
    };
  }
}

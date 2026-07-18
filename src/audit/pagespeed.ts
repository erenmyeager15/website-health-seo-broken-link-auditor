import https from 'node:https';
import { URL } from 'node:url';

export interface PageSpeedResult {
  measured: boolean;
  labData?: {
    performanceScore: number;
    firstContentfulPaintMs: number;
    largestContentfulPaintMs: number;
    cumulativeLayoutShift: number;
    totalBlockingTimeMs: number;
  };
  fieldData?: {
    available: boolean;
    lcpMs?: number;
    fidMs?: number;
    inpMs?: number;
    cls?: number;
  };
  error?: string;
  skipped?: boolean;
  skipReason?: string;
}

/**
 * Redacts any occurrence of the PageSpeed API key from text or logs.
 */
export function redactApiKey(text: string, apiKey?: string): string {
  if (!apiKey || !apiKey.trim()) return text;
  return text.split(apiKey).join('[REDACTED_API_KEY]');
}

/**
 * Fetches PageSpeed Insights performance lab and field metrics for a URL.
 * Automatically skips cleanly on quota limits, timeouts, network errors, or when quota exceeded.
 * Never logs or returns the secret API key.
 */
export async function fetchPageSpeedMetrics(targetUrl: string, apiKey?: string): Promise<PageSpeedResult> {
  return new Promise((resolve) => {
    try {
      const endpoint = new URL('https://www.googleapis.com/pagespeedonline/v5/runPagespeed');
      endpoint.searchParams.set('url', targetUrl);
      endpoint.searchParams.set('category', 'PERFORMANCE');
      endpoint.searchParams.set('strategy', 'DESKTOP');
      if (apiKey && apiKey.trim()) {
        endpoint.searchParams.set('key', apiKey.trim());
      }

      const req = https.get(
        endpoint,
        {
          timeout: 25000,
          headers: {
            'User-Agent': 'WebsiteHealthSEOBrokenLinkAuditor/1.0 (Apify)',
            'Accept': 'application/json',
          },
        },
        (res) => {
          const statusCode = res.statusCode ?? 0;
          const maxResponseBytes = 2 * 1024 * 1024;
          const declaredLength = Number(res.headers['content-length'] ?? 0);
          if (Number.isFinite(declaredLength) && declaredLength > maxResponseBytes) {
            res.destroy();
            resolve({
              measured: false,
              skipped: true,
              skipReason: 'PageSpeed response exceeded the 2 MiB safety limit.',
            });
            return;
          }

          let body = '';
          let receivedBytes = 0;
          let responseTooLarge = false;

          res.on('data', (chunk) => {
            receivedBytes += Buffer.byteLength(chunk);
            if (receivedBytes > maxResponseBytes) {
              responseTooLarge = true;
              res.destroy();
              resolve({
                measured: false,
                skipped: true,
                skipReason: 'PageSpeed response exceeded the 2 MiB safety limit.',
              });
              return;
            }
            body += chunk;
          });

          res.on('end', () => {
            if (responseTooLarge) return;
            if (statusCode === 429) {
              resolve({
                measured: false,
                skipped: true,
                skipReason: 'Google PageSpeed API quota exceeded (HTTP 429). Skipping cleanly without failing audit.',
              });
              return;
            }

            if (statusCode !== 200) {
              const safeErr = redactApiKey(`PageSpeed API returned HTTP ${statusCode}: ${body.slice(0, 150)}`, apiKey);
              resolve({
                measured: false,
                skipped: true,
                skipReason: safeErr,
              });
              return;
            }

            try {
              const data = JSON.parse(body);

              // Extract lab data from Lighthouse audit metrics
              const lighthouse = data.lighthouseResult;
              let labData: PageSpeedResult['labData'];
              if (lighthouse && lighthouse.categories?.performance) {
                const score = (lighthouse.categories.performance.score ?? 0) * 100;
                const audits = lighthouse.audits ?? {};
                const fcp = audits['first-contentful-paint']?.numericValue ?? 0;
                const lcp = audits['largest-contentful-paint']?.numericValue ?? 0;
                const cls = audits['cumulative-layout-shift']?.numericValue ?? 0;
                const tbt = audits['total-blocking-time']?.numericValue ?? 0;

                labData = {
                  performanceScore: Math.round(score),
                  firstContentfulPaintMs: Math.round(fcp),
                  largestContentfulPaintMs: Math.round(lcp),
                  cumulativeLayoutShift: Number(cls.toFixed(3)),
                  totalBlockingTimeMs: Math.round(tbt),
                };
              }

              // Extract field data from Chrome User Experience Report (CrUX)
              const loadingExperience = data.loadingExperience?.metrics;
              let fieldData: PageSpeedResult['fieldData'];
              if (loadingExperience && Object.keys(loadingExperience).length > 0) {
                fieldData = {
                  available: true,
                  lcpMs: loadingExperience.LARGEST_CONTENTFUL_PAINT_MS?.percentile,
                  fidMs: loadingExperience.FIRST_INPUT_DELAY_MS?.percentile,
                  inpMs: loadingExperience.INTERACTION_TO_NEXT_PAINT?.percentile,
                  cls: loadingExperience.CUMULATIVE_LAYOUT_SHIFT_SCORE?.percentile
                    ? loadingExperience.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile / 100
                    : undefined,
                };
              } else {
                fieldData = { available: false };
              }

              resolve({
                measured: true,
                labData,
                fieldData,
              });
            } catch (parseErr) {
              resolve({
                measured: false,
                skipped: true,
                skipReason: `Failed to parse PageSpeed JSON response: ${(parseErr as Error).message}`,
              });
            }
          });
        }
      );

      req.on('timeout', () => {
        req.destroy();
        resolve({
          measured: false,
          skipped: true,
          skipReason: 'PageSpeed Insights request timed out after 25 seconds.',
        });
      });

      req.on('error', (err) => {
        resolve({
          measured: false,
          skipped: true,
          skipReason: redactApiKey(`PageSpeed request connection error: ${err.message}`, apiKey),
        });
      });
    } catch (err) {
      resolve({
        measured: false,
        skipped: true,
        skipReason: redactApiKey(`PageSpeed error: ${(err as Error).message}`, apiKey),
      });
    }
  });
}

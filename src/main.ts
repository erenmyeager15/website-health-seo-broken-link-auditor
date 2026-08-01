import { Actor, log } from 'apify';
import { BasicCrawler } from '@crawlee/basic';
import { load } from 'cheerio';
import { URL } from 'node:url';
import type { AuditIssue, ActorInput, BrokenLinkItem, PageAuditRecord } from './types.js';
import { validateAuthorization, validateUrlSafety, isSameScope } from './security/url-validator.js';
import {
  createSecureAgents,
  inspectTlsCertificate,
  resolveAndValidateHost,
  secureCheckUrlStatus,
  secureFetchPage,
} from './security/dns-guard.js';
import { normalizeUrl, isCrawlTrap } from './crawler/url-normalizer.js';
import { fetchRobotsTxt, fetchAndParseSitemap, isAllowedByRobotsTxt } from './crawler/robots-sitemap.js';
import { createIssueFingerprint, evaluateLinkRules, evaluatePageRules } from './audit/rules-engine.js';
import { fetchPageSpeedMetrics } from './audit/pagespeed.js';
import { loadBaseline, saveBaseline, compareWithBaseline } from './baseline/regression-tracker.js';
import { atomicPushAndChargePage, getPageAuditAllowance } from './billing/charging.js';
import { saveReportsAndSummary } from './reports/reporter.js';

interface PageLinks {
  internal: string[];
  external: string[];
  malformed: BrokenLinkItem[];
}

interface LinkStatus {
  statusCode?: number;
  errorMessage?: string;
  blocked: boolean;
  finalUrl?: string;
}

const BLOCKED_STATUSES = new Set([401, 403, 429, 451]);
const MAX_INTERNAL_LINK_CHECKS = 5_000;

await Actor.init();

try {
  const rawInput = await Actor.getInput<ActorInput>() ?? {
    startUrl: 'https://example.com',
    confirmAuthorizedUse: false,
  };

  if (!rawInput.startUrl) throw new Error('startUrl parameter is required.');
  validateAuthorization(rawInput.startUrl, Boolean(rawInput.confirmAuthorizedUse));
  const { url: startUrlObject, registrableDomain } = validateUrlSafety(rawInput.startUrl);
  const startUrlNormalized = normalizeUrl(startUrlObject.href);

  const requestedMaxPages = clamp(rawInput.maxPages ?? 25, 1, 250);
  const maxCrawlDepth = clamp(rawInput.maxCrawlDepth ?? 3, 0, 10);
  const maxLinksPerPage = clamp(rawInput.maxLinksPerPage ?? 100, 1, 500);
  const checkExternalLinks = rawInput.checkExternalLinks ?? false;
  const maxExternalLinks = clamp(rawInput.maxExternalLinks ?? 250, 0, 2_000);
  const includePerformance = rawInput.includePerformance ?? false;
  const maxPerformancePages = clamp(rawInput.maxPerformancePages ?? 1, 1, 5);
  const compareWithPreviousRun = rawInput.compareWithPreviousRun ?? true;
  const generateHtmlReport = rawInput.generateHtmlReport ?? true;
  const generatePdfReport = rawInput.generatePdfReport ?? false;
  const failOnSeverity = rawInput.failOnSeverity ?? 'none';
  const paidPageAllowance = getPageAuditAllowance(requestedMaxPages);
  if (paidPageAllowance < 1) {
    throw new Error('The run maximum cost cannot cover one page-audited event. Increase the run budget and try again.');
  }
  const maxPages = Math.min(requestedMaxPages, paidPageAllowance);

  log.info(`Starting authorized website audit for ${startUrlNormalized}`, {
    registrableDomain,
    maxPages,
    maxCrawlDepth,
    maxLinksPerPage,
    checkExternalLinks,
    includePerformance,
  });

  await resolveAndValidateHost(startUrlObject.hostname);

  const robotsCache = new Map<string, ReturnType<typeof fetchRobotsTxt>>();
  const getRobotsForUrl = (urlStr: string) => {
    const origin = new URL(urlStr).origin;
    let promise = robotsCache.get(origin);
    if (!promise) {
      promise = fetchRobotsTxt(urlStr);
      robotsCache.set(origin, promise);
    }
    return promise;
  };

  const startRobots = await getRobotsForUrl(startUrlNormalized);
  const sitemapUrls = new Set<string>();
  const defaultSitemapUrl = `${startUrlObject.protocol}//${startUrlObject.host}/sitemap.xml`;
  const sitemapCandidates = [...new Set([defaultSitemapUrl, ...startRobots.sitemapUrls])]
    .filter((url) => isSameScope(url, registrableDomain))
    .slice(0, 5);

  for (const sitemapCandidate of sitemapCandidates) {
    const discovered = await fetchAndParseSitemap(sitemapCandidate, {
      authorizedRegistrableDomain: registrableDomain,
      maxUrls: Math.min(maxPages * 20, 5_000),
      maxSitemaps: 10,
      maxTotalBytes: 10 * 1024 * 1024,
    });
    for (const url of discovered) sitemapUrls.add(normalizeUrl(url));
  }
  log.info(`Loaded ${sitemapUrls.size} in-scope sitemap URL(s).`);

  const loadedBaseline = compareWithPreviousRun
    ? await loadBaseline(registrableDomain, rawInput.baselineKey)
    : undefined;

  const secureAgents = createSecureAgents();
  const tlsCache = new Map<string, ReturnType<typeof inspectTlsCertificate>>();
  const seenRequestedUrls = new Set<string>([startUrlNormalized]);
  const seenFinalUrls = new Set<string>();
  const pageRecords: PageAuditRecord[] = [];
  const pageLinks = new Map<string, PageLinks>();
  const linkStatuses = new Map<string, LinkStatus>();
  const externalCandidates = new Set<string>();
  let performanceAttempts = 0;
  let crawlHadFailures = false;

  try {
    const crawler = new BasicCrawler({
      maxConcurrency: 2,
      minConcurrency: 1,
      sameDomainDelaySecs: 1,
      maxRequestRetries: 1,
      retryOnBlocked: false,
      useSessionPool: false,
      requestHandlerTimeoutSecs: 45,
      maxRequestsPerCrawl: maxPages,
      requestHandler: async ({ request }) => {
        const requestedUrl = request.url;
        const requestedNormalized = normalizeUrl(requestedUrl);
        const depth = Number(request.userData.depth ?? 0);
        const trap = isCrawlTrap(requestedUrl);
        if (trap.isTrap) {
          log.info(`Skipped crawl trap (${trap.reason}): ${requestedUrl}`);
          return;
        }

        const robotsData = await getRobotsForUrl(requestedUrl);
        if (!isAllowedByRobotsTxt(requestedUrl, robotsData)) {
          log.info(`Skipped URL disallowed by robots.txt: ${requestedUrl}`);
          return;
        }

        const response = await secureFetchPage(requestedUrl, {
          allowedRegistrableDomain: registrableDomain,
          agents: secureAgents,
          maxBytes: 5 * 1024 * 1024,
          maxRedirects: 5,
          timeoutMs: 20_000,
        });
        const finalNormalized = normalizeUrl(response.finalUrl);
        if (seenFinalUrls.has(finalNormalized)) return;

        const finalRobots = await getRobotsForUrl(response.finalUrl);
        if (!isAllowedByRobotsTxt(response.finalUrl, finalRobots)) {
          log.info(`Skipped redirect target disallowed by robots.txt: ${response.finalUrl}`);
          return;
        }
        seenFinalUrls.add(finalNormalized);

        const contentType = headerValue(response.headers['content-type']) || 'application/octet-stream';
        const isHtml = contentType.includes('text/html') || contentType.includes('application/xhtml+xml');
        const $ = load(isHtml ? response.body : '');
        const title = isHtml ? $('title').first().text().trim() || null : null;
        const metaDescription = isHtml ? $('meta[name="description"]').attr('content')?.trim() || null : null;
        const canonicalUrl = resolveOptionalUrl($('link[rel="canonical"]').attr('href'), response.finalUrl);
        const robotsMeta = isHtml
          ? $('meta[name="robots"]').map((_, element) => $(element).attr('content')?.toLowerCase().trim()).get().filter(Boolean)
          : [];
        const xRobotsTag = toHeaderArray(response.headers['x-robots-tag']).map((value) => value.toLowerCase().trim());
        const robotsTxtAllowed = isAllowedByRobotsTxt(response.finalUrl, finalRobots);
        const isNoindex = [...robotsMeta, ...xRobotsTag].some((value) => value.includes('noindex'));

        const h1Texts = isHtml ? $('h1').map((_, element) => $(element).text().trim()).get() : [];
        const totalImages = isHtml ? $('img').length : 0;
        let missingAltCount = 0;
        if (isHtml) {
          $('img').each((_, element) => {
            const alt = $(element).attr('alt');
            const role = $(element).attr('role')?.toLowerCase();
            if (alt === undefined || (!alt.trim() && role !== 'presentation' && role !== 'none')) missingAltCount++;
          });
        }

        const links: PageLinks = { internal: [], external: [], malformed: [] };
        const perPageSeen = new Set<string>();
        if (isHtml) {
          $('a[href]').each((_, element) => {
            if (perPageSeen.size >= maxLinksPerPage) return;
            const rawHref = $(element).attr('href')?.trim();
            if (!rawHref || /^(#|mailto:|tel:|javascript:|data:)/i.test(rawHref)) return;

            try {
              const absolute = new URL(rawHref, response.finalUrl).href;
              validateUrlSafety(absolute);
              const normalized = normalizeUrl(absolute);
              if (perPageSeen.has(normalized)) return;
              perPageSeen.add(normalized);

              if (isSameScope(normalized, registrableDomain)) {
                links.internal.push(normalized);
              } else {
                links.external.push(normalized);
                if (checkExternalLinks && externalCandidates.size < maxExternalLinks) externalCandidates.add(normalized);
              }
            } catch (error) {
              links.malformed.push({
                url: rawHref,
                errorMessage: `Malformed or unsafe link target: ${(error as Error).message}`,
                isExternal: false,
              });
            }
          });
        }

        if (depth < maxCrawlDepth) {
          const toEnqueue = links.internal
            .filter((url) => !seenRequestedUrls.has(url) && !isCrawlTrap(url).isTrap)
            .slice(0, Math.max(0, maxPages - seenRequestedUrls.size));
          for (const url of toEnqueue) seenRequestedUrls.add(url);
          if (toEnqueue.length > 0) {
            await crawler.addRequests(toEnqueue.map((url) => ({ url, userData: { depth: depth + 1 } })));
          }
        }

        let performanceSummary: PageAuditRecord['performanceSummary'] = { measured: false };
        if (includePerformance && response.statusCode === 200 && performanceAttempts < maxPerformancePages) {
          performanceAttempts++;
          performanceSummary = await fetchPageSpeedMetrics(response.finalUrl, rawInput.pageSpeedApiKey);
        }

        let tlsSummary: PageAuditRecord['tlsSummary'] = { checked: false };
        if (response.finalUrl.startsWith('https://')) {
          const origin = new URL(response.finalUrl).origin;
          let tlsPromise = tlsCache.get(origin);
          if (!tlsPromise) {
            tlsPromise = inspectTlsCertificate(response.finalUrl);
            tlsCache.set(origin, tlsPromise);
          }
          tlsSummary = await tlsPromise;
        }

        const record: PageAuditRecord = {
          recordType: 'page_audit',
          url: response.finalUrl,
          normalizedUrl: finalNormalized,
          statusCode: response.statusCode,
          contentType,
          redirectChain: response.redirectChain,
          title,
          metaDescription,
          canonicalUrl,
          indexability: {
            isIndexable: response.statusCode === 200 && !isNoindex && robotsTxtAllowed,
            robotsMeta,
            xRobotsTag,
            robotsTxtAllowed,
            reason: !robotsTxtAllowed ? 'Disallowed by robots.txt' : isNoindex ? 'Marked noindex' : undefined,
          },
          headings: {
            h1Count: h1Texts.length,
            h1Texts,
            h2Count: isHtml ? $('h2').length : 0,
            h3Count: isHtml ? $('h3').length : 0,
          },
          linkSummary: {
            internalLinksCount: links.internal.length,
            externalLinksCount: links.external.length,
            brokenLinksCount: links.malformed.length,
            blockedLinksCount: 0,
          },
          brokenLinks: [...links.malformed],
          imageSummary: { totalImages, missingAltCount },
          sitemapContext: {
            inSitemap: sitemapUrls.has(finalNormalized),
            sitemapUrl: sitemapUrls.has(finalNormalized) ? defaultSitemapUrl : undefined,
          },
          performanceSummary,
          tlsSummary,
          securityHeaders: {
            strictTransportSecurity: headerValue(response.headers['strict-transport-security']),
            contentSecurityPolicy: headerValue(response.headers['content-security-policy']),
            xContentTypeOptions: headerValue(response.headers['x-content-type-options']),
            xFrameOptions: headerValue(response.headers['x-frame-options']),
            referrerPolicy: headerValue(response.headers['referrer-policy']),
            permissionsPolicy: headerValue(response.headers['permissions-policy']),
          },
          issues: [],
          score: 100,
          auditedAt: new Date().toISOString(),
        };

        record.issues = evaluatePageRules(record, $);
        pageRecords.push(record);
        pageLinks.set(finalNormalized, links);

        const observedStatus: LinkStatus = {
          statusCode: response.statusCode,
          blocked: BLOCKED_STATUSES.has(response.statusCode),
          finalUrl: response.finalUrl,
        };
        linkStatuses.set(requestedNormalized, observedStatus);
        linkStatuses.set(finalNormalized, observedStatus);
        log.info(`Fetched page [${pageRecords.length}/${maxPages}]: ${response.finalUrl}`);
      },
      failedRequestHandler: async ({ request }, error) => {
        crawlHadFailures = true;
        log.warning(`Failed to audit '${request.url}': ${error.message}`);
      },
    });

    await crawler.run([{ url: startUrlNormalized, userData: { depth: 0 } }]);

    if (pageRecords.length === 0) {
      throw new Error('Zero useful pages were audited. Check the URL, authorization, robots.txt policy, and run log.');
    }

    const allInternalLinks = [...new Set([...pageLinks.values()].flatMap((links) => links.internal))]
      .slice(0, MAX_INTERNAL_LINK_CHECKS);
    const allExternalLinks = checkExternalLinks ? [...externalCandidates].slice(0, maxExternalLinks) : [];
    const linksToCheck = [...allInternalLinks, ...allExternalLinks]
      .filter((url) => !linkStatuses.has(url));

    const scheduleByHost = createHostPacedScheduler();
    await mapWithConcurrency(linksToCheck, 4, async (url) => {
      const internal = isSameScope(url, registrableDomain);
      const result = await scheduleByHost(url, internal ? 1_000 : 250, async () => {
        return await secureCheckUrlStatus(url, 'HEAD', {
          maxRedirects: 5,
          allowedRegistrableDomain: internal ? registrableDomain : undefined,
          agents: secureAgents,
        });
      });
      linkStatuses.set(url, {
        statusCode: result.statusCode || undefined,
        errorMessage: result.errorMessage,
        blocked: BLOCKED_STATUSES.has(result.statusCode),
        finalUrl: result.finalUrl,
      });
    });

    const checkedTargets = new Set<string>();
    const brokenTargets = new Set<string>();
    const blockedTargets = new Set<string>();
    for (const record of pageRecords) {
      const links = pageLinks.get(record.normalizedUrl) ?? { internal: [], external: [], malformed: [] };
      for (const [isExternal, targets] of [[false, links.internal], [true, links.external]] as const) {
        for (const target of targets) {
          const status = linkStatuses.get(target);
          if (!status) continue;
          checkedTargets.add(target);
          if (status.blocked) {
            blockedTargets.add(target);
            record.brokenLinks.push({
              url: target,
              statusCode: status.statusCode,
              errorMessage: status.errorMessage,
              isExternal,
            });
          } else if (isBrokenStatus(status)) {
            brokenTargets.add(target);
            record.brokenLinks.push({
              url: target,
              statusCode: status.statusCode,
              errorMessage: status.errorMessage,
              isExternal,
            });
          }
        }
      }
      record.linkSummary.brokenLinksCount = record.brokenLinks.filter((link) => !BLOCKED_STATUSES.has(link.statusCode ?? -1)).length;
      record.linkSummary.blockedLinksCount = record.brokenLinks.filter((link) => BLOCKED_STATUSES.has(link.statusCode ?? -1)).length;
      record.issues.push(...evaluateLinkRules(record));
    }

    addDuplicateMetadataIssues(pageRecords);

    for (const record of pageRecords) record.score = calculatePageScore(record.issues);

    const storedRecords: PageAuditRecord[] = [];
    let spendingLimitReached = false;
    for (const record of pageRecords) {
      const result = await atomicPushAndChargePage(record);
      if (result.success) storedRecords.push(record);
      if (result.limitReached) {
        spendingLimitReached = true;
        break;
      }
    }
    if (storedRecords.length === 0) throw new Error('No page audit records could be stored within the run budget.');

    const allIssuesWithUrls = storedRecords.flatMap((record) => record.issues.map((issue) => ({ issue, url: record.url })));
    const totalErrors = allIssuesWithUrls.filter(({ issue }) => issue.severity === 'critical' || issue.severity === 'error').length;
    const totalWarnings = allIssuesWithUrls.filter(({ issue }) => issue.severity === 'warning').length;
    const averageScore = storedRecords.reduce((sum, record) => sum + record.score, 0) / storedRecords.length;
    const comparableBaseline = loadedBaseline?.domain === registrableDomain
      && loadedBaseline.summary.pagesAudited === storedRecords.length
      ? loadedBaseline
      : undefined;
    const baselineCompared = Boolean(comparableBaseline);
    const regression = baselineCompared
      ? compareWithBaseline(allIssuesWithUrls, comparableBaseline)
      : { newIssues: 0, resolvedIssues: 0, unchangedIssues: 0, materiallyChangedIssues: 0 };
    const ciPassed = !allIssuesWithUrls.some(({ issue }) => {
      if (failOnSeverity === 'critical') return issue.severity === 'critical';
      if (failOnSeverity === 'error') return issue.severity === 'critical' || issue.severity === 'error';
      return false;
    });

    const summary = await saveReportsAndSummary(
      storedRecords.length,
      checkedTargets.size,
      brokenTargets.size,
      blockedTargets.size,
      totalErrors,
      totalWarnings,
      averageScore,
      regression,
      baselineCompared,
      ciPassed,
      storedRecords,
      allIssuesWithUrls,
      generateHtmlReport,
      generatePdfReport,
    );

    const baselineEligible = compareWithPreviousRun
      && !crawlHadFailures
      && !spendingLimitReached
      && storedRecords.length === pageRecords.length;
    if (baselineEligible) {
      await saveBaseline(
        registrableDomain,
        allIssuesWithUrls,
        storedRecords.length,
        averageScore,
        rawInput.baselineKey,
      );
    } else if (compareWithPreviousRun) {
      log.warning('The prior baseline was preserved because this audit was partial or hit a run limit.');
    }

    log.info('Audit finished.', {
      pagesAudited: summary.pagesAudited,
      score: summary.score,
      ciPassed: summary.ciPassed,
      reports: summary.reports,
    });

    if (!ciPassed) {
      await Actor.fail(`Audit completed, but the '${failOnSeverity}' severity threshold was breached.`);
    }
  } finally {
    secureAgents.httpAgent.destroy();
    secureAgents.httpsAgent.destroy();
  }
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  log.error(`Actor failed: ${message}`);
  await Actor.fail(message);
} finally {
  await Actor.exit();
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.min(Math.max(Math.trunc(value), minimum), maximum);
}

function headerValue(value: string | string[] | undefined): string | null {
  if (Array.isArray(value)) return value.join('; ');
  return typeof value === 'string' ? value : null;
}

function toHeaderArray(value: string | string[] | undefined): string[] {
  if (Array.isArray(value)) return value;
  return typeof value === 'string' ? [value] : [];
}

function resolveOptionalUrl(value: string | undefined, baseUrl: string): string | null {
  if (!value?.trim()) return null;
  try {
    return new URL(value.trim(), baseUrl).href;
  } catch {
    return null;
  }
}

function isBrokenStatus(status: LinkStatus): boolean {
  return Boolean(status.errorMessage)
    || status.statusCode === undefined
    || status.statusCode === 0
    || status.statusCode >= 400;
}

async function mapWithConcurrency<T>(
  values: T[],
  concurrency: number,
  worker: (value: T) => Promise<void>,
): Promise<void> {
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (nextIndex < values.length) {
      const index = nextIndex++;
      await worker(values[index]);
    }
  });
  await Promise.all(workers);
}

function createHostPacedScheduler() {
  const chains = new Map<string, Promise<void>>();
  const lastStartedAt = new Map<string, number>();

  return async function schedule<T>(url: string, delayMs: number, task: () => Promise<T>): Promise<T> {
    const host = new URL(url).hostname;
    const prior = chains.get(host) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    chains.set(host, prior.catch(() => undefined).then(() => current));
    await prior.catch(() => undefined);

    const elapsed = Date.now() - (lastStartedAt.get(host) ?? 0);
    if (elapsed < delayMs) await new Promise((resolve) => setTimeout(resolve, delayMs - elapsed));
    lastStartedAt.set(host, Date.now());
    try {
      return await task();
    } finally {
      release();
    }
  };
}

function addDuplicateMetadataIssues(records: PageAuditRecord[]): void {
  addDuplicateIssues(records, 'title', 'DUPLICATE_TITLE', 'Duplicate HTML title');
  addDuplicateIssues(records, 'metaDescription', 'DUPLICATE_META_DESCRIPTION', 'Duplicate meta description');
}

function addDuplicateIssues(
  records: PageAuditRecord[],
  field: 'title' | 'metaDescription',
  ruleId: string,
  label: string,
): void {
  const groups = new Map<string, PageAuditRecord[]>();
  for (const record of records) {
    const value = record[field]?.trim().toLowerCase();
    if (!value) continue;
    const group = groups.get(value) ?? [];
    group.push(record);
    groups.set(value, group);
  }

  for (const group of groups.values()) {
    if (group.length < 2) continue;
    for (const record of group) {
      const value = record[field] ?? '';
      record.issues.push({
        ruleId,
        severity: 'warning',
        category: 'SEO',
        message: `${label} is shared by ${group.length} audited pages.`,
        evidence: `${field}: ${value}`,
        recommendation: `Give each indexable page a unique, descriptive ${field === 'title' ? 'title' : 'meta description'}.`,
        fingerprint: createIssueFingerprint(ruleId, record.url, value.toLowerCase()),
      });
    }
  }
}

function calculatePageScore(issues: AuditIssue[]): number {
  const penalty = issues.reduce((total, issue) => {
    if (issue.severity === 'critical') return total + 25;
    if (issue.severity === 'error') return total + 15;
    if (issue.severity === 'warning') return total + 5;
    return total;
  }, 0);
  return Math.max(0, Number((100 - penalty).toFixed(1)));
}

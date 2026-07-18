import crypto from 'node:crypto';
import type { PageAuditRecord, AuditIssue, IssueSeverity } from '../types.js';

/**
 * Generates a deterministic, stable SHA-256 fingerprint for an issue across runs.
 * Uses ruleId, exact affected URL, and concise evidence so minor layout changes don't break fingerprint stability.
 */
export function createIssueFingerprint(ruleId: string, url: string, evidenceKey: string): string {
  const hash = crypto.createHash('sha256');
  hash.update(`${ruleId.trim()}:${url.trim()}:${evidenceKey.trim()}`);
  return hash.digest('hex');
}

function addIssue(
  issues: AuditIssue[],
  ruleId: string,
  severity: IssueSeverity,
  category: string,
  message: string,
  evidence: string,
  recommendation: string,
  url: string,
  evidenceKey = evidence
): void {
  issues.push({
    ruleId,
    severity,
    category,
    message,
    evidence,
    recommendation,
    fingerprint: createIssueFingerprint(ruleId, url, evidenceKey),
  });
}

/** Evaluates link results after the bounded crawl and link-check phases finish. */
export function evaluateLinkRules(record: PageAuditRecord): AuditIssue[] {
  const issues: AuditIssue[] = [];
  for (const brokenLink of record.brokenLinks) {
    if ([401, 403, 429, 451].includes(brokenLink.statusCode ?? -1)) {
      addIssue(
        issues,
        'BLOCKED_LINK_INFO',
        'info',
        'LINKS',
        `Link target returned HTTP ${brokenLink.statusCode} (Blocked/Restricted).`,
        `Target: ${brokenLink.url} (Status: ${brokenLink.statusCode})`,
        'Classified as blocked/unavailable. Verify whether the target requires human verification or authentication.',
        record.url,
        `blocked-${brokenLink.url}`,
      );
    } else if (brokenLink.isExternal) {
      addIssue(
        issues,
        'BROKEN_EXTERNAL_LINK',
        'warning',
        'LINKS',
        'External link on this page is broken or unreachable.',
        `Target: ${brokenLink.url} (Status: ${brokenLink.statusCode ?? `Error: ${brokenLink.errorMessage}`})`,
        'Remove or update the broken external link.',
        record.url,
        `broken-ext-${brokenLink.url}`,
      );
    } else {
      addIssue(
        issues,
        'BROKEN_INTERNAL_LINK',
        'error',
        'LINKS',
        'Internal link on this page points to a broken or non-existent URL.',
        `Target: ${brokenLink.url} (Status: ${brokenLink.statusCode ?? `Error: ${brokenLink.errorMessage}`})`,
        'Fix the broken internal link or restore the missing target page.',
        record.url,
        `broken-int-${brokenLink.url}`,
      );
    }
  }
  return issues;
}

/**
 * Runs all evidence-based checks on a crawled page record and its cheerio DOM.
 */
export function evaluatePageRules(record: PageAuditRecord, $: any): AuditIssue[] {
  const issues: AuditIssue[] = [];
  const url = record.url;

  // 1. HTTP Status & Redirect checks
  if (record.statusCode >= 400) {
    if (record.statusCode === 401 || record.statusCode === 403 || record.statusCode === 429 || record.statusCode === 451) {
      addIssue(
        issues,
        'BLOCKED_PAGE_INFO',
        'info',
        'SECURITY',
        `Page returned HTTP ${record.statusCode} (Blocked/Access Restricted).`,
        `HTTP Status: ${record.statusCode}`,
        `Verify if rate limiting, bot protection, or authentication requirement applies. Classified as blocked/unavailable rather than broken.`,
        url,
        `status-${record.statusCode}`
      );
    } else if (record.statusCode >= 500) {
      addIssue(
        issues,
        'SERVER_ERROR',
        'critical',
        'STATUS',
        `Server returned error status code ${record.statusCode}.`,
        `HTTP Status: ${record.statusCode}`,
        `Inspect server logs and backend application health to resolve the 5xx status code.`,
        url,
        `status-${record.statusCode}`
      );
    } else {
      addIssue(
        issues,
        'BROKEN_PAGE',
        'error',
        'STATUS',
        `Page returned client error HTTP ${record.statusCode}.`,
        `HTTP Status: ${record.statusCode}`,
        `Fix or redirect this broken URL to a valid page with a 301 redirect.`,
        url,
        `status-${record.statusCode}`
      );
    }
  }

  if (record.redirectChain.length > 5) {
    addIssue(
      issues,
      'EXCESSIVE_REDIRECTS',
      'error',
      'STATUS',
      `Page followed an excessive redirect chain (${record.redirectChain.length} hops).`,
      `Chain: ${record.redirectChain.join(' -> ')}`,
      `Reduce redirect chain to a single direct 301 hop to improve crawl efficiency and page load speed.`,
      url,
      `redirect-hops`
    );
  } else if (record.redirectChain.length > 2) {
    addIssue(
      issues,
      'REDIRECT_CHAIN',
      'warning',
      'STATUS',
      `Page followed a multi-hop redirect chain (${record.redirectChain.length} hops).`,
      `Chain: ${record.redirectChain.join(' -> ')}`,
      `Update internal links and redirect configurations to point directly to the final destination URL.`,
      url,
      `redirect-chain`
    );
  }

  // Link checks run after the crawl; evaluateLinkRules() is appended then.

  // Only run HTML content checks if 200 OK and HTML content
  if (record.statusCode !== 200 || !record.contentType.includes('text/html')) {
    return issues;
  }

  // 3. Title Tags
  if (!record.title || !record.title.trim()) {
    addIssue(
      issues,
      'TITLE_MISSING',
      'error',
      'SEO',
      `Page is missing the <title> tag or it is empty.`,
      `Title: ${record.title === null ? 'missing' : 'empty'}`,
      `Add a descriptive, keyword-relevant <title> tag between 10 and 60 characters.`,
      url,
      'title-missing'
    );
  } else {
    const titleLen = record.title.trim().length;
    if (titleLen < 10) {
      addIssue(
        issues,
        'TITLE_TOO_SHORT',
        'warning',
        'SEO',
        `Page <title> tag is overly short (${titleLen} characters).`,
        `Title: "${record.title}"`,
        `Expand the title tag to clearly describe the page content (recommended 30-60 characters).`,
        url,
        'title-short'
      );
    } else if (titleLen > 60) {
      addIssue(
        issues,
        'TITLE_TOO_LONG',
        'warning',
        'SEO',
        `Page <title> tag exceeds recommended length (${titleLen} characters > 60).`,
        `Title: "${record.title}"`,
        `Keep title tags under 60 characters to prevent truncation in search engine results pages.`,
        url,
        'title-long'
      );
    }
  }

  // 4. Meta Descriptions
  if (!record.metaDescription || !record.metaDescription.trim()) {
    addIssue(
      issues,
      'META_DESC_MISSING',
      'warning',
      'SEO',
      `Page is missing a <meta name="description"> tag.`,
      `Meta description: missing`,
      `Add a compelling meta description summarizing the page content (50-160 characters).`,
      url,
      'meta-desc-missing'
    );
  } else {
    const descLen = record.metaDescription.trim().length;
    if (descLen < 50) {
      addIssue(
        issues,
        'META_DESC_TOO_SHORT',
        'warning',
        'SEO',
        `Meta description is overly short (${descLen} characters).`,
        `Description: "${record.metaDescription}"`,
        `Expand the meta description to provide better context for users in search results.`,
        url,
        'meta-desc-short'
      );
    } else if (descLen > 160) {
      addIssue(
        issues,
        'META_DESC_TOO_LONG',
        'warning',
        'SEO',
        `Meta description exceeds recommended length (${descLen} characters > 160).`,
        `Description: "${record.metaDescription.slice(0, 80)}..."`,
        `Keep meta descriptions under 160 characters to avoid truncation in search snippets.`,
        url,
        'meta-desc-long'
      );
    }
  }

  // 5. Headings (<h1>)
  if (record.headings.h1Count === 0) {
    addIssue(
      issues,
      'H1_MISSING',
      'error',
      'SEO',
      `Page is missing an <h1> heading.`,
      `h1Count: 0`,
      `Include exactly one main <h1> heading clearly stating the topic of the page.`,
      url,
      'h1-missing'
    );
  } else if (record.headings.h1Count > 1) {
    addIssue(
      issues,
      'H1_MULTIPLE',
      'warning',
      'SEO',
      `Page has multiple <h1> headings (${record.headings.h1Count} tags).`,
      `H1 Texts: ${record.headings.h1Texts.join(' | ')}`,
      `Use a single primary <h1> heading per page and organize sub-sections using <h2> and <h3> tags.`,
      url,
      'h1-multiple'
    );
  }
  if (record.headings.h1Texts.some(t => !t.trim())) {
    addIssue(
      issues,
      'H1_EMPTY',
      'error',
      'SEO',
      `Page contains an empty <h1> tag.`,
      `Empty H1 element found in DOM.`,
      `Ensure all <h1> headings contain descriptive, non-empty text.`,
      url,
      'h1-empty'
    );
  }

  // 6. Canonical URLs
  if (!record.canonicalUrl) {
    addIssue(
      issues,
      'CANONICAL_MISSING',
      'warning',
      'SEO',
      `Page is missing the <link rel="canonical"> tag.`,
      `Canonical: missing`,
      `Specify a self-referencing canonical URL to prevent duplicate content issues across URL variations.`,
      url,
      'canonical-missing'
    );
  } else {
    try {
      const canonicalU = new URL(record.canonicalUrl, url);
      const pageU = new URL(url);
      if (canonicalU.hostname !== pageU.hostname && !canonicalU.hostname.endsWith(`.${pageU.hostname}`) && !pageU.hostname.endsWith(`.${canonicalU.hostname}`)) {
        addIssue(
          issues,
          'CANONICAL_MISMATCH',
          'error',
          'SEO',
          `Canonical link points to a completely different domain (${canonicalU.hostname}).`,
          `Canonical: ${record.canonicalUrl}`,
          `Verify that the canonical URL correctly reflects the authorized domain and intended master version of this page.`,
          url,
          'canonical-domain-mismatch'
        );
      }
    } catch {
      addIssue(
        issues,
        'CANONICAL_BROKEN',
        'error',
        'SEO',
        `Canonical tag contains a malformed or invalid URL.`,
        `Canonical value: "${record.canonicalUrl}"`,
        `Fix the <link rel="canonical"> href value to be a valid absolute URL.`,
        url,
        'canonical-broken'
      );
    }
  }

  // 7. Robots Meta & Indexability Conflicts
  if (!record.indexability.isIndexable) {
    addIssue(
      issues,
      'ROBOTS_NOINDEX',
      'info',
      'INDEXABILITY',
      `Page has noindex or disallow instruction (${record.indexability.reason || 'noindex'}).`,
      `Robots Meta: ${record.indexability.robotsMeta.join(', ')} | X-Robots-Tag: ${record.indexability.xRobotsTag.join(', ')} | robots.txt allowed: ${record.indexability.robotsTxtAllowed}`,
      `Ensure that noindex is intentional for this page and not blocking public content from search engines.`,
      url,
      'noindex-detected'
    );
  }
  if (record.sitemapContext.inSitemap && !record.indexability.isIndexable) {
    addIssue(
      issues,
      'INDEXABILITY_CONFLICT',
      'error',
      'INDEXABILITY',
      `Conflict: Page is included in sitemap.xml but is marked noindex or disallowed by robots.txt.`,
      `inSitemap: true | isIndexable: false (${record.indexability.reason})`,
      `Remove non-indexable or disallowed pages from your XML sitemap so search engines only crawl valid URLs.`,
      url,
      'sitemap-conflict'
    );
  }
  if (record.indexability.isIndexable && record.sitemapContext.sitemapUrl && !record.sitemapContext.inSitemap) {
    addIssue(
      issues,
      'SITEMAP_URL_MISSING',
      'info',
      'INDEXABILITY',
      `Page is indexable (200 OK) but not found in the discovered XML sitemap.`,
      `Sitemap inspected: ${record.sitemapContext.sitemapUrl}`,
      `Add this important indexable page to your XML sitemap to assist discovery.`,
      url,
      'missing-from-sitemap'
    );
  }

  // 8. Lang & Viewport Metadata
  const langAttr = $('html').attr('lang');
  if (!langAttr || !langAttr.trim()) {
    addIssue(
      issues,
      'LANG_MISSING',
      'error',
      'ACCESSIBILITY',
      `The <html> tag is missing a valid 'lang' attribute.`,
      `html lang="${langAttr ?? ''}"`,
      `Specify the document language (e.g. <html lang="en">) for accessibility and screen readers.`,
      url,
      'lang-missing'
    );
  }
  const viewportMeta = $('meta[name="viewport"]').attr('content');
  if (!viewportMeta || !viewportMeta.trim()) {
    addIssue(
      issues,
      'VIEWPORT_MISSING',
      'error',
      'MOBILE',
      `Page is missing the <meta name="viewport"> tag for mobile responsiveness.`,
      `Viewport meta: missing`,
      `Add <meta name="viewport" content="width=device-width, initial-scale=1.0"> inside the <head>.`,
      url,
      'viewport-missing'
    );
  }

  // 9. Open Graph Basics
  const ogTitle = $('meta[property="og:title"]').attr('content');
  const ogDesc = $('meta[property="og:description"]').attr('content');
  const ogImg = $('meta[property="og:image"]').attr('content');
  if (!ogTitle || !ogDesc || !ogImg) {
    const missingOg: string[] = [];
    if (!ogTitle) missingOg.push('og:title');
    if (!ogDesc) missingOg.push('og:description');
    if (!ogImg) missingOg.push('og:image');
    addIssue(
      issues,
      'OG_TAGS_MISSING',
      'info',
      'SOCIAL',
      `Page is missing Open Graph tags: ${missingOg.join(', ')}.`,
      `Missing Open Graph metadata`,
      `Include og:title, og:description, and og:image to ensure rich previews on social media platforms.`,
      url,
      `og-missing-${missingOg.join('-')}`
    );
  }

  // 10. Structured Data (JSON-LD) Syntax
  $('script[type="application/ld+json"]').each((_: any, el: any) => {
    const rawJson = $(el).html();
    if (rawJson && rawJson.trim()) {
      try {
        JSON.parse(rawJson);
      } catch (err) {
        addIssue(
          issues,
          'STRUCTURED_DATA_SYNTAX_ERROR',
          'error',
          'SEO',
          `Invalid JSON syntax inside <script type="application/ld+json"> structured data block.`,
          `Syntax Error: ${(err as Error).message}`,
          `Validate and fix JSON-LD syntax using Google Rich Results Test or JSON validator.`,
          url,
          'json-ld-error'
        );
      }
    }
  });

  // 11. Image Alt Text
  if (record.imageSummary.missingAltCount > 0) {
    addIssue(
      issues,
      'IMAGE_ALT_MISSING',
      'warning',
      'ACCESSIBILITY',
      `${record.imageSummary.missingAltCount} out of ${record.imageSummary.totalImages} images are missing the 'alt' attribute.`,
      `missingAltCount: ${record.imageSummary.missingAltCount}`,
      `Add descriptive alt text to meaningful images and empty alt="" to decorative images for accessibility and SEO.`,
      url,
      'img-alt-missing'
    );
  }

  // 12. Mixed Content Check
  if (url.startsWith('https://')) {
    let mixedFound = false;
    $('img[src], script[src], link[rel="stylesheet"][href], iframe[src]').each((_: any, el: any) => {
      const src = $(el).attr('src') || $(el).attr('href');
      if (src && src.toLowerCase().startsWith('http://')) {
        mixedFound = true;
      }
    });
    if (mixedFound) {
      addIssue(
        issues,
        'MIXED_CONTENT',
        'error',
        'SECURITY',
        `Page loaded via HTTPS references insecure HTTP resources (images, scripts, styles, or iframes).`,
        `Insecure http:// resource detected in DOM`,
        `Update all resource references to use https:// or relative paths to prevent mixed-content browser warnings.`,
        url,
        'mixed-content'
      );
    }
  }

  // 13. TLS Certificate Checks
  if (record.tlsSummary.checked && record.tlsSummary.valid === false) {
    addIssue(
      issues,
      'TLS_INVALID',
      'critical',
      'SECURITY',
      `HTTPS TLS certificate is invalid or expired (${record.tlsSummary.error || 'Check failed'}).`,
      `TLS valid: false | Error: ${record.tlsSummary.error || 'expired/untrusted'}`,
      `Renew or correct the TLS/SSL certificate immediately to protect visitor data and prevent browser security blocks.`,
      url,
      'tls-invalid'
    );
  } else if (record.tlsSummary.checked && typeof record.tlsSummary.daysRemaining === 'number') {
    if (record.tlsSummary.daysRemaining <= 0) {
      addIssue(
        issues,
        'TLS_EXPIRED',
        'critical',
        'SECURITY',
        `TLS certificate has expired (${record.tlsSummary.daysRemaining} days remaining).`,
        `Valid To: ${record.tlsSummary.validTo}`,
        `Renew your TLS certificate immediately to restore secure HTTPS access.`,
        url,
        'tls-expired'
      );
    } else if (record.tlsSummary.daysRemaining < 30) {
      addIssue(
        issues,
        'TLS_EXPIRING_SOON',
        'warning',
        'SECURITY',
        `TLS certificate will expire in ${record.tlsSummary.daysRemaining} days.`,
        `Valid To: ${record.tlsSummary.validTo}`,
        `Schedule certificate renewal before expiration to avoid service interruption.`,
        url,
        'tls-expiring'
      );
    }
  }

  // 14. Informational Security-Header Checks
  const missingHeaders: string[] = [];
  if (!record.securityHeaders.strictTransportSecurity && url.startsWith('https://')) {
    missingHeaders.push('Strict-Transport-Security (HSTS)');
  }
  if (!record.securityHeaders.contentSecurityPolicy) {
    missingHeaders.push('Content-Security-Policy (CSP)');
  }
  if (!record.securityHeaders.xContentTypeOptions) {
    missingHeaders.push('X-Content-Type-Options');
  }
  if (!record.securityHeaders.xFrameOptions) {
    missingHeaders.push('X-Frame-Options');
  }
  if (!record.securityHeaders.referrerPolicy) {
    missingHeaders.push('Referrer-Policy');
  }

  if (missingHeaders.length > 0) {
    addIssue(
      issues,
      'SECURITY_HEADER_MISSING',
      'info',
      'SECURITY',
      `Informational: One or more recommended security response headers are not configured (${missingHeaders.join(', ')}).`,
      `Missing headers: ${missingHeaders.join(', ')}`,
      `Header checks are configuration observations, not a vulnerability assessment. Consider configuring HSTS, CSP, and X-Content-Type-Options according to OWASP guidelines to strengthen defense-in-depth.`,
      url,
      `missing-sec-headers`
    );
  }

  return issues;
}

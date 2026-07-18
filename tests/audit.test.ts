import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as cheerio from 'cheerio';
import { evaluateLinkRules, evaluatePageRules, createIssueFingerprint } from '../src/audit/rules-engine.js';
import { redactApiKey } from '../src/audit/pagespeed.js';
import { compareWithBaseline } from '../src/baseline/regression-tracker.js';
import type { PageAuditRecord, BaselineStore } from '../src/types.js';

describe('Audit Rules Engine, Stable Fingerprints & Regression Tracking', () => {
  test('Stable Issue Fingerprinting across runs', () => {
    const fp1 = createIssueFingerprint('TITLE_MISSING', 'https://example.com/page', 'title-missing');
    const fp2 = createIssueFingerprint('TITLE_MISSING', 'https://example.com/page', 'title-missing');
    const fpOther = createIssueFingerprint('TITLE_MISSING', 'https://example.com/other', 'title-missing');

    assert.equal(fp1, fp2, 'Fingerprint for exact same issue and URL must be strictly deterministic across calls.');
    assert.notEqual(fp1, fpOther, 'Fingerprint must vary when affected URL changes.');
  });

  test('Evidence-based SEO and Security Rules Evaluation', () => {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Short</title>
</head>
<body>
  <h1>Multiple H1 - First</h1>
  <h1>Multiple H1 - Second</h1>
  <img src="insecure.png" />
  <script src="http://insecure-cdn.com/app.js"></script>
</body>
</html>`;

    const $ = cheerio.load(html);
    const mockRecord: PageAuditRecord = {
      recordType: 'page_audit',
      url: 'https://example.com/test',
      normalizedUrl: 'https://example.com/test',
      statusCode: 200,
      contentType: 'text/html',
      redirectChain: [],
      title: 'Short',
      metaDescription: null,
      canonicalUrl: null,
      indexability: { isIndexable: true, robotsMeta: [], xRobotsTag: [], robotsTxtAllowed: true },
      headings: { h1Count: 2, h1Texts: ['Multiple H1 - First', 'Multiple H1 - Second'], h2Count: 0, h3Count: 0 },
      linkSummary: { internalLinksCount: 0, externalLinksCount: 0, brokenLinksCount: 0, blockedLinksCount: 0 },
      brokenLinks: [],
      imageSummary: { totalImages: 1, missingAltCount: 1 },
      sitemapContext: { inSitemap: false },
      performanceSummary: { measured: false },
      tlsSummary: { checked: true, valid: true, daysRemaining: 90 },
      securityHeaders: {
        strictTransportSecurity: null,
        contentSecurityPolicy: null,
        xContentTypeOptions: null,
        xFrameOptions: null,
        referrerPolicy: null,
        permissionsPolicy: null,
      },
      issues: [],
      score: 100,
      auditedAt: new Date().toISOString(),
    };

    const issues = evaluatePageRules(mockRecord, $);
    const ruleIds = new Set(issues.map(i => i.ruleId));

    assert.equal(ruleIds.has('TITLE_TOO_SHORT'), true, 'Expected TITLE_TOO_SHORT warning');
    assert.equal(ruleIds.has('META_DESC_MISSING'), true, 'Expected META_DESC_MISSING warning');
    assert.equal(ruleIds.has('H1_MULTIPLE'), true, 'Expected H1_MULTIPLE warning');
    assert.equal(ruleIds.has('CANONICAL_MISSING'), true, 'Expected CANONICAL_MISSING warning');
    assert.equal(ruleIds.has('VIEWPORT_MISSING'), true, 'Expected VIEWPORT_MISSING error');
    assert.equal(ruleIds.has('IMAGE_ALT_MISSING'), true, 'Expected IMAGE_ALT_MISSING warning');
    assert.equal(ruleIds.has('MIXED_CONTENT'), true, 'Expected MIXED_CONTENT error due to http script on https page');
    assert.equal(ruleIds.has('SECURITY_HEADER_MISSING'), true, 'Expected SECURITY_HEADER_MISSING informational check');
  });

  test('PageSpeed Secret API Key Redaction', () => {
    const secretKey = 'AIzaSySecretApiKey1234567890';
    const logText = `Request to PageSpeed API failed with key AIzaSySecretApiKey1234567890 due to quota limit.`;
    const redacted = redactApiKey(logText, secretKey);

    assert.equal(redacted.includes(secretKey), false, 'API key must not be present after redaction.');
    assert.equal(redacted.includes('[REDACTED_API_KEY]'), true);
  });

  test('Baseline Regression Diffing (New, Resolved, Unchanged, Materially Changed)', () => {
    const url = 'https://example.com/page';
    const fpUnchanged = createIssueFingerprint('TITLE_MISSING', url, 'title-missing');
    const fpResolved = createIssueFingerprint('H1_MISSING', url, 'h1-missing');
    const fpOldSeverity = createIssueFingerprint('BROKEN_INTERNAL_LINK', url, 'broken-old');
    const fpNewSeverity = createIssueFingerprint('BROKEN_INTERNAL_LINK', url, 'broken-new');
    const fpNewIssue = createIssueFingerprint('CANONICAL_MISSING', url, 'canonical-missing');

    const mockBaseline: BaselineStore = {
      domain: 'example.com',
      updatedAt: '2026-07-01T00:00:00Z',
      summary: { pagesAudited: 1, score: 80 },
      issues: {
        [fpUnchanged]: { ruleId: 'TITLE_MISSING', severity: 'error', url, fingerprint: fpUnchanged },
        [fpResolved]: { ruleId: 'H1_MISSING', severity: 'error', url, fingerprint: fpResolved },
        [fpOldSeverity]: { ruleId: 'BROKEN_INTERNAL_LINK', severity: 'warning', url, fingerprint: fpOldSeverity },
      },
    };

    const currentIssues = [
      { issue: { ruleId: 'TITLE_MISSING', severity: 'error' as const, category: 'SEO', message: '', evidence: '', recommendation: '', fingerprint: fpUnchanged }, url },
      { issue: { ruleId: 'BROKEN_INTERNAL_LINK', severity: 'error' as const, category: 'LINKS', message: '', evidence: '', recommendation: '', fingerprint: fpNewSeverity }, url },
      { issue: { ruleId: 'CANONICAL_MISSING', severity: 'warning' as const, category: 'SEO', message: '', evidence: '', recommendation: '', fingerprint: fpNewIssue }, url },
    ];

    const comparison = compareWithBaseline(currentIssues, mockBaseline);

    assert.equal(comparison.unchangedIssues, 1, 'Expected exactly 1 unchanged issue (TITLE_MISSING)');
    assert.equal(comparison.resolvedIssues, 1, 'Expected exactly 1 resolved issue (H1_MISSING)');
    assert.equal(comparison.materiallyChangedIssues, 1, 'Expected exactly 1 materially changed issue (BROKEN_INTERNAL_LINK)');
    assert.equal(comparison.newIssues, 1, 'Expected exactly 1 new issue (CANONICAL_MISSING)');
  });

  test('Broken and blocked links receive distinct classifications', () => {
    const record = {
      recordType: 'page_audit',
      url: 'https://example.com/',
      brokenLinks: [
        { url: 'https://example.com/missing', statusCode: 404, isExternal: false },
        { url: 'https://outside.example/limited', statusCode: 429, isExternal: true },
      ],
    } as PageAuditRecord;
    const rules = evaluateLinkRules(record);
    assert.deepEqual(rules.map((rule) => rule.ruleId), ['BROKEN_INTERNAL_LINK', 'BLOCKED_LINK_INFO']);
  });
});

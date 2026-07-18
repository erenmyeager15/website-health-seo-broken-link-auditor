import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { atomicPushAndChargePage } from '../src/billing/charging.js';
import {
  escapeHtml,
  generateDeterministicAgentSummary,
  generateHtmlReportString,
  generatePdfReportBuffer,
  HTML_REPORT_CONTENT_TYPE,
} from '../src/reports/reporter.js';
import type { AuditSummary, PageAuditRecord } from '../src/types.js';

describe('Billing Safety & Reporting Summary', () => {
  test('Blocked or non-200/300 status codes do not charge as useful pages', async () => {
    const blockedRecord: PageAuditRecord = {
      recordType: 'page_audit',
      url: 'https://example.com/blocked',
      normalizedUrl: 'https://example.com/blocked',
      statusCode: 403,
      contentType: 'text/html',
      redirectChain: [],
      title: null,
      metaDescription: null,
      canonicalUrl: null,
      indexability: { isIndexable: false, robotsMeta: [], xRobotsTag: [], robotsTxtAllowed: true },
      headings: { h1Count: 0, h1Texts: [], h2Count: 0, h3Count: 0 },
      linkSummary: { internalLinksCount: 0, externalLinksCount: 0, brokenLinksCount: 0, blockedLinksCount: 1 },
      brokenLinks: [],
      imageSummary: { totalImages: 0, missingAltCount: 0 },
      sitemapContext: { inSitemap: false },
      performanceSummary: { measured: false },
      tlsSummary: { checked: false },
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

    const res = await atomicPushAndChargePage(blockedRecord);
    assert.equal(res.success, false, 'Expected 403 blocked record to not be pushed/charged as useful page.');
  });

  test('Deterministic Agent Summary generation without LLM', () => {
    const summaryStr = generateDeterministicAgentSummary(
      10,
      120,
      2,
      1,
      1,
      4,
      85.5,
      { newIssues: 2, resolvedIssues: 5, unchangedIssues: 12, materiallyChangedIssues: 1 },
      true
    );

    assert.equal(summaryStr.includes('PASSED'), true);
    assert.equal(summaryStr.includes('85.5/100'), true);
    assert.equal(summaryStr.includes('Audited 10 page(s)'), true);
    assert.equal(summaryStr.includes('2 new issue(s), 5 resolved issue(s)'), true);
  });

  test('HTML report escapes all target-controlled text', () => {
    const malicious = '<script>alert("owned")</script>';
    const summary: AuditSummary = {
      pagesAudited: 0,
      linksChecked: 0,
      brokenLinks: 0,
      blockedLinks: 0,
      errors: 1,
      warnings: 0,
      score: 0,
      newIssues: 1,
      resolvedIssues: 0,
      unchangedIssues: 0,
      materiallyChangedIssues: 0,
      baselineCompared: false,
      ciPassed: false,
      agentSummary: malicious,
      reports: { jsonSummaryUrl: '', htmlReportUrl: '' },
    };
    const html = generateHtmlReportString(summary, [], [{
      url: 'https://example.com/',
      issue: {
        ruleId: 'TEST',
        severity: 'error',
        category: 'TEST',
        message: malicious,
        evidence: malicious,
        recommendation: malicious,
        fingerprint: 'test',
      },
    }]);

    assert.equal(html.includes(malicious), false);
    assert.equal(html.includes(escapeHtml(malicious)), true);
    assert.equal(html.includes('Content-Security-Policy'), true);
  });

  test('HTML report content type matches the Apify key-value store schema', () => {
    const schema = JSON.parse(readFileSync(resolve('.actor/key_value_store_schema.json'), 'utf8')) as {
      collections: { htmlReport: { contentTypes: string[] } };
    };
    assert.equal(HTML_REPORT_CONTENT_TYPE, 'text/html');
    assert.equal(schema.collections.htmlReport.contentTypes.includes(HTML_REPORT_CONTENT_TYPE), true);
  });

  test('PDF report generator returns a real PDF document', async () => {
    const summary: AuditSummary = {
      pagesAudited: 0,
      linksChecked: 0,
      brokenLinks: 0,
      blockedLinks: 0,
      errors: 0,
      warnings: 0,
      score: 100,
      newIssues: 0,
      resolvedIssues: 0,
      unchangedIssues: 0,
      materiallyChangedIssues: 0,
      baselineCompared: false,
      ciPassed: true,
      agentSummary: 'No issues found.',
      reports: { jsonSummaryUrl: '', htmlReportUrl: '' },
    };
    const pdf = await generatePdfReportBuffer(summary, [], []);
    assert.equal(Buffer.from(pdf).subarray(0, 5).toString('ascii'), '%PDF-');
  });
});

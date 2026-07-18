import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeUrl, isCrawlTrap } from '../src/crawler/url-normalizer.js';
import { parseRobotsTxt, isAllowedByRobotsTxt } from '../src/crawler/robots-sitemap.js';

describe('Crawler Limits, Robots.txt & URL Deduplication', () => {
  test('Deterministic URL Normalization and Tracking Parameter Stripping', () => {
    const rawUrl = 'HTTPS://www.Example.com/path/?utm_source=google&b=2&gclid=12345&a=1#fragment';
    const normalized = normalizeUrl(rawUrl);
    assert.equal(normalized, 'https://www.example.com/path?a=1&b=2');

    // Root slash preservation vs subpath trailing slash stripping
    assert.equal(normalizeUrl('https://example.com/'), 'https://example.com/');
    assert.equal(normalizeUrl('https://example.com/sub/'), 'https://example.com/sub');
  });

  test('Crawl Trap & Loop Detection', () => {
    // Calendar loop detection
    const calendarUrl = 'https://example.com/events/2026/07/18/next/2026/08/01';
    const trapRes1 = isCrawlTrap(calendarUrl);
    assert.equal(trapRes1.isTrap, true);

    // Directory repetition trap (/dir/dir/dir/dir)
    const repeatUrl = 'https://example.com/shop/category/category/category/category/item';
    const trapRes2 = isCrawlTrap(repeatUrl);
    assert.equal(trapRes2.isTrap, true);

    // Excessive directory depth
    const deepUrl = 'https://example.com/' + Array(16).fill('dir').join('/') + '/page';
    const trapRes3 = isCrawlTrap(deepUrl);
    assert.equal(trapRes3.isTrap, true);

    // Normal valid URL
    const normalUrl = 'https://example.com/blog/article-title?page=2';
    const trapRes4 = isCrawlTrap(normalUrl);
    assert.equal(trapRes4.isTrap, false);
  });

  test('Un-bypassable Robots.txt Enforcement', () => {
    const rawRobots = `
User-agent: *
Disallow: /admin/
Disallow: /private/secret
Allow: /private/public

User-agent: WebsiteHealthSEOBrokenLinkAuditor
Disallow: /blocked-for-auditor
Sitemap: https://example.com/sitemap.xml
`;
    const parsed = parseRobotsTxt(rawRobots);
    assert.equal(parsed.sitemapUrls.length, 1);
    assert.equal(parsed.sitemapUrls[0], 'https://example.com/sitemap.xml');

    // Test wildcard rules
    assert.equal(isAllowedByRobotsTxt('https://example.com/public-page', parsed), true);
    assert.equal(isAllowedByRobotsTxt('https://example.com/admin/dashboard', parsed), false);
    assert.equal(isAllowedByRobotsTxt('https://example.com/private/secret', parsed), false);
    assert.equal(isAllowedByRobotsTxt('https://example.com/private/public', parsed), true); // Allow longer prefix overrides Disallow

    // Test specific User-Agent rules
    assert.equal(isAllowedByRobotsTxt('https://example.com/blocked-for-auditor', parsed), false);
  });

  test('Consecutive user-agent declarations retain wildcard restrictions', () => {
    const parsed = parseRobotsTxt(`
User-agent: OtherBot
User-agent: *
Disallow: /private
`);

    assert.equal(isAllowedByRobotsTxt('https://example.com/private/report', parsed), false);
    assert.equal(isAllowedByRobotsTxt('https://example.com/public', parsed), true);
  });
});

# Website SEO, Health & Broken Link Auditor

Audit an authorized website for technical SEO, broken links, redirect chains, indexability, sitemap coverage, TLS certificate status, security headers, and prior-run regressions.

This Actor is HTTP-only. It uses Crawlee `BasicCrawler`, a bounded HTTP client, and Cheerio. It does not run Chromium or execute page JavaScript.

## Responsible Use

You must own the target website or have explicit prior authorization to audit it.

- Set `confirmAuthorizedUse: true` for every target except the built-in `example.com` demo.
- The checkbox confirms permission you already have. It does not create permission.
- Recursive crawling stays inside the starting URL's registrable domain.
- External links may receive one bounded status check, but they are never crawled.
- `robots.txt` is always enforced and cannot be disabled.
- The Actor does not log in, submit forms, bypass access controls, solve CAPTCHAs, scan ports, or probe private networks.
- Domain owners can request blocking through the process in `DOMAIN-REMOVAL.md`.

Security-header and TLS findings are configuration observations, not a penetration test, compliance audit, ranking guarantee, or accessibility certification.

## Safe Demo

The Store prefill uses one lightweight page:

```json
{
  "startUrl": "https://example.com",
  "confirmAuthorizedUse": false,
  "maxPages": 1,
  "maxCrawlDepth": 0,
  "maxLinksPerPage": 25,
  "checkExternalLinks": false,
  "maxExternalLinks": 0,
  "includePerformance": false,
  "compareWithPreviousRun": false,
  "generateHtmlReport": true,
  "generatePdfReport": false
}
```

For any real website, set `confirmAuthorizedUse` to `true` only after confirming authorization.

## What It Checks

- HTTP statuses and bounded in-scope redirect chains
- Broken internal and optional external links
- Titles, meta descriptions, canonical tags, headings, and indexability
- Duplicate titles and meta descriptions across audited pages
- `robots.txt` and sitemap coverage
- Image alt text and mixed-content references
- Open Graph tags and JSON-LD syntax
- Selected security headers
- Real TLS certificate validity and expiry dates
- Optional PageSpeed Insights lab and field metrics
- New, resolved, unchanged, and materially changed findings against a comparable baseline

## Input

| Field | Default | Limit | Purpose |
| --- | ---: | ---: | --- |
| `startUrl` | required | HTTP/HTTPS only | Authorized starting page |
| `confirmAuthorizedUse` | `false` | required | Confirms prior authorization; `example.com` is exempt |
| `maxPages` | `25` | 250 | Maximum internal pages processed |
| `maxCrawlDepth` | `3` | 10 | Maximum click depth from the start page |
| `maxLinksPerPage` | `100` | 500 | Maximum unique links extracted per page |
| `checkExternalLinks` | `true` | - | Run a bounded status check for external links |
| `maxExternalLinks` | `250` | 2,000 | Maximum unique external links checked |
| `includePerformance` | `false` | - | Enable PageSpeed Insights |
| `pageSpeedApiKey` | empty | secret | Optional Google PageSpeed API key; never returned |
| `maxPerformancePages` | `1` | 5 | Maximum PageSpeed attempts, including failed attempts |
| `compareWithPreviousRun` | `true` | - | Enable persistent baseline comparison |
| `baselineKey` | empty | 48 safe characters | Optional baseline-store suffix |
| `generateHtmlReport` | `true` | - | Save escaped `report.html` |
| `generatePdfReport` | `false` | - | Save a real `application/pdf` file at `report.pdf` |
| `failOnSeverity` | `none` | `none`, `error`, `critical` | Optional CI failure threshold |

Run limits are also constrained by the user's maximum cost. If the budget cannot cover one paid page event, the Actor stops before crawling.

## Output

Each successfully audited, non-blocked page produces one default-dataset item. Important fields include:

```json
{
  "recordType": "page_audit",
  "url": "https://example.com/",
  "normalizedUrl": "https://example.com/",
  "statusCode": 200,
  "contentType": "text/html",
  "redirectChain": [],
  "title": "Example Domain",
  "metaDescription": null,
  "canonicalUrl": null,
  "indexability": {
    "isIndexable": true,
    "robotsMeta": [],
    "xRobotsTag": [],
    "robotsTxtAllowed": true
  },
  "linkSummary": {
    "internalLinksCount": 0,
    "externalLinksCount": 1,
    "brokenLinksCount": 0,
    "blockedLinksCount": 0
  },
  "tlsSummary": {
    "checked": true,
    "valid": true,
    "issuer": "Certificate Authority",
    "validFrom": "2026-05-31T21:39:12.000Z",
    "validTo": "2026-08-29T21:41:26.000Z",
    "daysRemaining": 42
  },
  "issues": [
    {
      "ruleId": "META_DESC_MISSING",
      "severity": "warning",
      "category": "SEO",
      "message": "Page is missing a meta description.",
      "evidence": "Meta description: missing",
      "recommendation": "Add a concise description of the page.",
      "fingerprint": "stable-sha256-fingerprint"
    }
  ],
  "score": 95,
  "auditedAt": "2026-07-18T16:58:23.026Z"
}
```

The default Key-Value Store may contain:

- `OUTPUT`: machine-readable run summary and artifact links
- `report.html`: escaped self-contained report with a restrictive Content Security Policy
- `report.pdf`: generated PDF when requested

The output schema links the dataset and summary for API, MCP, and AI-agent workflows.

## Regression Tracking

When enabled, the Actor stores only minimized issue metadata in a persistent named Key-Value Store. Raw HTML is never stored in the baseline.

Regression comparison runs only when the previous baseline covered the same number of pages. This prevents a smaller crawl from reporting findings on omitted pages as resolved. The baseline is replaced only when:

- at least one page record was stored;
- the crawl did not report failed requests;
- the maximum-cost limit did not stop output; and
- every collected page record was stored.

## CI Use

`OUTPUT.ciPassed` is suitable for pipelines and agents.

- `none`: findings do not fail the run.
- `error`: an `error` or `critical` finding fails the run after output is saved.
- `critical`: only a `critical` finding fails the run after output is saved.

## Security Controls

- HTTP and HTTPS only; ports 80 and 443 only
- Credentials in URLs rejected
- Private, loopback, link-local, metadata, benchmarking, documentation, tunneling, multicast, and reserved IP ranges blocked
- Decimal, hexadecimal, octal, shortened IPv4, mapped IPv6, and compatible IPv6 forms checked
- DNS validated both before a request and at socket connection time
- Redirects revalidated and limited to five in-scope hops
- Page bodies limited to 5 MiB compressed and decompressed
- Sitemap graph limited by file count, total bytes, URL count, and authorized scope
- Link checks bounded and paced per host
- PageSpeed responses limited to 2 MiB and API keys redacted

See `SECURITY.md` for implementation details.

## Limitations

- Client-rendered single-page applications are evaluated from their initial server HTML only.
- Some external sites reject `HEAD` or automated requests. HTTP 401, 403, 429, and 451 are reported as blocked/restricted rather than broken.
- PageSpeed data depends on Google's quota and CrUX availability.
- A clean report does not prove that a website is secure, accessible, compliant, or guaranteed to rank.

## Billing Behavior

Useful, non-blocked page records use the `page-audited` event when pay-per-event pricing is configured. Dataset storage and event charging use the Apify SDK's combined `Actor.pushData(record, eventName)` operation. Blocked, skipped, duplicate, and synthetic pages are not charged as successful page audits.

No live price is configured by this repository.

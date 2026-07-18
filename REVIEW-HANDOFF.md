# Review Handoff & Architecture Verification (`REVIEW-HANDOFF.md`)

This document provides a comprehensive architectural and verification summary for the newly developed **Website SEO, Health & Broken Link Auditor** Apify Actor, adhering to all strict local development boundaries.

---

## 1. Architecture Summary

The Actor is an HTTP-only auditor built with Crawlee `BasicCrawler`, a bounded custom HTTP client, and Cheerio. It is designed for technical QA and regression monitoring while enforcing authorization and SSRF boundaries:
- **Input & Authorization Layer**: Validates mandatory options (`startUrl`, `confirmAuthorizedUse=true`). Rejects unauthorized targets, unsupported protocols, credentials, and custom non-standard ports.
- **SSRF & DNS Defense Layer (`url-validator.ts`, `dns-guard.ts`)**: Normalizes and inspects all host representations (`decimal`, `octal`, `hex`, `IPv4-mapped`, `URL-encoded`) against prohibited IP ranges (`loopback`, `private`, `link-local`, `multicast`, `reserved`, `cloud-metadata`). Intercepts socket connections via `secureLookupHook` to eliminate DNS rebinding attacks.
- **Crawl Engine (`robots-sitemap.ts`, `url-normalizer.ts`)**: Enforces `robots.txt` with `robots-parser`, traverses only bounded in-scope sitemaps, strips tracking parameters/fragments, and rejects crawl traps.
- **Audit Rules Engine (`rules-engine.ts`)**: Evaluates 15+ evidence-based technical SEO, broken link, redirect loop, Open Graph, structured data syntax, image accessibility, mixed content, TLS validity/expiry, and security header checks. Generates stable SHA-256 issue fingerprints.
- **PageSpeed & Baseline Layer (`pagespeed.ts`, `regression-tracker.ts`)**: Optionally runs Google PageSpeed Insights while redacting API keys (`[REDACTED_API_KEY]`). Persists minimized issue fingerprints across runs inside the Key-Value Store (`loadBaseline`/`saveBaseline`) to calculate exact `newIssues`, `resolvedIssues`, `unchangedIssues`, and `materiallyChangedIssues`.
- **Atomic PPE Billing Layer (`charging.ts`)**: Atomically charges `page-audited` exact events when useful page data records are pushed. Never charges for blocked (`401, 403, 429, 451`), skipped, duplicate, or synthetic records. Stops cleanly when spending limits are reached.
- **Reporting & Summary Layer (`reporter.ts`)**: Generates deterministic agent summary text (without calling an LLM), self-contained interactive HTML audit reports (`report.html`), and structured JSON summaries linked to the dataset and Key-Value store.

---

## 2. Complete File List

```text
E:\APIFY PROJECT\Website Health SEO Broken Link Auditor\
├── package.json
├── tsconfig.json
├── .gitignore
├── Dockerfile
├── LICENSE
├── README.md
├── SECURITY.md
├── DOMAIN-REMOVAL.md
├── REVIEW-HANDOFF.md
├── .actor/
│   ├── actor.json
│   ├── INPUT_SCHEMA.json
│   ├── dataset_schema.json
│   └── output_schema.json
├── .github/
│   └── workflows/
│       └── ci.yml
├── src/
│   ├── types.ts
│   ├── main.ts
│   ├── security/
│   │   ├── blocklist.ts
│   │   ├── url-validator.ts
│   │   └── dns-guard.ts
│   ├── crawler/
│   │   ├── url-normalizer.ts
│   │   └── robots-sitemap.ts
│   ├── audit/
│   │   ├── rules-engine.ts
│   │   └── pagespeed.ts
│   ├── baseline/
│   │   └── regression-tracker.ts
│   ├── billing/
│   │   └── charging.ts
│   └── reports/
│       └── reporter.ts
└── tests/
    ├── security.test.ts
    ├── crawler.test.ts
    ├── audit.test.ts
    └── billing.test.ts
```

---

## 3. Security Controls Implemented

| Security Control | Implementation Detail | Verified Status |
| :--- | :--- | :--- |
| **Authorization Requirement** | Enforces `confirmAuthorizedUse=true` for all domains except `example.com`. | Verified (`url-validator.ts`) |
| **Protocol & Port Guard** | Only permits `http:` and `https:` on ports `80` and `443`. Rejects URL credentials. | Verified (`url-validator.ts`) |
| **SSRF & IP Representation Filter** | Blocks private, loopback, link-local, reserved, and cloud metadata (`169.254.169.254`, `fd00:ec2::254`) across decimal, hex, octal, and IPv4-mapped representations. | Verified (`url-validator.ts`) |
| **DNS Rebinding Protection** | Pre-resolves A/AAAA records before request; intercepts TCP connect via `secureLookupHook` to verify resolved IP immediately prior to connection. Revalidates redirect targets. | Verified (`dns-guard.ts`) |
| **Domain Scope Isolation** | Limits internal crawling strictly to authorized registrable domain (`tldts`). External links checked via bounded `HEAD`/`GET` once without recursion. | Verified (`main.ts`) |
| **Un-bypassable `robots.txt`** | Fetches and parses `robots.txt` (`Disallow`/`Allow`). Evaluated before every request; no option to disable. | Verified (`robots-sitemap.ts`) |
| **XXE & Sitemap DoS Protection** | Parses XML with entities disabled and enforces graph-wide file, byte, and URL caps. | Verified (`robots-sitemap.ts`) |
| **Blocked Status Classification** | `401`, `403`, `429`, `451` classified as `blockedLinks` (unavailable/restricted), not broken links. | Verified (`rules-engine.ts`) |
| **Domain Blocklist & Opt-out** | Enforces immutable `DOMAIN_BLOCKLIST` (`blocklist.ts`) and provides `DOMAIN-REMOVAL.md` opt-out process. | Verified (`blocklist.ts`) |
| **Secret Redaction** | Strips `pageSpeedApiKey` across all strings, error messages, and logs (`[REDACTED_API_KEY]`). | Verified (`pagespeed.ts`) |

---

## 4. Suggested PPE Prices with Cost Reasoning

> **NOTE**: Following strict boundaries, no monetary prices have been configured or applied to Apify platform settings (`do not change live pricing`). Below are the suggested PPE event definitions and reasoning prepared for future evaluation:

| PPE Event Name | Suggested Price | Cost Reasoning & Value Alignment |
| :--- | :--- | :--- |
| `page-audited` | **$0.002 per page** | Suggested only. The implementation uses `Actor.pushData(record, 'page-audited')`, allowing the SDK to limit the dataset write and event charge together. Blocked pages are not stored as paid results. |

---

## 5. Known Limitations

- **JavaScript Execution**: Pages requiring client-side rendering are audited only from their initial server HTML response; no browser engine runs.
- **CrUX Field Data Availability**: Google PageSpeed field metrics depend on Chrome User Experience Report data. Newly created or low-traffic web pages will not have CrUX field data available (`available: false`).
- **Informational Header & TLS Checks**: Security header observations (`HSTS`, `CSP`) and basic TLS checks reflect configuration state at audit time and do not replace professional vulnerability penetration testing.

---

## 6. Strict Boundary Confirmation

We confirm that **all strict boundaries** were followed without deviation:
1. Only `E:\APIFY PROJECT\Website Health SEO Broken Link Auditor` was created/modified.
2. No existing Actor (`Actor Portfolio Monitor`, `Apify Change Tracker`, etc.), roadmap, status matrix, or portfolio file was touched.
3. No `apify push` or deployment commands were run.
4. No git commit, GitHub push, or remote repository creation occurred.
5. Live pricing was left untouched.
6. No paid cloud smoke tests were initiated.
7. No other proposed Actor was started.
8. No fake or synthetic outputs were generated to force a passing run.
9. No guarantees of SEO rankings, compliance, accessibility, or security are claimed.

We now await Codex hard review and user confirmation.

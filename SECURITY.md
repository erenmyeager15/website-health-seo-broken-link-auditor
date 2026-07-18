# Security Architecture & Safety Controls (`SECURITY.md`)

This document outlines the strict defense-in-depth security architecture implemented inside the **Website SEO, Health & Broken Link Auditor** Apify Actor.

---

## 1. Server-Side Request Forgery (SSRF) Defenses

To prevent the Actor from being abused as a proxy to probe internal networks, cloud metadata endpoints, or private infrastructure, a multi-layered validation and resolution engine (`src/security/url-validator.ts` and `src/security/dns-guard.ts`) is enforced across every HTTP/HTTPS operation:

### Protocol & Port Restrictions
- **Allowed Protocols**: Only `http:` and `https:` are allowed. Any scheme such as `file:`, `ftp:`, `gopher:`, `data:`, or `javascript:` is rejected immediately upon parsing.
- **Allowed Ports**: Only standard web ports `80` (HTTP) and `443` (HTTPS) are permitted. Any URL containing a custom port (e.g., `:8080`, `:22`, `:3306`, `:9200`) is blocked.
- **Credential Rejection**: URLs containing embedded authentication credentials (`http://admin:secret@domain.com`) are strictly prohibited and raise a security violation error.

### Comprehensive IP & Host Representation Filtering
The validator parses, URL-decodes, and normalizes all hostname representations before checking them against restricted IP ranges:
- **Restricted Ranges**:
  - Loopback (`127.0.0.0/8`, `::1`, `localhost`)
  - RFC1918 Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-local & Cloud Metadata (`169.254.0.0/16`, specifically AWS/GCP/Azure/Tencent metadata `169.254.169.254` and `fd00:ec2::254`)
  - Carrier-grade NAT (`100.64.0.0/10`, including Alibaba metadata `100.100.100.200`)
  - Reserved & Multicast (`0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `ff00::/8`)
  - RFC5737 Documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`)
  - Unique-local IPv6 (`fc00::/7`) and link-local IPv6 (`fe80::/10`)

- **Supported Host Representations Blocked**:
  - **Decimal Notation**: E.g., `2130706433` (`127.0.0.1`) or `2852039166` (`169.254.169.254`)
  - **Hexadecimal Notation**: E.g., `0x7f000001` or `0xa9fea9fe`
  - **Octal Notation**: E.g., `0177.0.0.1` or `0177.00.00.01`
  - **Mixed / Shortened Dotted Notation**: E.g., `127.1` or `169.254.1`
  - **Encoded Forms**: URL-encoded strings (`%31%32%37.%30.%30.%31`)
  - **IPv4-Mapped IPv6**: E.g., `::ffff:127.0.0.1` or `::ffff:7f00:1`

---

## 2. DNS Rebinding Defense & Connection-Time Validation (`dns-guard.ts`)

A classic bypass technique against SSRF filters involves creating a domain (`rebinder.attacker.com`) with a short TTL that resolves to a safe public IP during pre-flight validation but flips (`DNS rebinding`) to `127.0.0.1` or `169.254.169.254` right when the actual TCP socket connection is opened.

To completely defeat DNS rebinding:
1. **Pre-Request DNS Verification**: Before initiating any crawl request, `resolveAndValidateHost()` resolves all `A` and `AAAA` records using `node:dns/promises` and verifies that **every returned address** falls in safe public IP space.
2. **Socket Lookup Interception (`secureLookupHook`)**: Custom `http.Agent` and `https.Agent` instances intercept the socket DNS lookup phase (`lookup` option). Immediately prior to TCP SYN packet transmission, the resolved IP address is verified against our private/prohibited range list. If an IP resolves to `127.0.0.1` or metadata ranges during socket connect, the connection is instantly aborted with `ERR_SSRF_BLOCKED`.
3. **Redirect Chain Revalidation**: When an HTTP `301/302/307/308` redirect is followed, the target Location header undergoes full protocol, port, credential, blocklist, and pre-socket DNS validation before the redirect request is emitted.

---

## 3. Scope Boundaries & Robots.txt Enforcement

- **Registrable Domain Isolation**: Crawling is strictly confined to the exact registrable domain of the starting URL (`tldts`). Subdomains of the same registrable domain are permitted, but links to external or out-of-scope domains are never crawled recursively.
- **Un-bypassable `robots.txt`**: The crawler automatically fetches and parses `robots.txt` (`Disallow`/`Allow` directives for `WebsiteHealthSEOBrokenLinkAuditor` and `*`). Users have no configuration option to bypass or disable `robots.txt` compliance.
- **Safe Sitemap Parsing**: XML sitemaps are parsed with entity processing disabled. Production runs cap the graph at 10 sitemap files, 10 MiB total XML, and at most `maxPages * 20` URLs (up to 5,000).
- **Bounded Page Bodies**: Page responses are capped at 5 MiB in both compressed and decompressed form. Redirects are manually followed for at most five in-scope hops.

---

## 4. Behavioral Security & Blocked HTTP Statuses

- **No Exploitation or Probing**: Only safe HTTP `GET` and `HEAD` methods are utilized. The Actor never logs in, submits web forms, bypasses CAPTCHAs, probes administrative/internal paths (`/admin`, `/.env`, `/config.yml`), or scans ports.
- **Accurate Status Classification**: HTTP responses `401 Unauthorized`, `403 Forbidden`, `429 Too Many Requests`, and `451 Unavailable For Legal Reasons` are classified as **Blocked/Unavailable (`blockedLinks`)** rather than automatically marked as broken links. This ensures honest reporting when security gateways (Cloudflare, Akamai) or rate limits intercept automated requests.

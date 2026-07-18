# Domain Removal & Blocklisting Policy (`DOMAIN-REMOVAL.md`)

The **Website SEO, Health & Broken Link Auditor** is an ethical, authorized quality assurance tool. We respect the wishes of domain owners and web administrators who do not want their public web properties scanned or audited by this software, regardless of whether a user claims to possess authorization.

---

## 1. Enforced Registrable-Domain Blocklist

The codebase maintains an enforced, immutable list of prohibited domains (`DOMAIN_BLOCKLIST` inside `src/security/blocklist.ts`). Before any DNS resolution, network request, or crawl task is initiated, the target hostname is evaluated against this list.

If a domain is listed on the blocklist:
- The Actor immediately aborts the run with a clear safety rejection message.
- No HTTP connection or network probe is made to the domain.
- Users cannot override or bypass the blocklist using any configuration parameter.

---

## 2. How to Request Domain Removal / Opt-Out

If you are the owner, security officer, or authorized administrator of a website and wish to add your domain (or organization's domains) to our permanent blocklist so that no user can run automated audits against your properties using this tool, please submit an opt-out request following these guidelines:

### Contact Information
Please send an email from an address matching your domain (e.g., `security@yourdomain.com` or `admin@yourdomain.com`) to our repository/project maintainer contact point.

### Required Details
Include the following information in your request:
1. **Target Domain(s)**: The exact registrable domain(s) or hostname(s) you wish to block (e.g., `yourdomain.com`).
2. **Verification of Ownership**: A brief confirmation that you are authorized to request blocklisting for the domain (e.g., email from official domain address or verification via DNS TXT record if requested).
3. **Reason (Optional)**: Any context regarding your request (e.g., policy restrictions, security gateway requirements).

### Processing Time
- Once verified, your domain will be added to `DOMAIN_BLOCKLIST` in the next patch release (`blocklist.ts`).
- Any future execution attempts targeting your domain or its subdomains will be automatically blocked at the pre-flight check phase.

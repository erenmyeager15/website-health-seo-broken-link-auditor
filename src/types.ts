export interface ActorInput {
  startUrl: string;
  confirmAuthorizedUse: boolean;
  maxPages?: number;
  maxCrawlDepth?: number;
  maxLinksPerPage?: number;
  checkExternalLinks?: boolean;
  maxExternalLinks?: number;
  includePerformance?: boolean;
  pageSpeedApiKey?: string;
  maxPerformancePages?: number;
  compareWithPreviousRun?: boolean;
  baselineKey?: string;
  generateHtmlReport?: boolean;
  generatePdfReport?: boolean;
  failOnSeverity?: 'none' | 'error' | 'critical';
}

export type IssueSeverity = 'info' | 'warning' | 'error' | 'critical';

export interface AuditIssue {
  ruleId: string;
  severity: IssueSeverity;
  category: string;
  message: string;
  evidence: string;
  recommendation: string;
  fingerprint: string;
}

export interface BrokenLinkItem {
  url: string;
  statusCode?: number;
  errorMessage?: string;
  isExternal: boolean;
}

export interface PageAuditRecord {
  recordType: 'page_audit';
  url: string;
  normalizedUrl: string;
  statusCode: number;
  contentType: string;
  redirectChain: string[];
  title: string | null;
  metaDescription: string | null;
  canonicalUrl: string | null;
  indexability: {
    isIndexable: boolean;
    robotsMeta: string[];
    xRobotsTag: string[];
    robotsTxtAllowed: boolean;
    reason?: string;
  };
  headings: {
    h1Count: number;
    h1Texts: string[];
    h2Count: number;
    h3Count: number;
  };
  linkSummary: {
    internalLinksCount: number;
    externalLinksCount: number;
    brokenLinksCount: number;
    blockedLinksCount: number;
  };
  brokenLinks: BrokenLinkItem[];
  imageSummary: {
    totalImages: number;
    missingAltCount: number;
  };
  sitemapContext: {
    inSitemap: boolean;
    sitemapUrl?: string;
  };
  performanceSummary: {
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
  };
  tlsSummary: {
    checked: boolean;
    valid?: boolean;
    issuer?: string;
    validFrom?: string;
    validTo?: string;
    daysRemaining?: number;
    error?: string;
  };
  securityHeaders: {
    strictTransportSecurity: string | null;
    contentSecurityPolicy: string | null;
    xContentTypeOptions: string | null;
    xFrameOptions: string | null;
    referrerPolicy: string | null;
    permissionsPolicy: string | null;
  };
  issues: AuditIssue[];
  score: number;
  auditedAt: string;
}

export interface BaselineIssue {
  ruleId: string;
  severity: IssueSeverity;
  url: string;
  fingerprint: string;
}

export interface BaselineStore {
  domain: string;
  updatedAt: string;
  issues: Record<string, BaselineIssue>;
  summary: {
    pagesAudited: number;
    score: number;
  };
}

export interface AuditSummary {
  pagesAudited: number;
  linksChecked: number;
  brokenLinks: number;
  blockedLinks: number;
  errors: number;
  warnings: number;
  score: number;
  newIssues: number;
  resolvedIssues: number;
  unchangedIssues: number;
  materiallyChangedIssues: number;
  baselineCompared: boolean;
  ciPassed: boolean;
  agentSummary: string;
  reports: {
    jsonSummaryUrl: string;
    htmlReportUrl: string;
    pdfReportUrl?: string;
    datasetId?: string;
  };
}

export interface AuditContext {
  input: Required<ActorInput>;
  startUrlNormalized: string;
  registrableDomain: string;
  sitemapUrls: Set<string>;
  sitemapFetched: boolean;
  sitemapUrl?: string;
  seenNormalizedUrls: Set<string>;
  externalLinksChecked: Map<string, { statusCode?: number; errorMessage?: string; blocked: boolean }>;
  externalCheckQueue: Set<string>;
  pagesAuditedCount: number;
  performancePagesAudited: number;
  spendingLimitReached: boolean;
  baseline?: BaselineStore;
  allIssues: Array<{ issue: AuditIssue; url: string }>;
  pageRecords: PageAuditRecord[];
  linksCheckedCount: number;
  brokenLinksCount: number;
  blockedLinksCount: number;
}

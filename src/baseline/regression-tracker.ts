import { Actor, log } from 'apify';
import type { BaselineStore, BaselineIssue, AuditIssue, IssueSeverity } from '../types.js';

/**
 * Derives a clean, safe, deterministic Key-Value Store key/name for baseline storage from a domain.
 */
export function deriveBaselineKey(registrableDomain: string, customBaselineKey?: string): string {
  if (customBaselineKey && customBaselineKey.trim()) {
    const cleanCustomKey = customBaselineKey.trim().replace(/[^a-zA-Z0-9_-]/g, '-').replace(/-+/g, '-').slice(0, 48);
    if (!/[a-zA-Z0-9]/.test(cleanCustomKey)) {
      throw new Error('baselineKey must contain at least one letter or number.');
    }
    return `audit-baseline-${cleanCustomKey}`.slice(0, 63);
  }
  const cleanDomain = registrableDomain.toLowerCase().replace(/[^a-zA-Z0-9]/g, '-');
  if (!cleanDomain) throw new Error('Unable to derive a safe baseline store name from the target domain.');
  return `audit-baseline-${cleanDomain}`.slice(0, 63);
}

/**
 * Loads the existing baseline from the named Key-Value Store.
 */
export async function loadBaseline(registrableDomain: string, customBaselineKey?: string): Promise<BaselineStore | undefined> {
  try {
    const storeName = deriveBaselineKey(registrableDomain, customBaselineKey);
    const store = await Actor.openKeyValueStore(storeName);
    const baseline = await store.getValue<BaselineStore>('BASELINE_DATA');
    if (baseline && baseline.domain === registrableDomain && baseline.issues && baseline.summary) {
      return baseline;
    }
  } catch (error) {
    log.debug(`No comparable baseline loaded: ${(error as Error).message}`);
  }
  return undefined;
}

/**
 * Persists the current run's issues as the new baseline inside the named Key-Value Store.
 * Must only be called after a substantially successful audit (`pagesAudited > 0`).
 * Stores strictly minimized fingerprints/metadata (NEVER stores raw page HTML).
 */
export async function saveBaseline(
  registrableDomain: string,
  issuesWithUrls: Array<{ issue: AuditIssue; url: string }>,
  pagesAudited: number,
  score: number,
  customBaselineKey?: string
): Promise<void> {
  if (pagesAudited <= 0) {
    return; // Preserve previous baseline when current run fails early or returns zero pages
  }

  try {
    const storeName = deriveBaselineKey(registrableDomain, customBaselineKey);
    const store = await Actor.openKeyValueStore(storeName);

    const issuesMap: Record<string, BaselineIssue> = {};
    for (const { issue, url } of issuesWithUrls) {
      issuesMap[issue.fingerprint] = {
        ruleId: issue.ruleId,
        severity: issue.severity,
        url,
        fingerprint: issue.fingerprint,
      };
    }

    const baselineData: BaselineStore = {
      domain: registrableDomain,
      updatedAt: new Date().toISOString(),
      issues: issuesMap,
      summary: {
        pagesAudited,
        score,
      },
    };

    await store.setValue('BASELINE_DATA', baselineData);
  } catch (error) {
    log.warning(`Audit completed, but the regression baseline could not be saved: ${(error as Error).message}`);
  }
}

export interface RegressionComparison {
  newIssues: number;
  resolvedIssues: number;
  unchangedIssues: number;
  materiallyChangedIssues: number;
}

/**
 * Compares current run issues against the loaded baseline to calculate exact regression statistics.
 */
export function compareWithBaseline(
  currentIssues: Array<{ issue: AuditIssue; url: string }>,
  baseline?: BaselineStore
): RegressionComparison {
  if (!baseline || !baseline.issues) {
    return {
      newIssues: currentIssues.length,
      resolvedIssues: 0,
      unchangedIssues: 0,
      materiallyChangedIssues: 0,
    };
  }

  const baselineIssues = baseline.issues;
  const currentFingerprints = new Set<string>();
  const currentRuleUrlMap = new Map<string, Array<{ severity: IssueSeverity; fingerprint: string }>>();

  for (const { issue, url } of currentIssues) {
    currentFingerprints.add(issue.fingerprint);
    const key = `${issue.ruleId}:${url}`;
    const list = currentRuleUrlMap.get(key) || [];
    list.push({ severity: issue.severity, fingerprint: issue.fingerprint });
    currentRuleUrlMap.set(key, list);
  }

  const baselineFingerprints = new Set(Object.keys(baselineIssues));
  const baselineRuleUrlMap = new Map<string, Array<{ severity: IssueSeverity; fingerprint: string }>>();

  for (const [fingerprint, bIssue] of Object.entries(baselineIssues)) {
    const key = `${bIssue.ruleId}:${bIssue.url}`;
    const list = baselineRuleUrlMap.get(key) || [];
    list.push({ severity: bIssue.severity, fingerprint });
    baselineRuleUrlMap.set(key, list);
  }

  let unchangedCount = 0;
  let newCount = 0;
  let materiallyChangedCount = 0;

  for (const { issue, url } of currentIssues) {
    if (baselineFingerprints.has(issue.fingerprint)) {
      unchangedCount++;
    } else {
      // Check if same ruleId + url existed in baseline with a different fingerprint/severity
      const key = `${issue.ruleId}:${url}`;
      if (baselineRuleUrlMap.has(key)) {
        materiallyChangedCount++;
      } else {
        newCount++;
      }
    }
  }

  let resolvedCount = 0;
  for (const [fingerprint, bIssue] of Object.entries(baselineIssues)) {
    if (!currentFingerprints.has(fingerprint)) {
      // Check if it was materially changed (same ruleId + url still exists) or completely resolved
      const key = `${bIssue.ruleId}:${bIssue.url}`;
      if (!currentRuleUrlMap.has(key)) {
        resolvedCount++;
      }
    }
  }

  return {
    newIssues: newCount,
    resolvedIssues: resolvedCount,
    unchangedIssues: unchangedCount,
    materiallyChangedIssues: materiallyChangedCount,
  };
}

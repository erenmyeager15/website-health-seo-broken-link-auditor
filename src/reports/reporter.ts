import { Actor } from 'apify';
import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from 'pdf-lib';
import type { AuditSummary, PageAuditRecord, AuditIssue, IssueSeverity } from '../types.js';
import type { RegressionComparison } from '../baseline/regression-tracker.js';

export const HTML_REPORT_CONTENT_TYPE = 'text/html';

export function generateDeterministicAgentSummary(
  pagesAudited: number,
  linksChecked: number,
  brokenLinks: number,
  blockedLinks: number,
  errors: number,
  warnings: number,
  score: number,
  regression: RegressionComparison,
  ciPassed: boolean,
  baselineCompared = true,
): string {
  const status = ciPassed ? 'PASSED' : 'FAILED (severity threshold breached)';
  let summary = `Website Health Audit ${status} with an overall health score of ${score.toFixed(1)}/100. `;
  summary += `Audited ${pagesAudited} page(s) and checked ${linksChecked} unique link(s). `;

  if (errors === 0 && warnings === 0 && brokenLinks === 0) {
    summary += 'No technical SEO errors, warnings, or broken links were discovered. ';
  } else {
    summary += `Discovered ${errors} error(s), ${warnings} warning(s), and ${brokenLinks} broken link(s). `;
    if (blockedLinks > 0) {
      summary += `Observed ${blockedLinks} blocked/restricted target link(s) (HTTP 401/403/429/451). `;
    }
  }

  if (baselineCompared) {
    summary += `Regression against a comparable baseline: ${regression.newIssues} new issue(s), `;
    summary += `${regression.resolvedIssues} resolved issue(s), and ${regression.materiallyChangedIssues} materially changed issue(s).`;
  } else {
    summary += 'No like-for-like prior baseline was available; this run establishes the comparison state.';
  }
  return summary;
}

export function escapeHtml(value: unknown): string {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function severityBadge(severity: IssueSeverity): string {
  const colors: Record<IssueSeverity, string> = {
    critical: '#b91c1c',
    error: '#c2410c',
    warning: '#a16207',
    info: '#1d4ed8',
  };
  return `<span class="badge" style="background:${colors[severity]}">${escapeHtml(severity)}</span>`;
}

export function generateHtmlReportString(
  summary: AuditSummary,
  pageRecords: PageAuditRecord[],
  allIssuesWithUrls: Array<{ issue: AuditIssue; url: string }>,
): string {
  const issueRows = allIssuesWithUrls.map(({ issue, url }) => `
    <tr>
      <td>${severityBadge(issue.severity)}</td>
      <td><code>${escapeHtml(issue.ruleId)}</code></td>
      <td><a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(url)}</a></td>
      <td>${escapeHtml(issue.message)}</td>
      <td><code>${escapeHtml(issue.evidence)}</code></td>
      <td>${escapeHtml(issue.recommendation)}</td>
    </tr>`).join('');

  const pageRows = pageRecords.map((record) => `
    <tr>
      <td><a href="${escapeHtml(record.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(record.url)}</a></td>
      <td>${record.statusCode}</td>
      <td>${record.score.toFixed(1)}</td>
      <td>${record.issues.length}</td>
      <td>${escapeHtml(record.title ?? '')}</td>
    </tr>`).join('');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data: https:; base-uri 'none'; form-action 'none'">
  <title>Website Health Audit Report</title>
  <style>
    :root { color-scheme: light; font-family: Arial, sans-serif; color: #172033; background: #eef1f5; }
    * { box-sizing: border-box; }
    body { margin: 0; padding: 24px; }
    main { max-width: 1240px; margin: 0 auto; background: #fff; border: 1px solid #d8dee8; }
    header { padding: 28px 32px; color: #fff; background: #172033; }
    h1, h2 { margin: 0; }
    header p { color: #cbd5e1; margin: 8px 0 0; }
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); border-bottom: 1px solid #d8dee8; }
    .metric { min-height: 104px; padding: 22px; border-right: 1px solid #e5e9f0; }
    .metric strong { display: block; font-size: 28px; }
    .metric span { color: #64748b; font-size: 12px; text-transform: uppercase; }
    section { padding: 28px 32px; }
    section + section { border-top: 1px solid #d8dee8; }
    h2 { margin-bottom: 16px; font-size: 20px; }
    .summary { padding: 16px; background: #eff6ff; border-left: 4px solid #2563eb; }
    .table-wrap { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { padding: 10px; text-align: left; color: #475569; background: #f1f5f9; border-bottom: 2px solid #cbd5e1; }
    td { padding: 10px; vertical-align: top; border-bottom: 1px solid #e5e7eb; overflow-wrap: anywhere; }
    a { color: #1d4ed8; }
    code { font-family: Consolas, monospace; white-space: pre-wrap; }
    .badge { display: inline-block; padding: 3px 7px; color: #fff; font-size: 11px; font-weight: 700; text-transform: uppercase; }
    .empty { color: #047857; font-weight: 700; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Website SEO, Health &amp; Broken Link Audit</h1>
      <p>Deterministic report generated ${escapeHtml(new Date().toISOString())}</p>
    </header>
    <div class="metrics">
      <div class="metric"><strong>${summary.score.toFixed(1)}</strong><span>Health score</span></div>
      <div class="metric"><strong>${summary.pagesAudited}</strong><span>Pages audited</span></div>
      <div class="metric"><strong>${summary.linksChecked}</strong><span>Links checked</span></div>
      <div class="metric"><strong>${summary.brokenLinks}</strong><span>Broken links</span></div>
      <div class="metric"><strong>${summary.errors}</strong><span>Errors</span></div>
      <div class="metric"><strong>${summary.ciPassed ? 'PASS' : 'FAIL'}</strong><span>Threshold</span></div>
    </div>
    <section>
      <h2>Executive summary</h2>
      <div class="summary">${escapeHtml(summary.agentSummary)}</div>
      <p><strong>Regression:</strong> ${summary.baselineCompared
        ? `${summary.newIssues} new, ${summary.resolvedIssues} resolved, ${summary.unchangedIssues} unchanged, ${summary.materiallyChangedIssues} materially changed.`
        : 'No like-for-like prior baseline was available.'}</p>
    </section>
    <section>
      <h2>Pages</h2>
      <div class="table-wrap"><table>
        <thead><tr><th>URL</th><th>Status</th><th>Score</th><th>Issues</th><th>Title</th></tr></thead>
        <tbody>${pageRows}</tbody>
      </table></div>
    </section>
    <section>
      <h2>Issues (${allIssuesWithUrls.length})</h2>
      ${issueRows ? `<div class="table-wrap"><table>
        <thead><tr><th>Severity</th><th>Rule</th><th>URL</th><th>Message</th><th>Evidence</th><th>Recommendation</th></tr></thead>
        <tbody>${issueRows}</tbody>
      </table></div>` : '<p class="empty">No issues were discovered in the audited scope.</p>'}
    </section>
  </main>
</body>
</html>`;
}

export async function generatePdfReportBuffer(
  summary: AuditSummary,
  pageRecords: PageAuditRecord[],
  allIssuesWithUrls: Array<{ issue: AuditIssue; url: string }>,
): Promise<Uint8Array> {
  const document = await PDFDocument.create();
  const regular = await document.embedFont(StandardFonts.Helvetica);
  const bold = await document.embedFont(StandardFonts.HelveticaBold);
  const state = createPdfState(document, regular, bold);

  drawPdfLine(state, 'Website SEO, Health & Broken Link Audit', 18, bold, rgb(0.09, 0.13, 0.2));
  drawPdfLine(state, `Generated: ${new Date().toISOString()}`, 9, regular, rgb(0.35, 0.4, 0.48));
  state.y -= 8;
  drawPdfLine(state, `Health score: ${summary.score.toFixed(1)}/100`, 12, bold);
  drawPdfLine(state, `Pages: ${summary.pagesAudited} | Links: ${summary.linksChecked} | Broken: ${summary.brokenLinks}`, 10, regular);
  drawPdfLine(state, `Errors: ${summary.errors} | Warnings: ${summary.warnings} | Threshold: ${summary.ciPassed ? 'PASS' : 'FAIL'}`, 10, regular);
  state.y -= 8;
  drawWrappedPdfText(state, summary.agentSummary, 10, regular);
  state.y -= 12;
  drawPdfLine(state, 'Pages', 14, bold);

  for (const record of pageRecords.slice(0, 250)) {
    drawWrappedPdfText(
      state,
      `${record.statusCode} | ${record.score.toFixed(1)} | ${record.issues.length} issue(s) | ${record.url}`,
      9,
      regular,
    );
  }

  state.y -= 12;
  drawPdfLine(state, 'Prioritized issues', 14, bold);
  const issueLimit = 500;
  for (const { issue, url } of allIssuesWithUrls.slice(0, issueLimit)) {
    drawWrappedPdfText(state, `[${issue.severity.toUpperCase()}] ${issue.ruleId} - ${url}`, 9, bold);
    drawWrappedPdfText(state, issue.message, 9, regular);
    drawWrappedPdfText(state, `Fix: ${issue.recommendation}`, 9, regular, rgb(0.05, 0.45, 0.3));
    state.y -= 5;
  }
  if (allIssuesWithUrls.length > issueLimit) {
    drawPdfLine(state, `${allIssuesWithUrls.length - issueLimit} additional issues are available in the JSON dataset and HTML report.`, 9, regular);
  }

  return await document.save();
}

interface PdfState {
  document: PDFDocument;
  page: PDFPage;
  regular: PDFFont;
  bold: PDFFont;
  y: number;
}

function createPdfState(document: PDFDocument, regular: PDFFont, bold: PDFFont): PdfState {
  const page = document.addPage([612, 792]);
  return { document, page, regular, bold, y: 750 };
}

function ensurePdfSpace(state: PdfState, requiredHeight: number): void {
  if (state.y - requiredHeight >= 42) return;
  state.page = state.document.addPage([612, 792]);
  state.y = 750;
}

function drawPdfLine(
  state: PdfState,
  text: string,
  size: number,
  font: PDFFont,
  color = rgb(0.1, 0.12, 0.16),
): void {
  ensurePdfSpace(state, size + 6);
  state.page.drawText(toPdfAscii(text), { x: 42, y: state.y, size, font, color });
  state.y -= size + 6;
}

function drawWrappedPdfText(
  state: PdfState,
  text: string,
  size: number,
  font: PDFFont,
  color = rgb(0.1, 0.12, 0.16),
): void {
  const maxWidth = 528;
  const words = toPdfAscii(text).split(/\s+/).filter(Boolean);
  let line = '';
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (font.widthOfTextAtSize(candidate, size) <= maxWidth) {
      line = candidate;
      continue;
    }
    if (line) drawPdfLine(state, line, size, font, color);
    line = word.length > 120 ? `${word.slice(0, 117)}...` : word;
  }
  if (line) drawPdfLine(state, line, size, font, color);
}

function toPdfAscii(value: string): string {
  return value.replace(/[^\x20-\x7E]/g, '?');
}

export async function saveReportsAndSummary(
  pagesAudited: number,
  linksChecked: number,
  brokenLinks: number,
  blockedLinks: number,
  errors: number,
  warnings: number,
  score: number,
  regression: RegressionComparison,
  baselineCompared: boolean,
  ciPassed: boolean,
  pageRecords: PageAuditRecord[],
  allIssuesWithUrls: Array<{ issue: AuditIssue; url: string }>,
  generateHtmlReport: boolean,
  generatePdfReport: boolean,
): Promise<AuditSummary> {
  const store = await Actor.openKeyValueStore();
  const dataset = await Actor.openDataset();
  const agentSummary = generateDeterministicAgentSummary(
    pagesAudited,
    linksChecked,
    brokenLinks,
    blockedLinks,
    errors,
    warnings,
    score,
    regression,
    ciPassed,
    baselineCompared,
  );

  const summary: AuditSummary = {
    pagesAudited,
    linksChecked,
    brokenLinks,
    blockedLinks,
    errors,
    warnings,
    score: Number(score.toFixed(1)),
    newIssues: regression.newIssues,
    resolvedIssues: regression.resolvedIssues,
    unchangedIssues: regression.unchangedIssues,
    materiallyChangedIssues: regression.materiallyChangedIssues,
    baselineCompared,
    ciPassed,
    agentSummary,
    reports: {
      jsonSummaryUrl: store.getPublicUrl('OUTPUT'),
      htmlReportUrl: '',
      datasetId: dataset.id,
    },
  };

  if (generateHtmlReport || generatePdfReport) {
    const html = generateHtmlReportString(summary, pageRecords, allIssuesWithUrls);
    await store.setValue('report.html', html, { contentType: HTML_REPORT_CONTENT_TYPE });
    summary.reports.htmlReportUrl = store.getPublicUrl('report.html');
  }

  if (generatePdfReport) {
    const pdf = await generatePdfReportBuffer(summary, pageRecords, allIssuesWithUrls);
    await store.setValue('report.pdf', Buffer.from(pdf), { contentType: 'application/pdf' });
    summary.reports.pdfReportUrl = store.getPublicUrl('report.pdf');
  }

  await store.setValue('OUTPUT', summary);
  return summary;
}

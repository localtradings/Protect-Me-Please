import type { BolaMap, OwnershipTrace } from '../agents/bola.js';
import type { PatchTournamentSummary } from '../agents/patch-tournament.js';
import type { InvariantResultsArtifact } from '../proof/invariants.js';
import type { ProtectReport } from '../core/types.js';

export interface HtmlReportExtras {
  invariantResults?: InvariantResultsArtifact;
  bolaMap?: BolaMap;
  ownershipTraces?: OwnershipTrace[];
  patchTournament?: PatchTournamentSummary;
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function severityClass(severity: string): string {
  if (severity === 'critical' || severity === 'high') return 'high';
  if (severity === 'medium') return 'medium';
  return 'low';
}

function rows(values: string[][]): string {
  return values.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join('')}</tr>`).join('\n');
}

export function renderHtmlReport(report: ProtectReport, extras: HtmlReportExtras = {}): string {
  const breachPathRows = report.findings.map((finding) => [
    finding.ruleId,
    finding.title,
    finding.severity,
    finding.proofMode,
    finding.attackPath.join(' -> '),
    `evidence/${finding.id}/README.md`
  ]);
  const invariantRows =
    extras.invariantResults?.invariants.map((invariant) => [
      invariant.id,
      invariant.status,
      invariant.routes.slice(0, 4).join(', ') || 'global',
      invariant.evidence[0] ?? 'No evidence'
    ]) ?? [];
  const patchRows =
    extras.patchTournament?.items.map((item) => [
      item.findingId,
      item.recommended,
      item.candidates.map((candidate) => `${candidate.candidate}:${candidate.score}`).join(', '),
      item.directory
    ]) ?? [];
  const verificationRows = report.verification.items.map((item) => [item.findingId, item.status, item.proofMode, item.summary]);
  const projectCheckRows = report.projectVerification?.checks.map((item) => [item.name, item.status, item.command.join(' '), item.summary, item.logPath]) ?? [];
  const bolaRows =
    extras.ownershipTraces?.map((trace) => [trace.findingId, trace.route, trace.source, trace.sink, trace.missingPredicate]) ?? [];

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>BreachProof Report - ${escapeHtml(report.project)}</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #16202a;
      --muted: #526171;
      --border: #d8dee6;
      --accent: #0f766e;
      --high: #b42318;
      --medium: #b54708;
      --low: #344054;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    header {
      background: #101828;
      color: #fff;
      padding: 32px max(24px, calc((100vw - 1180px) / 2));
    }
    header h1 { margin: 0 0 8px; font-size: 32px; letter-spacing: 0; }
    header p { margin: 0; color: #cbd5e1; max-width: 780px; }
    main {
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }
    section {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 18px;
      padding: 18px;
    }
    h2 { margin: 0 0 12px; font-size: 18px; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
    }
    .metric {
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      background: #fbfcfe;
    }
    .metric strong { display: block; font-size: 24px; }
    .metric span { color: var(--muted); }
    table {
      width: 100%;
      border-collapse: collapse;
      overflow-wrap: anywhere;
    }
    th, td {
      border-top: 1px solid var(--border);
      padding: 9px 8px;
      text-align: left;
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      background: #e6f4f1;
      color: var(--accent);
      font-weight: 600;
    }
    .high { color: var(--high); font-weight: 700; }
    .medium { color: var(--medium); font-weight: 700; }
    .low { color: var(--low); font-weight: 700; }
    .graph {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    code { background: #eef2f6; padding: 2px 5px; border-radius: 4px; }
    a { color: var(--accent); }
    @media (max-width: 760px) {
      .graph { grid-template-columns: 1fr; }
      header h1 { font-size: 24px; }
      table { font-size: 12px; }
    }
  </style>
</head>
<body>
  <header>
    <h1>BreachProof</h1>
    <p>${escapeHtml(report.tagline)} Local proof engine report for <strong>${escapeHtml(report.project)}</strong>.</p>
  </header>
  <main>
    <section>
      <h2>Executive Summary</h2>
      <div class="metrics">
        <div class="metric"><strong>${report.findings.length}</strong><span>findings</span></div>
        <div class="metric"><strong>${report.summary.possiblyReachableIssues}</strong><span>reachable issues</span></div>
        <div class="metric"><strong>${extras.invariantResults?.summary.failed ?? 0}</strong><span>failed invariants</span></div>
        <div class="metric"><strong>${extras.patchTournament?.items.length ?? 0}</strong><span>patch tournaments</span></div>
        <div class="metric"><strong>${report.verification.items.filter((item) => item.status === 'verified_fixed').length}</strong><span>verified fixed</span></div>
      </div>
    </section>

    <section>
      <h2>Corpus Loaded</h2>
      <p>Sources: ${escapeHtml(report.summary.sources.join(', ') || 'none')} · Records: ${report.summary.recordsLoaded} · Relevant matches: ${report.summary.matchedComponents}</p>
    </section>

    <section>
      <h2>Breach Paths and Replayable Evidence</h2>
      <table>
        <thead><tr><th>Rule</th><th>Finding</th><th>Severity</th><th>Proof</th><th>Path</th><th>Evidence</th></tr></thead>
        <tbody>${breachPathRows
          .map(
            (row) =>
              `<tr><td>${escapeHtml(row[0] ?? '')}</td><td>${escapeHtml(row[1] ?? '')}</td><td class="${severityClass(row[2] ?? '')}">${escapeHtml(row[2] ?? '')}</td><td><span class="pill">${escapeHtml(row[3] ?? '')}</span></td><td>${escapeHtml(row[4] ?? '')}</td><td><a href="${escapeHtml(row[5] ?? '')}">open</a></td></tr>`
          )
          .join('\n')}</tbody>
      </table>
    </section>

    <section>
      <h2>Security Invariants</h2>
      <table>
        <thead><tr><th>Invariant</th><th>Status</th><th>Routes</th><th>Evidence</th></tr></thead>
        <tbody>${rows(invariantRows)}</tbody>
      </table>
    </section>

    <section>
      <h2>BOLA Ownership Traces</h2>
      <table>
        <thead><tr><th>Finding</th><th>Route</th><th>Source</th><th>Sink</th><th>Missing Predicate</th></tr></thead>
        <tbody>${rows(bolaRows)}</tbody>
      </table>
    </section>

    <section>
      <h2>Patch Tournament</h2>
      <table>
        <thead><tr><th>Finding</th><th>Recommended</th><th>Scores</th><th>Directory</th></tr></thead>
        <tbody>${rows(patchRows)}</tbody>
      </table>
    </section>

    <section>
      <h2>Verification Replay</h2>
      <table>
        <thead><tr><th>Finding</th><th>Status</th><th>Proof Mode</th><th>Summary</th></tr></thead>
        <tbody>${rows(verificationRows)}</tbody>
      </table>
    </section>

    <section>
      <h2>Project Checks</h2>
      <table>
        <thead><tr><th>Check</th><th>Status</th><th>Command</th><th>Summary</th><th>Log</th></tr></thead>
        <tbody>${rows(projectCheckRows)}</tbody>
      </table>
    </section>

    <section>
      <h2>Attack Graph</h2>
      <div class="graph">
        <div>
          <h3>Nodes</h3>
          <p>${report.attackGraph.nodes.length} total. Route nodes: ${report.attackGraph.nodes.filter((node) => node.type === 'route').length}. Weakness nodes: ${report.attackGraph.nodes.filter((node) => node.type === 'weakness').length}.</p>
        </div>
        <div>
          <h3>Edges</h3>
          <p>${report.attackGraph.edges.length} total breach-path relationships.</p>
        </div>
      </div>
    </section>

    <section>
      <h2>Manual Review Items</h2>
      <ul>
        ${
          report.findings
            .filter((finding) => finding.status === 'manual_review')
            .map((finding) => `<li>${escapeHtml(finding.title)}: ${escapeHtml(finding.recommendation)}</li>`)
            .join('\n') || '<li>No manual review items.</li>'
        }
      </ul>
    </section>
  </main>
</body>
</html>
`;
}

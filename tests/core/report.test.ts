import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { buildAttackGraph } from '../../src/agents/attack-graph.js';
import { mapRepository } from '../../src/agents/repo-mapper.js';
import { buildLocalVulnerabilityCorpus } from '../../src/agents/vulnerability-corpus.js';
import { buildReachabilityGraph } from '../../src/agents/reachability.js';
import { validateSystemMap } from '../../src/agents/safe-validation.js';
import { createReportModel, renderJsonReport, renderMarkdownReport, renderSarifReport } from '../../src/reporting/report-generator.js';

const fixtureRoot = path.resolve('tests/fixtures/sample-next-express');

describe('report generator', () => {
  test('renders Markdown, JSON, and SARIF without claiming production was touched', async () => {
    const systemMap = await mapRepository(fixtureRoot);
    const corpus = buildLocalVulnerabilityCorpus();
    const reachabilityGraph = await buildReachabilityGraph(fixtureRoot, systemMap);
    const attackGraph = buildAttackGraph(systemMap, corpus, reachabilityGraph);
    const findings = validateSystemMap(systemMap, attackGraph, corpus);
    const report = createReportModel({
      workspace: fixtureRoot,
      mode: 'local',
      systemMap,
      attackGraph,
      findings,
      projectVerification: {
        generatedAt: new Date().toISOString(),
        checks: [{
          name: 'node:test',
          ecosystem: 'node',
          command: ['npm', 'run', 'test'],
          status: 'passed',
          exitCode: 0,
          durationMs: 12,
          logPath: 'reports/verification/node-test.log',
          summary: 'Exited with code 0.'
        }],
        summary: { passed: 1, failed: 0, skipped: 0, timedOut: 0 }
      }
    });

    const markdown = renderMarkdownReport(report);
    const json = renderJsonReport(report);
    const sarif = renderSarifReport(report);

    expect(markdown).toContain('BreachProof Final Report');
    expect(markdown).toContain('Project: sample-next-express');
    expect(markdown).toContain('Production touched: no');
    expect(markdown).toContain('Confirmed breach paths');
    expect(markdown).toContain('Project checks');
    expect(markdown).toContain('node:test: passed');
    expect(markdown).toContain('Cross-tenant or ownership check missing');
    expect(JSON.parse(json).findings.length).toBeGreaterThan(0);
    expect(JSON.parse(json).projectVerification.summary.passed).toBe(1);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.results.length).toBeGreaterThan(0);
    expect(JSON.stringify(sarif)).not.toContain('node:test');
  });
});

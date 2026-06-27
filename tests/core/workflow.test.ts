import { cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { createDefaultScopeConfig } from '../../src/core/config.js';
import { runAutonomousWorkflow } from '../../src/core/workflow.js';

describe('autonomous proof and fix workflow', () => {
  test('writes required JSON artifacts, patch files, and verification without applying source changes by default', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-workflow-'));
    await cp(path.resolve('tests/fixtures/sample-next-express'), workspace, {
      recursive: true,
      filter: (source) => !source.includes('.breachproof') && !source.endsWith('breachproof.scope.yml') && !source.includes('/reports/')
    });
    const invoiceRoute = path.join(workspace, 'app/api/invoices/[id]/route.ts');
    const before = await readFile(invoiceRoute, 'utf8');

    try {
      const config = createDefaultScopeConfig(workspace);
      const result = await runAutonomousWorkflow({ workspace, config, yes: true, apply: false });
      const after = await readFile(invoiceRoute, 'utf8');

      expect(result.artifacts.map((artifact) => path.basename(artifact))).toEqual(
        expect.arrayContaining([
          'system-map.json',
          'vulnerability-corpus-summary.json',
          'reachability-graph.json',
          'attack-graph.json',
          'bola-map.json',
          'ownership-traces.json',
          'validation-plan.json',
          'invariant-results.json',
          'request-sequences.json',
          'evidence.json',
          'evidence-summary.json',
          'patch-summary.json',
          'patch-tournament.json',
          'verification.json',
          'range-summary.json',
          'final-report.md',
          'final-report.html',
          'final-report.sarif'
        ])
      );
      expect(result.patchSummary.items.some((item) => item.status === 'patch_created')).toBe(true);
      expect(result.verification.items.every((item) => item.productionTouched === false)).toBe(true);
      expect(after).toBe(before);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

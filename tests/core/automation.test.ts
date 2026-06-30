import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { classifyFixDispositions } from '../../src/core/fix-policy.js';
import { runProjectVerification } from '../../src/core/project-verification.js';
import { automationExitCode, createAutomationSummary } from '../../src/core/automation.js';
import { buildVaultGraph } from '../../src/vault/graph.js';
import { makeGraphInput } from '../helpers/vault-fixtures.js';
import { makeFinding } from '../helpers/vault-fixtures.js';

describe('generated-artifact-only fix policy', () => {
  test('classifies patch artifacts for review without claiming an automatic fix', () => {
    const dispositions = classifyFixDispositions(
      [makeFinding(), makeFinding({ id: 'manual', status: 'manual_review' })],
      {
        generatedAt: new Date().toISOString(),
        apply: false,
        items: [
          {
            findingId: 'generated-id',
            status: 'patch_created',
            patchFile: 'reports/patches/generated-id/patch.diff',
            summary: 'Review this generated patch.'
          },
          {
            findingId: 'manual',
            status: 'needs_human_review',
            summary: 'No safe patch exists.'
          }
        ]
      }
    );

    expect(dispositions).toEqual([
      { findingId: 'generated-id', disposition: 'review_patch' },
      { findingId: 'manual', disposition: 'manual_review' }
    ]);
    expect(dispositions.some((item) => item.disposition === 'auto_fixed')).toBe(false);
  });
});

describe('project verification', () => {
  test('detects declared Node scripts and writes bounded logs while continuing after failure', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-project-verification-'));
    try {
      await writeFile(
        path.join(workspace, 'package.json'),
        JSON.stringify({ scripts: { lint: 'node -e "process.exit(2)"', test: 'node -e "console.log(\'ok\')"' } }),
        'utf8'
      );
      await writeFile(path.join(workspace, 'package-lock.json'), '{}', 'utf8');

      const result = await runProjectVerification({ workspace, reportsDir: 'reports', timeoutMs: 10_000 });

      expect(result.checks.map((check) => [check.name, check.status])).toEqual([
        ['node:lint', 'failed'],
        ['node:test', 'passed']
      ]);
      expect(result.summary).toEqual({ passed: 1, failed: 1, skipped: 0, timedOut: 0 });
      await mkdir(path.join(workspace, 'reports', 'verification'), { recursive: true });
      expect(await readFile(path.join(workspace, result.checks[1]!.logPath), 'utf8')).toContain('ok');
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('reports configured ecosystems as skipped when their tools are unavailable', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-project-verification-'));
    try {
      await writeFile(path.join(workspace, 'go.mod'), 'module example.test/app\n', 'utf8');
      const result = await runProjectVerification({
        workspace,
        reportsDir: 'reports',
        env: { ...process.env, PATH: '' }
      });

      expect(result.checks).toHaveLength(3);
      expect(result.checks.every((check) => check.status === 'skipped')).toBe(true);
      expect(result.summary.skipped).toBe(3);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

describe('automation summary', () => {
  test('reports map, fix, verification, lifecycle, output, and delayed failure counts', () => {
    const graphInput = makeGraphInput();
    const graph = buildVaultGraph(graphInput);
    const projectVerification = {
      generatedAt: new Date().toISOString(),
      checks: [{
        name: 'node:test', ecosystem: 'node' as const, command: ['npm', 'run', 'test'],
        status: 'failed' as const, exitCode: 1, durationMs: 5,
        logPath: 'reports/verification/node-test.log', summary: 'Exited with code 1.'
      }],
      summary: { passed: 0, failed: 1, skipped: 0, timedOut: 0 }
    };
    const summary = createAutomationSummary({
      artifacts: [],
      patchSummary: graphInput.patchSummary,
      verification: graphInput.verification,
      findingsCount: graphInput.findings.length,
      systemMap: graphInput.systemMap,
      projectVerification,
      fixDispositions: [{ findingId: graphInput.findings[0]!.id, disposition: 'review_patch' }],
      vaultGraph: graph
    }, 'reports');

    expect(summary.systemMap).toMatchObject({ routes: 3, models: 1, authGates: 1, webhooks: 1, uploads: 1, aiTools: 1 });
    expect(summary.fixes).toEqual({ autoFixed: 0, reviewPatches: 1, manualReview: 0 });
    expect(summary.outputs.vault).toBe('reports/vault/index.html');
    expect(summary.rescan.status).toBe('skipped');
    expect(automationExitCode(projectVerification)).toBe(1);
  });
});

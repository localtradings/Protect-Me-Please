import { execFile } from 'node:child_process';
import { access, cp, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, test } from 'vitest';

const execFileAsync = promisify(execFile);
const cliPath = path.resolve('src/cli/index.ts');

interface EvidenceSummary {
  items: Array<{ findingId: string }>;
}

async function runCli(args: string[], cwd: string): Promise<string> {
  const { stdout } = await execFileAsync('npx', ['tsx', cliPath, ...args], { cwd });
  return stdout;
}

describe('CLI', () => {
  test('prints doctor status', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'pmp-cli-'));
    try {
      const stdout = await runCli(['doctor'], workspace);

      expect(stdout).toContain('BreachProof doctor');
      expect(stdout).toContain('Node.js');
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('initializes config and maps a fixture workspace', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'pmp-cli-fixture-'));
    await cp(path.resolve('tests/fixtures/sample-next-express'), workspace, {
      recursive: true,
      filter: (source) => !source.includes('.breachproof') && !source.endsWith('breachproof.scope.yml') && !source.includes('/reports/')
    });

    try {
      const initOutput = await runCli(['init', '--yes'], workspace);
      const mapOutput = await runCli(['map'], workspace);

    expect(initOutput).toContain('Scope approved');
    expect(mapOutput).toContain('System map written');
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('run --auto writes required artifacts without modifying fixture source by default', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-cli-fixture-'));
    await cp(path.resolve('tests/fixtures/sample-next-express'), workspace, {
      recursive: true,
      filter: (source) => !source.includes('.breachproof') && !source.endsWith('breachproof.scope.yml') && !source.includes('/reports/')
    });
    const invoiceRoute = path.join(workspace, 'app/api/invoices/[id]/route.ts');
    const before = await readFile(invoiceRoute, 'utf8');

    try {
      const output = await runCli(['run', '--auto', '--yes'], workspace);
      const after = await readFile(invoiceRoute, 'utf8');
      const artifacts = [
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
        'final-report.md',
        'final-report.html',
        'final-report.sarif'
      ];

      await Promise.all(artifacts.map((artifact) => access(path.join(workspace, 'reports', artifact))));
      expect(output).toContain('BreachProof run completed');
      expect(await runCli(['vault', 'build'], workspace)).toContain('Vault built');
      expect(await runCli(['vault', 'view'], workspace)).toContain('reports/vault/index.html');
      expect(await runCli(['vault', 'timeline'], workspace)).toContain('new');
      expect(after).toBe(before);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });

  test('proof mode commands generate replay, range, invariant, tournament, html, vibe, and ai-lab artifacts', async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), 'bp-cli-proof-'));
    await cp(path.resolve('tests/fixtures/sample-next-express'), workspace, {
      recursive: true,
      filter: (source) => !source.includes('.breachproof') && !source.endsWith('breachproof.scope.yml') && !source.includes('/reports/')
    });

    try {
      expect(await runCli(['proof', 'run', '--yes'], workspace)).toContain('Proof Mode completed');
      const summary = JSON.parse(await readFile(path.join(workspace, 'reports/evidence-summary.json'), 'utf8')) as EvidenceSummary;
      const findingId = summary.items[0]?.findingId;
      expect(findingId).toBeTruthy();
      if (findingId) {
        expect(await runCli(['proof', 'replay', findingId], workspace)).toContain('Replay evidence');
      }

      expect(await runCli(['range', 'init'], workspace)).toContain('Local cyber range written');
      expect(await runCli(['range', 'seed'], workspace)).toContain('Range seed artifacts refreshed');
      expect(await runCli(['invariants', 'init'], workspace)).toContain('Invariant file ready');
      expect(await runCli(['invariants', 'test'], workspace)).toContain('Invariant test completed');
      expect(await runCli(['graph', 'view'], workspace)).toContain('Attack graph');
      expect(await runCli(['fix', '--tournament'], workspace)).toContain('Patch tournament written');
      expect(await runCli(['report', '--format', 'html'], workspace)).toContain('HTML report written');
      expect(await runCli(['vibe', 'audit'], workspace)).toContain('Vibe-Code audit completed');
      expect(await runCli(['ai-lab', 'run'], workspace)).toContain('AI-agent security lab completed');

      await Promise.all([
        access(path.join(workspace, '.breachproof/range/docker-compose.range.yml')),
        access(path.join(workspace, 'breachproof.invariants.yml')),
        access(path.join(workspace, 'reports/final-report.html')),
        access(path.join(workspace, 'reports/vibe-audit.md')),
        access(path.join(workspace, 'reports/ai-lab.md'))
      ]);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  }, 30_000);
});

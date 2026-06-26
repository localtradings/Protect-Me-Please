import { execFile } from 'node:child_process';
import { cp, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, test } from 'vitest';

const execFileAsync = promisify(execFile);
const cliPath = path.resolve('src/cli/index.ts');

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
    const before = await import('node:fs/promises').then((fs) => fs.readFile(invoiceRoute, 'utf8'));

    try {
      const output = await runCli(['run', '--auto', '--yes'], workspace);
      const after = await import('node:fs/promises').then((fs) => fs.readFile(invoiceRoute, 'utf8'));
      const { access } = await import('node:fs/promises');
      const artifacts = [
        'system-map.json',
        'vulnerability-corpus-summary.json',
        'reachability-graph.json',
        'attack-graph.json',
        'validation-plan.json',
        'evidence.json',
        'patch-summary.json',
        'verification.json',
        'final-report.md',
        'final-report.sarif'
      ];

      await Promise.all(artifacts.map((artifact) => access(path.join(workspace, 'reports', artifact))));
      expect(output).toContain('BreachProof run completed');
      expect(after).toBe(before);
    } finally {
      await rm(workspace, { recursive: true, force: true });
    }
  });
});

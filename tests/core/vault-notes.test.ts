import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import type { BuildVaultGraphInput } from '../../src/vault/graph.js';
import { buildVaultGraph } from '../../src/vault/graph.js';
import { buildPatchMemory } from '../../src/vault/history.js';
import {
  writeVaultNotes,
  type VaultNoteSummary,
  type WriteVaultNotesInput
} from '../../src/vault/markdown.js';
import { redactVaultText, safeSlug } from '../../src/vault/redaction.js';
import {
  renderRouteProfile,
  type RouteProfileInput
} from '../../src/vault/route-profile.js';
import { makeGraphInput } from '../helpers/vault-fixtures.js';

const workspaces: string[] = [];

async function temporaryWorkspace(): Promise<string> {
  const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-notes-'));
  workspaces.push(workspace);
  return workspace;
}

function relocateInput(input: BuildVaultGraphInput, workspace: string): BuildVaultGraphInput {
  const serialized = JSON.stringify(input).split(input.systemMap.workspace).join(workspace);
  return JSON.parse(serialized) as BuildVaultGraphInput;
}

function vaultFixture(workspace: string): WriteVaultNotesInput {
  const sourceInput = makeGraphInput();
  const sourceWorkspace = sourceInput.systemMap.workspace;
  const finding = sourceInput.findings[0]!;
  finding.evidence = `api_key=secret-value observed at ${sourceWorkspace}/app/api/invoices/[id]/route.ts`;
  finding.validation.summary = `authorization=secret-value ${sourceWorkspace}\\private`;
  for (const event of sourceInput.history.findings) {
    if (event.finding.id === finding.id) event.finding = finding;
  }
  sourceInput.systemMap.routes[0]!.sourceSummary =
    '<script>alert(1)</script> api_key=secret-value';
  const graph = buildVaultGraph(sourceInput);
  const input = relocateInput(sourceInput, workspace);

  return {
    workspace,
    graph,
    history: input.history,
    systemMap: input.systemMap,
    invariantResults: input.invariantResults,
    patchMemory: buildPatchMemory(input.history)
  };
}

function routeProfileFixture(workspace: string): RouteProfileInput {
  const fixture = vaultFixture(workspace);
  fixture.invariantResults.invariants[0]!.evidence.push(
    '<script>alert(1)</script> password=secret-value'
  );
  fixture.patchMemory[0]!.verificationEvidence =
    '<script>alert(1)</script> token=secret-value';
  return {
    ...fixture,
    route: fixture.systemMap.routes[0]!
  };
}

function relativeFile(workspace: string, file: string): string {
  return path.relative(workspace, file).split(path.sep).join('/');
}

async function generatedFileContents(
  workspace: string,
  output: VaultNoteSummary
): Promise<Record<string, string>> {
  const files = [
    ...output.findings,
    ...output.routes,
    ...output.invariants,
    ...output.patches,
    ...output.replays,
    ...output.runs,
    ...output.daily,
    output.summaryPath
  ];
  const entries = await Promise.all(
    files.map(async (file) => [relativeFile(workspace, file), await readFile(file, 'utf8')] as const)
  );
  return Object.fromEntries(entries.sort(([left], [right]) => left.localeCompare(right)));
}

afterEach(async () => {
  await Promise.all(
    workspaces.splice(0).map((workspace) => rm(workspace, { recursive: true, force: true }))
  );
});

describe('Vault Markdown memory', () => {
  test('writes linked notes without secrets or absolute workspace paths', async () => {
    const workspace = await temporaryWorkspace();
    const { graph, history, systemMap, invariantResults, patchMemory } =
      vaultFixture(workspace);

    const output = await writeVaultNotes({
      workspace,
      graph,
      history,
      systemMap,
      invariantResults,
      patchMemory
    });
    const finding = await readFile(output.findings[0]!, 'utf8');

    expect(finding).toContain('type: finding');
    expect(finding).toContain('[[../../routes/');
    expect(finding).not.toContain(workspace);
    expect(finding).not.toContain('secret-value');
    expect(finding).toContain('## Lifecycle');
    expect(finding).toContain('## Attack Path');
    expect(finding).toContain('## Similar Findings');
    expect(finding).toContain('## Verification');
    expect(finding).toContain(
      '](../../../reports/evidence/generated-id/regression.test.ts)'
    );
    expect(output.routes).toHaveLength(1);
    expect(output.invariants).toHaveLength(1);
    expect(output.runs.length).toBeGreaterThan(0);
    expect(output.daily.length).toBeGreaterThan(0);
    await expect(access(output.summaryPath)).resolves.toBeUndefined();
  });

  test('writes deterministic notes and stable state summary ordering', async () => {
    const firstWorkspace = await temporaryWorkspace();
    const secondWorkspace = await temporaryWorkspace();
    const firstFixture = vaultFixture(firstWorkspace);
    const secondFixture = vaultFixture(secondWorkspace);

    const first = await writeVaultNotes(firstFixture);
    const second = await writeVaultNotes(secondFixture);
    const firstFiles = await generatedFileContents(firstWorkspace, first);
    const secondFiles = await generatedFileContents(secondWorkspace, second);

    expect(firstFixture).not.toBe(secondFixture);
    expect(Object.keys(secondFiles)).toEqual(Object.keys(firstFiles));
    expect(secondFiles).toEqual(firstFiles);
    const firstFinding = firstFiles[relativeFile(firstWorkspace, first.findings[0]!)]!;
    const firstSummary = firstFiles[relativeFile(firstWorkspace, first.summaryPath)]!;
    expect(firstFinding.indexOf('type: finding')).toBeLessThan(
      firstFinding.indexOf('status:')
    );
    expect(firstFinding).toContain('No request body values are stored.');
    expect(firstSummary).toContain('.breachproof/vault/findings/');
  });

  test('creates every category directory even when no category has notes', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    fixture.graph = {
      ...fixture.graph,
      nodes: [],
      edges: [],
      timeline: [],
      summary: {
        nodes: 0,
        edges: 0,
        newIssues: 0,
        fixedIssues: 0,
        reopenedIssues: 0,
        repeatedIssues: 0
      }
    };
    fixture.history = { runs: [], findings: [], patches: [], replays: [] };
    fixture.systemMap = { ...fixture.systemMap, routes: [] };
    fixture.invariantResults = {
      ...fixture.invariantResults,
      invariants: [],
      summary: { total: 0, passed: 0, failed: 0, manualReview: 0 }
    };
    fixture.patchMemory = [];

    const output = await writeVaultNotes(fixture);

    expect(output).toMatchObject({
      findings: [],
      routes: [],
      invariants: [],
      patches: [],
      replays: [],
      runs: [],
      daily: []
    });
    for (const category of [
      'findings',
      'routes',
      'invariants',
      'patches',
      'replays',
      'runs',
      'daily'
    ]) {
      await expect(
        access(path.join(workspace, '.breachproof', 'vault', category))
      ).resolves.toBeUndefined();
    }
  });
});

describe('Vault redaction', () => {
  test('redacts sensitive text and slash variants of regex-heavy workspaces', () => {
    const workspace = '/tmp/Protect.Me+(Please)[vault]';
    const backslashWorkspace = workspace.replaceAll('/', '\\');
    const unrelatedBackslashes = String.raw`C:\outside\evidence\trace.txt literal\nsequence`;
    const value = [
      `api_key=secret-value ${workspace}/private/file.ts`,
      `password=hunter2 ${backslashWorkspace}\\private\\file.ts`,
      unrelatedBackslashes
    ].join('\n');

    const redacted = redactVaultText(value, `${workspace}/`);

    expect(redacted).not.toContain('secret-value');
    expect(redacted).not.toContain('hunter2');
    expect(redacted).not.toContain(workspace);
    expect(redacted).not.toContain(backslashWorkspace);
    expect(redacted.match(/<workspace>/g)).toHaveLength(2);
    expect(redacted).toContain(unrelatedBackslashes);
  });

  test('creates deterministic lowercase ASCII path-safe slugs with a fallback', () => {
    expect(safeSlug('  Caf\u00e9 / INVOICE [ID]  ')).toBe('cafe-invoice-id');
    expect(safeSlug('Caf\u00e9 / INVOICE [ID]')).toBe(
      safeSlug('  Caf\u00e9 / INVOICE [ID]  ')
    );
    expect(safeSlug('\u6771\u4eac \ud83d\udd10')).toBe('item');
    expect(safeSlug('A_B.C')).toMatch(/^[a-z0-9-]+$/);
  });
});

describe('Vault route profiles', () => {
  test('renders a route profile with controls, history, evidence, and invariant cards', async () => {
    const workspace = await temporaryWorkspace();
    const html = renderRouteProfile(routeProfileFixture(workspace));

    expect(html).toContain('Route security profile');
    expect(html).toContain('tenant-isolation');
    expect(html).toContain('verified_fixed');
    expect(html).toContain('../index.html#node=');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).not.toContain('secret-value');
    expect(html).not.toContain(workspace);
  });

  test('escapes route-derived text and renders explicit empty connected sections', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = routeProfileFixture(workspace);
    fixture.route = {
      ...fixture.route,
      id: 'route" onclick="alert(1)',
      path: '/api/<script>alert(1)</script>',
      sourceSummary: '<script>alert(1)</script>'
    };
    fixture.systemMap = { ...fixture.systemMap, routes: [fixture.route], aiToolCalls: [] };

    const html = renderRouteProfile(fixture);

    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toContain('onclick="alert(1)');
    expect(html).toContain('No connected jobs represented by the current system map.');
    expect(html).toContain('No connected AI tools.');
    expect(html).not.toContain('<script');
    expect(html).not.toContain('src="http');
  });
});

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
import { vaultHistorySchema } from '../../src/vault/types.js';
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

function relocatedGraphInputFixture(workspace: string): BuildVaultGraphInput {
  const input = relocateInput(makeGraphInput(), workspace);
  const finding = input.findings[0]!;
  finding.evidence = 'api_key=secret-value observed at <workspace>/app/api/invoices/[id]/route.ts';
  finding.validation.summary = String.raw`authorization=secret-value <workspace>\private`;
  for (const event of input.history.findings) {
    if (event.finding.id === finding.id) event.finding = finding;
  }
  input.systemMap.routes[0]!.sourceSummary =
    '<script>alert(1)</script> api_key=secret-value';
  return input;
}

function vaultFixture(workspace: string): WriteVaultNotesInput {
  const input = relocatedGraphInputFixture(workspace);

  return {
    workspace,
    graph: buildVaultGraph(input),
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

  test('preserves attack-path order and duplicate steps', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    const orderedSteps = [
      'zeta entry',
      'alpha lookup',
      'zeta entry',
      'middle guard',
      'owner read',
      'beta sink',
      'tenant miss',
      'gamma response',
      'delta replay',
      'epsilon proof',
      'final impact'
    ];
    const events = fixture.history.findings
      .filter((event) => event.fingerprint === 'invoice-fingerprint')
      .sort((left, right) => left.observedAt.localeCompare(right.observedAt));
    for (const event of events) event.finding.attackPath = [];
    events.at(-1)!.finding.attackPath = orderedSteps;

    const output = await writeVaultNotes(fixture);
    const finding = await readFile(
      output.findings.find((file) => path.basename(file) === 'invoice-fingerprint.md')!,
      'utf8'
    );
    const attackPath = finding.split('## Attack Path')[1]!.split('## Invariants')[0]!;

    expect(attackPath).toContain(
      orderedSteps.map((step, index) => `- ${index + 1}. ${step}`).join('\n')
    );
  });

  test('writes patch nodes without note paths to distinct deterministic notes', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    const patchesWithoutPaths = fixture.graph.nodes.filter(
      (node) => node.type === 'patch' && !node.notePath
    );
    expect(patchesWithoutPaths.length).toBeGreaterThan(0);

    const output = await writeVaultNotes(fixture);
    const summary = await readFile(output.summaryPath, 'utf8');

    for (const node of patchesWithoutPaths) {
      const fallbackName = new RegExp(`^${safeSlug(node.id)}-[a-f0-9]{8}\\.md$`);
      const note = output.patches.find((file) => fallbackName.test(path.basename(file)));
      expect(note).toBeDefined();
      expect(await readFile(note!, 'utf8')).toContain(node.label);
      expect(summary).toContain(
        `.breachproof/vault/patches/${path.basename(note!)}`
      );
    }
    expect(new Set(output.patches.map((file) => path.basename(file))).size).toBe(
      output.patches.length
    );
  });

  test('hashes colliding fallback slugs into distinct deterministic note keys', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    const sourceNode = fixture.graph.nodes.find(
      (node) => node.type === 'patch' && !node.notePath
    )!;
    fixture.graph.nodes.push(
      {
        ...sourceNode,
        id: 'patch:a/b',
        label: 'Slash collision patch',
        notePath: undefined
      },
      {
        ...sourceNode,
        id: 'patch:a-b',
        label: 'Hyphen collision patch',
        notePath: undefined
      }
    );

    const first = await writeVaultNotes(fixture);
    const firstFiles = await generatedFileContents(workspace, first);
    const collisionEntries = Object.entries(firstFiles).filter(
      ([file, content]) =>
        file.startsWith('.breachproof/vault/patches/patch-a-b') &&
        (content.includes('Slash collision patch') ||
          content.includes('Hyphen collision patch'))
    );

    expect(collisionEntries).toHaveLength(2);
    expect(new Set(collisionEntries.map(([file]) => file)).size).toBe(2);
    expect(
      collisionEntries.every(([file]) =>
        /patch-a-b-[a-f0-9]{8}\.md$/.test(file)
      )
    ).toBe(true);
    expect(collisionEntries.some(([, content]) => content.includes('Slash collision patch'))).toBe(
      true
    );
    expect(collisionEntries.some(([, content]) => content.includes('Hyphen collision patch'))).toBe(
      true
    );
    const summary = await readFile(first.summaryPath, 'utf8');
    for (const [file] of collisionEntries) expect(summary).toContain(file);

    const second = await writeVaultNotes(fixture);
    expect(await generatedFileContents(workspace, second)).toEqual(firstFiles);
  });

  test('escapes artifact link labels so Markdown delimiters cannot terminate them', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    const testNode = fixture.graph.nodes.find((node) => node.type === 'test')!;
    testNode.label = String.raw`bad\](/malicious)[tail]`;

    const output = await writeVaultNotes(fixture);
    const finding = await readFile(
      output.findings.find((file) => path.basename(file) === 'invoice-fingerprint.md')!,
      'utf8'
    );
    const linkLine = finding
      .split('\n')
      .find((line) => line.includes('reports/evidence/generated-id/regression.test.ts'))!;

    expect(linkLine).not.toContain('](/malicious)');
    expect(linkLine).toContain(String.raw`bad\\\]\(/malicious\)\[tail\]`);
  });

  test('uses the newest finding event when graph node IDs sort in the opposite order', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    const events = fixture.history.findings
      .filter((event) => event.fingerprint === 'invoice-fingerprint')
      .sort((left, right) => left.observedAt.localeCompare(right.observedAt));
    const newestEvent = events.at(-1)!;
    newestEvent.finding.title = 'Newest finding title';
    newestEvent.finding.severity = 'critical';
    const newestNode = fixture.graph.nodes.find(
      (node) => node.id === `finding:${newestEvent.id}`
    )!;
    newestNode.label = 'Newest finding title';
    newestNode.status = 'newest-lifecycle';
    newestNode.severity = 'critical';
    const staleNode = fixture.graph.nodes.find(
      (node) =>
        node.type === 'finding' &&
        node.notePath === newestNode.notePath &&
        node.id !== newestNode.id
    )!;
    const staleId = staleNode.id;
    staleNode.id = 'finding:zzzz-stale';
    staleNode.label = 'Stale lexicographic title';
    staleNode.status = 'stale-status';
    staleNode.severity = 'low';
    fixture.graph.edges = fixture.graph.edges.map((edge) => ({
      ...edge,
      from: edge.from === staleId ? staleNode.id : edge.from,
      to: edge.to === staleId ? staleNode.id : edge.to
    }));

    const output = await writeVaultNotes(fixture);
    const finding = await readFile(
      output.findings.find((file) => path.basename(file) === 'invoice-fingerprint.md')!,
      'utf8'
    );

    expect(finding).toContain('title: Newest finding title');
    expect(finding).toContain('status: newest-lifecycle');
    expect(finding).toContain('severity: critical');
    expect(finding).toContain('# Newest finding title');
    expect(finding).not.toContain('title: Stale lexicographic title');
  });

  test('renders unavailable controls for graph routes absent from the system map', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    fixture.graph.nodes.push({
      id: 'route:detached-route',
      type: 'route',
      label: 'POST /api/detached',
      status: 'unknown',
      route: 'POST /api/detached',
      notePath: '.breachproof/vault/routes/detached-route.md',
      profilePath: 'reports/vault/route-profiles/detached-route.html',
      metadata: { file: 'app/api/detached/route.ts' }
    });

    const output = await writeVaultNotes(fixture);
    const route = await readFile(
      output.routes.find((file) => path.basename(file) === 'detached-route.md')!,
      'utf8'
    );

    expect(route).toContain('Authentication detected: unavailable');
    expect(route).toContain('Ownership check detected: unavailable');
    expect(route).toContain('Tenant scoping status: unavailable');
    expect(route).toContain('Upload validation: unavailable');
    expect(route).toContain('Webhook signature verification: unavailable');
    expect(route).not.toContain('Authentication detected: no');
    expect(route).not.toContain('Tenant scoping status: not detected');
  });

  test('builds fixture graphs from the same relocated workspace as their artifacts', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = vaultFixture(workspace);
    const relocatedInput = relocatedGraphInputFixture(workspace);

    expect(fixture.systemMap.workspace).toBe(workspace);
    expect(fixture.graph).toEqual(buildVaultGraph(relocatedInput));
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

  test('redacts only exact workspace boundaries, not longer path prefixes', () => {
    const workspace = '/repo/project';

    expect(redactVaultText(workspace, workspace)).toBe('<workspace>');
    expect(redactVaultText(`${workspace}/file.ts`, workspace)).toBe(
      '<workspace>/file.ts'
    );
    expect(redactVaultText(`${workspace}\\file.ts`, workspace)).toBe(
      '<workspace>\\file.ts'
    );
    expect(redactVaultText(`${workspace}-copy/file.ts`, workspace)).toBe(
      `${workspace}-copy/file.ts`
    );
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

  test('preserves chronological verification order and repeated entries', async () => {
    const workspace = await temporaryWorkspace();
    const fixture = routeProfileFixture(workspace);
    const sourceEvent = fixture.history.findings.find(
      (event) => event.fingerprint === 'invoice-fingerprint'
    )!;
    const repeatedEvent = {
      ...sourceEvent,
      id: 'finding-repeat-a',
      runId: 'repeat-run-a',
      observedAt: '2026-06-06T10:00:00.000Z',
      verificationStatus: 'passed' as const,
      finding: {
        ...sourceEvent.finding,
        validation: {
          ...sourceEvent.finding.validation,
          summary: 'Zulu repeated verification'
        }
      }
    };
    fixture.history.findings.push(repeatedEvent, {
      ...repeatedEvent,
      id: 'finding-repeat-b',
      runId: 'repeat-run-b'
    });
    fixture.history.findings.push({
      ...repeatedEvent,
      id: 'finding-later',
      runId: 'later-run',
      observedAt: '2026-06-07T10:00:00.000Z',
      finding: {
        ...repeatedEvent.finding,
        validation: {
          ...repeatedEvent.finding.validation,
          summary: 'Alpha later verification'
        }
      }
    });
    const sourceRun = fixture.history.runs.find((run) => run.id === 'day-5')!;
    fixture.history.runs.push(
      {
        ...sourceRun,
        id: 'repeat-run-a',
        startedAt: '2026-06-06T09:59:00.000Z',
        completedAt: '2026-06-06T10:00:00.000Z'
      },
      {
        ...sourceRun,
        id: 'repeat-run-b',
        startedAt: '2026-06-06T09:59:00.000Z',
        completedAt: '2026-06-06T10:00:00.000Z'
      },
      {
        ...sourceRun,
        id: 'later-run',
        startedAt: '2026-06-07T09:59:00.000Z',
        completedAt: '2026-06-07T10:00:00.000Z'
      }
    );

    const addedEvents = fixture.history.findings.slice(-3);
    expect(new Set(addedEvents.map((event) => event.runId)).size).toBe(
      addedEvents.length
    );
    expect(vaultHistorySchema.parse(fixture.history)).toEqual(fixture.history);

    const html = renderRouteProfile(fixture);
    const repeated =
      '2026-06-06T10:00:00.000Z - passed: Zulu repeated verification';
    const later = '2026-06-07T10:00:00.000Z - passed: Alpha later verification';

    expect(html.split(repeated)).toHaveLength(3);
    expect(html.indexOf(repeated)).toBeLessThan(html.indexOf(later));
  });
});

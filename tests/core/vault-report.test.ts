import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, test } from 'vitest';
import { buildVaultGraph } from '../../src/vault/graph.js';
import {
  serializeEmbeddedJson,
  writeVaultReport,
  type VaultRouteProfile
} from '../../src/vault/report.js';
import {
  vaultGraphSchema,
  vaultTimelineEventSchema,
  type VaultGraph
} from '../../src/vault/types.js';
import { makeGraphInput } from '../helpers/vault-fixtures.js';

const workspaces: string[] = [];

async function temporaryWorkspace(): Promise<string> {
  const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-report-'));
  workspaces.push(workspace);
  return workspace;
}

function graphFixture(): VaultGraph {
  return buildVaultGraph(makeGraphInput());
}

function embeddedGraph(html: string): unknown {
  const match = html.match(
    /<script type="application\/json" id="breachproof-vault-data">([\s\S]*?)<\/script>/
  );
  expect(match).not.toBeNull();
  return JSON.parse(match?.[1] ?? 'null') as unknown;
}

async function routeProfileContents(
  workspace: string,
  files: string[]
): Promise<Record<string, string>> {
  const entries = await Promise.all(
    files.map(async (file) => [path.relative(workspace, file), await readFile(file, 'utf8')] as const)
  );
  return Object.fromEntries(entries);
}

afterEach(async () => {
  await Promise.all(
    workspaces.splice(0).map((workspace) => rm(workspace, { recursive: true, force: true }))
  );
});

describe('offline Vault report', () => {
  test('writes an offline report with safe embedded data and portable graph.json', async () => {
    const workspace = await temporaryWorkspace();
    const graph = graphFixture();
    graph.project = 'unsafe < > & \u2028 \u2029 </script><script>alert(1)</script>';
    const routeProfiles = [
      { routeId: 'GET /api/invoices/[id]', html: '<!doctype html><title>Invoice route</title>' }
    ];

    const result = await writeVaultReport({
      workspace,
      reportsDir: 'reports',
      graph,
      routeProfiles
    });
    const html = await readFile(result.indexFile, 'utf8');
    const json: unknown = JSON.parse(await readFile(result.graphFile, 'utf8'));
    const timeline: unknown = JSON.parse(await readFile(result.timelineFile, 'utf8'));

    expect(vaultGraphSchema.parse(json)).toEqual(json);
    expect(vaultTimelineEventSchema.array().parse(timeline)).toEqual(graph.timeline);
    expect(embeddedGraph(html)).toEqual(json);
    expect(html).toContain('id="breachproof-vault-data"');
    expect(html).toContain('./assets/vault.css');
    expect(html).toContain('./assets/vault-graph.js');
    expect(html).toContain("default-src 'self' data: blob:");
    expect(html).not.toMatch(/https?:\/\//i);
    expect(html).not.toContain('</script><script>alert(1)</script>');
    await access(path.join(workspace, 'reports/vault/assets/vault-graph.js'));
  });

  test('escapes every HTML-sensitive JSON character and remains parseable', () => {
    const value = {
      content: '<tag>Tom & Jerry</tag>\u2028line separator\u2029paragraph separator'
    };

    const serialized = serializeEmbeddedJson(value);

    expect(serialized).toContain('\\u003ctag\\u003e');
    expect(serialized).toContain('Tom \\u0026 Jerry');
    expect(serialized).toContain('\\u003c/tag\\u003e');
    expect(serialized).toContain('\\u2028');
    expect(serialized).toContain('\\u2029');
    expect(serialized).not.toMatch(/[<>&\u2028\u2029]/u);
    expect(JSON.parse(serialized)).toEqual(value);
  });

  test('writes stable readable JSON and copies both built UI assets', async () => {
    const firstWorkspace = await temporaryWorkspace();
    const secondWorkspace = await temporaryWorkspace();
    const firstGraph = graphFixture();
    const secondGraph = structuredClone(firstGraph);
    firstGraph.nodes[0]!.metadata = { zeta: 'last', alpha: 'first' };
    secondGraph.nodes[0]!.metadata = { alpha: 'first', zeta: 'last' };

    const first = await writeVaultReport({
      workspace: firstWorkspace,
      reportsDir: 'reports',
      graph: firstGraph,
      routeProfiles: []
    });
    const second = await writeVaultReport({
      workspace: secondWorkspace,
      reportsDir: 'reports',
      graph: secondGraph,
      routeProfiles: []
    });
    const firstGraphJson = await readFile(first.graphFile, 'utf8');
    const secondGraphJson = await readFile(second.graphFile, 'utf8');
    const timelineJson = await readFile(first.timelineFile, 'utf8');

    expect(firstGraphJson).toBe(secondGraphJson);
    expect(firstGraphJson).toBe(`${JSON.stringify(JSON.parse(firstGraphJson), null, 2)}\n`);
    expect(timelineJson).toBe(`${JSON.stringify(JSON.parse(timelineJson), null, 2)}\n`);
    expect(first.assetFiles).toEqual([
      path.join(firstWorkspace, 'reports/vault/assets/vault-graph.js'),
      path.join(firstWorkspace, 'reports/vault/assets/vault.css')
    ]);
    await Promise.all(
      first.assetFiles.map(async (assetFile) => {
        const sourceFile = path.resolve('dist/vault-ui', path.basename(assetFile));
        expect(await readFile(assetFile)).toEqual(await readFile(sourceFile));
      })
    );
  });

  test('writes path-safe collision-safe route profiles deterministically', async () => {
    const firstWorkspace = await temporaryWorkspace();
    const secondWorkspace = await temporaryWorkspace();
    const routeProfiles: VaultRouteProfile[] = [
      { routeId: 'Admin Route', html: '<p>alpha</p>' },
      { routeId: 'admin/route', html: '<p>beta</p>' },
      { routeId: '../admin route', html: '<p>gamma</p>' }
    ];

    const first = await writeVaultReport({
      workspace: firstWorkspace,
      reportsDir: 'reports',
      graph: graphFixture(),
      routeProfiles
    });
    const second = await writeVaultReport({
      workspace: secondWorkspace,
      reportsDir: 'reports',
      graph: graphFixture(),
      routeProfiles: [...routeProfiles].reverse()
    });
    const firstContents = await routeProfileContents(firstWorkspace, first.routeProfileFiles);
    const secondContents = await routeProfileContents(secondWorkspace, second.routeProfileFiles);

    expect(new Set(first.routeProfileFiles).size).toBe(routeProfiles.length);
    expect(first.routeProfileFiles).toEqual(
      [...first.routeProfileFiles].sort((left, right) => left.localeCompare(right))
    );
    expect(first.routeProfileFiles.every((file) => path.isAbsolute(file))).toBe(true);
    expect(
      first.routeProfileFiles.every(
        (file) => path.dirname(file) === path.join(firstWorkspace, 'reports/vault/route-profiles')
      )
    ).toBe(true);
    expect(firstContents).toEqual(secondContents);
    expect(Object.values(firstContents).sort()).toEqual(
      routeProfiles.map((profile) => profile.html).sort()
    );
  });

  test('supports an empty route profile list', async () => {
    const workspace = await temporaryWorkspace();

    const result = await writeVaultReport({
      workspace,
      reportsDir: 'reports',
      graph: graphFixture(),
      routeProfiles: []
    });

    expect(result.routeProfileFiles).toEqual([]);
    await expect(
      access(path.join(workspace, 'reports/vault/route-profiles'))
    ).resolves.toBeUndefined();
  });

  test('reports a precise error when a built UI asset is missing', async () => {
    const workspace = await temporaryWorkspace();
    const uiAssetsDir = path.join(workspace, 'incomplete-vault-ui');
    await mkdir(uiAssetsDir, { recursive: true });
    await writeFile(path.join(uiAssetsDir, 'vault-graph.js'), '/* built */\n', 'utf8');

    await expect(
      writeVaultReport({
        workspace,
        reportsDir: 'reports',
        graph: graphFixture(),
        routeProfiles: [],
        uiAssetsDir
      })
    ).rejects.toThrow(/vault\.css.*npm run build:vault-ui/is);
  });

  test('validates before writing and does not mutate inputs', async () => {
    const workspace = await temporaryWorkspace();
    const graph = graphFixture();
    const routeProfiles: VaultRouteProfile[] = [
      { routeId: 'GET /api/invoices/[id]', html: '<p>Invoice</p>' }
    ];
    const graphBefore = structuredClone(graph);
    const routeProfilesBefore = structuredClone(routeProfiles);

    await writeVaultReport({
      workspace,
      reportsDir: 'reports',
      graph,
      routeProfiles
    });

    expect(graph).toEqual(graphBefore);
    expect(routeProfiles).toEqual(routeProfilesBefore);

    const invalidGraph = { ...graph, schemaVersion: 2 } as unknown as VaultGraph;
    const invalidWorkspace = await temporaryWorkspace();
    await expect(
      writeVaultReport({
        workspace: invalidWorkspace,
        reportsDir: 'reports',
        graph: invalidGraph,
        routeProfiles: []
      })
    ).rejects.toThrow();
    await expect(access(path.join(invalidWorkspace, 'reports/vault'))).rejects.toThrow();
  });
});

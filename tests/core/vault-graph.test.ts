import { describe, expect, test } from 'vitest';
import { buildVaultGraph } from '../../src/vault/graph.js';
import { findingFingerprint } from '../../src/vault/fingerprint.js';
import { buildPatchMemory } from '../../src/vault/history.js';
import { vaultGraphSchema } from '../../src/vault/types.js';
import {
  makeGraphInput,
  makePatchHistory,
  makeSnapshot
} from '../helpers/vault-fixtures.js';

const nodeTypes = ['ai_tool', 'asset', 'auth_gate', 'file', 'finding', 'invariant', 'model', 'patch', 'replay', 'route', 'run', 'test', 'upload', 'webhook'];
const edgeTypes = [
  'affects',
  'fixed_by',
  'observed_in',
  'protects',
  'proved_by',
  'reaches',
  'reopened_from',
  'repeated_from',
  'similar_to',
  'verified_by',
  'violates'
];

describe('Vault graph projection', () => {
  test('emits every supplied node and evidence-backed edge type as schema version 2', () => {
    const graph = buildVaultGraph(makeGraphInput());

    expect([...new Set(graph.nodes.map((node) => node.type))].sort()).toEqual(nodeTypes);
    expect([...new Set(graph.edges.map((edge) => edge.type))].sort()).toEqual(edgeTypes);
    expect(graph.schemaVersion).toBe(2);
    expect(graph.timeline.map((event) => event.lifecycle)).toEqual(
      expect.arrayContaining(['new', 'repeated', 'fixed', 'reopened'])
    );
    expect(graph.edges.every((edge) => edge.evidence.trim().length > 0)).toBe(true);
    expect(vaultGraphSchema.parse(graph)).toEqual(graph);
  });

  test('links current findings to similar prior occurrences with an explained threshold score', () => {
    const graph = buildVaultGraph(makeGraphInput());
    const similar = graph.edges.find((edge) => edge.type === 'similar_to');

    expect(similar?.score).toBeGreaterThanOrEqual(0.75);
    expect(similar?.signals).toEqual(
      expect.arrayContaining(['same_rule', 'same_control_family', 'same_sink'])
    );
    expect(similar?.from).not.toBe(similar?.to);
    expect(similar?.evidence).toContain('0.75');
  });

  test('links repeated and reopened events to prior occurrence nodes and preserves related fingerprints', () => {
    const graph = buildVaultGraph(makeGraphInput());
    const repeated = graph.edges.find((edge) => edge.type === 'repeated_from');
    const reopened = graph.edges.find((edge) => edge.type === 'reopened_from');
    const repeatedEvent = graph.timeline.find((event) => event.lifecycle === 'repeated');
    const reopenedEvent = graph.timeline.find((event) => event.lifecycle === 'reopened');

    expect(repeated?.from).not.toBe(repeated?.to);
    expect(reopened?.from).not.toBe(reopened?.to);
    expect(repeatedEvent?.relatedFingerprint).toBe('invoice-fingerprint');
    expect(reopenedEvent?.relatedFingerprint).toBe('invoice-fingerprint');
  });

  test('sorts and deduplicates output while preserving referential integrity and safe paths', () => {
    const input = makeGraphInput();
    input.findings.push(input.findings[0]!);
    const graph = buildVaultGraph(input);
    const again = buildVaultGraph(input);
    const nodeIds = graph.nodes.map((node) => node.id);
    const edgeIds = graph.edges.map((edge) => edge.id);

    expect(again).toEqual(graph);
    expect(graph.nodes).toEqual(
      [...graph.nodes].sort(
        (left, right) => left.type.localeCompare(right.type) || left.id.localeCompare(right.id)
      )
    );
    expect(graph.edges).toEqual(
      [...graph.edges].sort(
        (left, right) =>
          left.type.localeCompare(right.type) ||
          left.from.localeCompare(right.from) ||
          left.to.localeCompare(right.to) ||
          left.id.localeCompare(right.id)
      )
    );
    expect(graph.timeline).toEqual(
      [...graph.timeline].sort(
        (left, right) =>
          left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)
      )
    );
    expect(new Set(nodeIds).size).toBe(nodeIds.length);
    expect(new Set(edgeIds).size).toBe(edgeIds.length);
    expect(graph.edges.every((edge) => nodeIds.includes(edge.from) && nodeIds.includes(edge.to))).toBe(true);
    expect(JSON.stringify(graph)).not.toContain(input.systemMap.workspace);
    expect(
      graph.nodes.every(
        (node) =>
          !node.notePath?.startsWith('/') &&
          !node.profilePath?.startsWith('/') &&
          !node.notePath?.includes('..') &&
          !node.profilePath?.includes('..')
      )
    ).toBe(true);
    expect(graph.edges.flatMap((edge) => edge.artifactPaths).every((file) => !file.startsWith('/'))).toBe(true);
    expect(graph.summary).toEqual({
      nodes: graph.nodes.length,
      edges: graph.edges.length,
      newIssues: 2,
      fixedIssues: 1,
      reopenedIssues: 1,
      repeatedIssues: 1
    });
  });

  test('rejects conflicting duplicate node identities before schema parsing', () => {
    const input = makeGraphInput();
    input.systemMap.routes.push({
      ...input.systemMap.routes[0]!,
      path: '/api/projects/[id]'
    });

    expect(() => buildVaultGraph(input)).toThrow(/duplicate node id/i);
  });

  test('keeps repeated evidence entries for one finding as distinct replay nodes', () => {
    const input = makeGraphInput();
    input.evidence.items.push({
      ...input.evidence.items[0]!,
      directory: 'reports/evidence/generated-id-second'
    });

    const graph = buildVaultGraph(input);
    const replayIds = graph.nodes
      .filter((node) => node.id.startsWith('replay:evidence:day-5:'))
      .map((node) => node.id);

    expect(replayIds).toEqual([
      'replay:evidence:day-5:invoice-fingerprint',
      'replay:evidence:day-5:invoice-fingerprint:2'
    ]);
  });

  test('keeps repeated patch summaries for one fingerprint as distinct nodes', () => {
    const input = makeGraphInput();
    input.patchSummary.items.push({
      ...input.patchSummary.items[0]!,
      summary: 'Added a shared tenant policy guard.'
    });

    const graph = buildVaultGraph(input);
    const patchIds = graph.nodes
      .filter((node) => node.id.startsWith('patch:summary:day-5:'))
      .map((node) => node.id);

    expect(patchIds).toEqual([
      'patch:summary:day-5:invoice-fingerprint:verified_fixed',
      'patch:summary:day-5:invoice-fingerprint:verified_fixed:2'
    ]);
  });

  test('does not treat a tournament recommendation as a verified fix', () => {
    const input = makeGraphInput();
    input.patchSummary.items = [];
    input.history.patches = [];
    input.verification.items = [];
    const graph = buildVaultGraph(input);

    expect(graph.edges.filter((edge) => edge.type === 'fixed_by')).toHaveLength(0);
    expect(graph.edges.filter((edge) => edge.type === 'verified_by')).toHaveLength(0);
  });

  test('skips replay and patch claim edges when optional source artifacts are missing', () => {
    const input = makeGraphInput();
    input.history.replays = input.history.replays.map((replay) => ({
      ...replay,
      artifactPath: undefined
    }));
    input.history.patches = input.history.patches.map((patch) => ({
      ...patch,
      patchFile: undefined,
      testFile: undefined
    }));
    input.patchSummary.items = input.patchSummary.items.map((item) => ({
      ...item,
      patchFile: undefined,
      testFile: undefined
    }));

    const graph = buildVaultGraph(input);
    const replayEdge = graph.edges.find(
      (edge) => edge.type === 'proved_by' && edge.to === 'replay:replay-day-2-fixed'
    );
    const historicalPatchEdge = graph.edges.find(
      (edge) => edge.type === 'fixed_by' && edge.to === 'patch:patch-day-2-fixed'
    );
    const summaryPatchEdge = graph.edges.find(
      (edge) =>
        edge.type === 'fixed_by' &&
        edge.to === 'patch:summary:day-5:invoice-fingerprint:verified_fixed'
    );
    const summaryReplayVerificationEdge = graph.edges.find(
      (edge) =>
        edge.type === 'verified_by' &&
        edge.from === 'patch:summary:day-5:invoice-fingerprint:verified_fixed' &&
        edge.to === 'replay:evidence:day-5:invoice-fingerprint'
    );

    expect(graph.edges.every((edge) => edge.artifactPaths.length > 0)).toBe(true);
    expect(vaultGraphSchema.parse(graph)).toEqual(graph);
    expect(replayEdge).toBeUndefined();
    expect(historicalPatchEdge).toBeUndefined();
    expect(summaryPatchEdge).toBeUndefined();
    expect(summaryReplayVerificationEdge?.artifactPaths).toEqual([
      'reports/evidence/generated-id'
    ]);
  });

  test('projects detached current findings through the shared lifecycle timeline', () => {
    const reopenedInput = makeGraphInput();
    const currentFingerprint = findingFingerprint(reopenedInput.findings[0]!);
    reopenedInput.history.findings = reopenedInput.history.findings.map((event) => ({
      ...event,
      fingerprint:
        event.fingerprint === 'invoice-fingerprint'
          ? currentFingerprint
          : event.fingerprint
    }));
    reopenedInput.history.findings = reopenedInput.history.findings.filter(
      (event) => event.runId !== reopenedInput.currentRunId
    );

    const reopenedGraph = buildVaultGraph(reopenedInput);
    const reopenedNode = reopenedGraph.nodes.find(
      (node) => node.id === `finding:day-5:${currentFingerprint}`
    );
    const reopenedTimeline = reopenedGraph.timeline.filter(
      (event) => event.findingFingerprint === currentFingerprint
    );
    const reopenedEdge = reopenedGraph.edges.find((edge) => edge.type === 'reopened_from');

    expect(reopenedNode?.status).toBe('reopened');
    expect(reopenedTimeline.at(-1)?.lifecycle).toBe('reopened');
    expect(reopenedGraph.summary.reopenedIssues).toBe(1);
    expect(reopenedEdge?.from).toBe(`finding:day-5:${currentFingerprint}`);
    expect(reopenedEdge?.artifactPaths).toEqual(['app/api/invoices/[id]/route.ts']);

    const repeatedInput = makeGraphInput();
    repeatedInput.history.findings = repeatedInput.history.findings.map((event) => ({
      ...event,
      fingerprint:
        event.fingerprint === 'invoice-fingerprint'
          ? currentFingerprint
          : event.fingerprint
    }));
    repeatedInput.history.findings = repeatedInput.history.findings.filter(
      (event) =>
        event.runId !== repeatedInput.currentRunId &&
        event.lifecycleInput !== 'verified_fixed'
    );
    repeatedInput.history.patches = [];
    repeatedInput.history.replays = [];

    const repeatedGraph = buildVaultGraph(repeatedInput);
    const repeatedNode = repeatedGraph.nodes.find(
      (node) => node.id === `finding:day-5:${currentFingerprint}`
    );
    const repeatedTimeline = repeatedGraph.timeline.filter(
      (event) => event.findingFingerprint === currentFingerprint
    );
    const repeatedEdge = repeatedGraph.edges.find((edge) => edge.type === 'repeated_from');

    expect(repeatedNode?.status).toBe('repeated');
    expect(repeatedTimeline.at(-1)?.lifecycle).toBe('repeated');
    expect(repeatedGraph.summary.repeatedIssues).toBe(2);
    expect(repeatedEdge?.from).toBe(`finding:day-5:${currentFingerprint}`);
  });

  test('does not fabricate regression test artifacts from evidence directories alone', () => {
    const input = makeGraphInput();
    input.history.patches = input.history.patches.map((patch) => ({
      ...patch,
      testFile: undefined
    }));
    input.patchSummary.items = input.patchSummary.items.map((item) => ({
      ...item,
      testFile: undefined
    }));

    const graph = buildVaultGraph(input);

    expect(graph.nodes.filter((node) => node.type === 'test')).toHaveLength(0);
    expect(
      graph.edges.some((edge) =>
        edge.artifactPaths.includes('reports/evidence/generated-id/regression.test.ts')
      )
    ).toBe(false);
    expect(
      graph.edges.some(
        (edge) => edge.type === 'protects' && edge.from.startsWith('test:')
      )
    ).toBe(false);
  });
});

describe('Vault patch memory', () => {
  test('remembers only verified fixes and counts later reopenings', () => {
    const memory = buildPatchMemory(
      makePatchHistory(['patch_created', 'test_added', 'verified_fixed'])
    );

    expect(memory).toHaveLength(1);
    expect(memory[0]).toMatchObject({
      patternId: 'tenant-scope-query',
      strategy: 'add-tenant-predicate',
      regressionTestArtifact: 'reports/evidence/generated-id/regression.test.ts',
      verificationRunId: 'day-2-fixed',
      findingFingerprints: ['invoice-fingerprint'],
      reopenedCount: 1,
      outcome: 'verified_fixed'
    });
    expect(memory[0]?.verificationEvidence).toContain('Cross-tenant request denied');
  });

  test('groups compatible verified fixes and sorts unique fingerprints', () => {
    const history = makePatchHistory(['verified_fixed']);
    history.patches.push({
      ...history.patches[0]!,
      id: 'patch-memory-02',
      findingFingerprint: 'alpha-fingerprint',
      observedAt: '2026-06-02T11:01:00.000Z'
    });
    history.patches.push({
      ...history.patches[0]!,
      id: 'patch-memory-03',
      outcome: 'patch_created',
      findingFingerprint: 'ignored-fingerprint',
      observedAt: '2026-06-02T11:02:00.000Z'
    });

    const memory = buildPatchMemory(history);

    expect(memory).toHaveLength(1);
    expect(memory[0]?.findingFingerprints).toEqual([
      'alpha-fingerprint',
      'invoice-fingerprint'
    ]);
    expect(memory[0]?.outcome).toBe('verified_fixed');
  });

  test('keeps grouped verification metadata aligned with the reopened-count window', () => {
    const history = makePatchHistory(['verified_fixed']);
    const laterVerifiedRun = makeSnapshot('day-7-fixed', 'verified_fixed');
    const laterVerifiedFinding = laterVerifiedRun.findings[0]!;

    history.runs.push(laterVerifiedRun.run);
    history.findings.push({
      id: 'finding-day-7-fixed',
      runId: laterVerifiedRun.run.id,
      fingerprint: laterVerifiedFinding.fingerprint,
      lifecycleInput: laterVerifiedFinding.lifecycleInput,
      ruleId: laterVerifiedFinding.finding.ruleId,
      finding: laterVerifiedFinding.finding,
      verificationStatus: 'verified_fixed',
      observedAt: laterVerifiedRun.run.completedAt
    });
    history.patches.push({
      ...history.patches[0]!,
      id: 'patch-memory-02',
      runId: laterVerifiedRun.run.id,
      verificationEvidence: 'Later verification evidence should not reset the reopened window.',
      observedAt: laterVerifiedRun.run.completedAt
    });

    const memory = buildPatchMemory(history);

    expect(memory).toHaveLength(1);
    expect(memory[0]).toMatchObject({
      verificationRunId: 'day-2-fixed',
      verificationEvidence: 'Cross-tenant request denied after the tenant predicate was added.',
      reopenedCount: 1
    });
  });

  test('never promotes generated or recommended patch states to success', () => {
    expect(buildPatchMemory(makePatchHistory(['patch_created', 'test_added']))).toEqual([]);
  });
});

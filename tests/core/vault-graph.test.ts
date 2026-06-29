import { describe, expect, test } from 'vitest';
import { buildVaultGraph } from '../../src/vault/graph.js';
import { buildPatchMemory } from '../../src/vault/history.js';
import { vaultGraphSchema } from '../../src/vault/types.js';
import { makeGraphInput, makePatchHistory } from '../helpers/vault-fixtures.js';

const nodeTypes = ['asset', 'finding', 'invariant', 'patch', 'replay', 'route', 'run', 'test'];
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
  test('emits every supplied node and evidence-backed edge type as schema version 1', () => {
    const graph = buildVaultGraph(makeGraphInput());

    expect([...new Set(graph.nodes.map((node) => node.type))].sort()).toEqual(nodeTypes);
    expect([...new Set(graph.edges.map((edge) => edge.type))].sort()).toEqual(edgeTypes);
    expect(graph.schemaVersion).toBe(1);
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

  test('does not treat a tournament recommendation as a verified fix', () => {
    const input = makeGraphInput();
    input.patchSummary.items = [];
    input.history.patches = [];
    input.verification.items = [];
    const graph = buildVaultGraph(input);

    expect(graph.edges.filter((edge) => edge.type === 'fixed_by')).toHaveLength(0);
    expect(graph.edges.filter((edge) => edge.type === 'verified_by')).toHaveLength(0);
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

  test('never promotes generated or recommended patch states to success', () => {
    expect(buildPatchMemory(makePatchHistory(['patch_created', 'test_added']))).toEqual([]);
  });
});

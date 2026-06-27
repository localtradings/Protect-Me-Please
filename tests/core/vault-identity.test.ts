import { describe, expect, test } from 'vitest';
import { findingFingerprint, routeFingerprint } from '../../src/vault/fingerprint.js';
import { compareFindingSimilarity, findSimilarFindings } from '../../src/vault/similarity.js';
import {
  vaultEdgeTypeSchema,
  vaultGraphSchema,
  vaultLifecycleSchema,
  vaultNodeTypeSchema
} from '../../src/vault/types.js';
import { makeFinding } from '../helpers/vault-fixtures.js';

describe('Vault identities', () => {
  test('ignores workspace prefixes, generated IDs, line numbers, and prose variation', () => {
    const original = makeFinding();
    const moved = makeFinding({
      id: 'other-generated-id',
      title: 'Reworded title',
      evidence: 'Different evidence wording with no stable identity data',
      exploitabilityReasoning: 'Different reasoning prose',
      recommendation: 'Different recommendation prose',
      affectedFiles: ['/tmp/another-workspace/app/api/invoices/[id]/route.ts:417']
    });

    expect(findingFingerprint(original)).toBe(findingFingerprint(moved));
  });

  test('changes when the protected sink changes', () => {
    expect(findingFingerprint(makeFinding())).not.toBe(
      findingFingerprint(makeFinding({ attackPath: ['GET /api/invoices/[id]', 'User'] }))
    );
  });

  test('normalizes route parameters while retaining the HTTP method', () => {
    const numeric = routeFingerprint('get', '/api/invoices/123');

    expect(numeric).toBe(routeFingerprint('GET', '/api/invoices/[id]'));
    expect(numeric).toBe(routeFingerprint('GET', '/api/invoices/:id'));
    expect(numeric).not.toBe(routeFingerprint('POST', '/api/invoices/:id'));
  });
});

describe('Vault finding similarity', () => {
  test('explains a similar invoice/orders bug without treating it as identical', () => {
    const result = compareFindingSimilarity(
      makeFinding(),
      makeFinding({
        id: 'orders-finding',
        affectedRoutes: ['GET /api/orders/[id]'],
        affectedFiles: ['app/api/orders/[id]/route.ts'],
        attackPath: ['GET /api/orders/[id]', 'Invoice']
      })
    );

    expect(result.exactMatch).toBe(false);
    expect(result.score).toBeGreaterThanOrEqual(0.75);
    expect(result.signals).toContain('same_rule');
    expect(result.signals).toEqual([...result.signals].sort());
  });

  test('identifies exact fingerprints and excludes them from similar findings', () => {
    const current = makeFinding();
    const exact = makeFinding({ id: 'rerun-generated-id', title: 'Same finding, new prose' });

    expect(compareFindingSimilarity(current, exact).exactMatch).toBe(true);
    expect(findSimilarFindings(current, [exact])).toEqual([]);
  });

  test('sorts equal-score matches by stable fingerprint', () => {
    const current = makeFinding();
    const candidates = [
      makeFinding({
        id: 'payments',
        affectedRoutes: ['GET /api/payments/[id]'],
        affectedFiles: ['app/api/payments/[id]/route.ts'],
        attackPath: ['GET /api/payments/[id]', 'Invoice']
      }),
      makeFinding({
        id: 'orders',
        affectedRoutes: ['GET /api/orders/[id]'],
        affectedFiles: ['app/api/orders/[id]/route.ts'],
        attackPath: ['GET /api/orders/[id]', 'Invoice']
      })
    ];

    const forward = findSimilarFindings(current, candidates);
    const reverse = findSimilarFindings(current, [...candidates].reverse());

    expect(forward).toEqual(reverse);
    expect(forward).toHaveLength(2);
    expect(forward.map((match) => match.previousFingerprint)).toEqual(
      forward.map((match) => match.previousFingerprint).sort()
    );
  });
});

describe('Vault graph contracts', () => {
  test('defines every node, edge, and lifecycle value', () => {
    expect(vaultNodeTypeSchema.options).toEqual([
      'run',
      'route',
      'finding',
      'invariant',
      'patch',
      'replay',
      'test',
      'asset'
    ]);
    expect(vaultEdgeTypeSchema.options).toEqual([
      'observed_in',
      'affects',
      'violates',
      'reaches',
      'proved_by',
      'fixed_by',
      'verified_by',
      'similar_to',
      'reopened_from',
      'repeated_from',
      'protects'
    ]);
    expect(vaultLifecycleSchema.options).toEqual([
      'new',
      'repeated',
      'fixed',
      'reopened',
      'not_observed'
    ]);
  });

  test('parses schema version 1 and applies collection defaults', () => {
    const parsed = vaultGraphSchema.parse({
      schemaVersion: 1,
      generatedAt: '2026-06-28T00:00:00.000Z',
      project: 'breachproof',
      currentRunId: 'run-1',
      nodes: [
        {
          id: 'finding:invoice',
          type: 'finding',
          label: 'Tenant escape',
          status: 'new'
        }
      ],
      edges: [
        {
          id: 'finding-run',
          from: 'finding:invoice',
          to: 'run:1',
          type: 'observed_in',
          label: 'observed in',
          evidence: 'Recorded in run 1'
        }
      ],
      timeline: [
        {
          id: 'timeline:run-1:invoice',
          runId: 'run-1',
          findingFingerprint: 'invoice-fingerprint',
          lifecycle: 'new',
          timestamp: '2026-06-28T00:00:00.000Z',
          ruleId: 'BP-BOLA-002',
          title: 'Tenant escape'
        }
      ],
      summary: {
        nodes: 1,
        edges: 1,
        newIssues: 1,
        fixedIssues: 0,
        reopenedIssues: 0,
        repeatedIssues: 0
      }
    });

    expect(parsed.nodes[0]?.metadata).toEqual({});
    expect(parsed.edges[0]?.artifactPaths).toEqual([]);
    expect(parsed.timeline[0]?.artifactPaths).toEqual([]);
  });
});

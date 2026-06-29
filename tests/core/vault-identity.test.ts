import { describe, expect, test } from 'vitest';
import type { Finding } from '../../src/core/types.js';
import {
  findingFingerprint,
  findingIdentityTraits,
  routeFingerprint
} from '../../src/vault/fingerprint.js';
import { compareFindingSimilarity, findSimilarFindings } from '../../src/vault/similarity.js';
import {
  vaultEdgeTypeSchema,
  vaultEdgeSchema,
  vaultFindingEventSchema,
  vaultGraphSchema,
  vaultHistorySchema,
  vaultLifecycleSchema,
  vaultNodeTypeSchema,
  vaultPatchEventSchema,
  vaultPatchMemorySchema,
  vaultReplayEventSchema,
  vaultRunEventSchema,
  vaultRunSnapshotSchema
} from '../../src/vault/types.js';
import {
  makeAiToolFinding,
  makeFinding,
  makeProductionBolaFinding
} from '../helpers/vault-fixtures.js';

function isolatedFinding(name: string, overrides: Partial<Finding> = {}): Finding {
  return makeFinding({
    id: name,
    ruleId: `BP-CUSTOM-${name.toUpperCase()}`,
    affectedFiles: [`lib/${name}.txt`],
    affectedRoutes: [`GET /${name}`],
    attackPath: [`GET /${name}`, `${name}Sink`],
    evidence: `${name}marker`,
    ...overrides
  });
}

describe('Vault identities', () => {
  test('ignores workspace prefixes, generated IDs, line numbers, and prose variation', () => {
    const original = makeFinding();
    const moved = makeFinding({
      id: 'other-generated-id',
      title: 'Reworded title',
      evidence: 'The invoice query is not constrained to the authenticated tenantId.',
      exploitabilityReasoning: 'Different reasoning prose',
      recommendation: 'Different recommendation prose',
      affectedFiles: ['/tmp/another-workspace/app/api/invoices/[id]/route.ts:417']
    });

    expect(findingFingerprint(original)).toBe(findingFingerprint(moved));
  });

  test('uses the last repository route anchor after misleading workspace segments', () => {
    expect(findingFingerprint(makeFinding())).toBe(
      findingFingerprint(
        makeFinding({
          affectedFiles: ['/tmp/src/workspace/app/api/invoices/[id]/route.ts']
        })
      )
    );
  });

  test('extracts the production BOLA sink before a terminal missing-control description', () => {
    const invoice = makeProductionBolaFinding();
    const user = makeProductionBolaFinding({
      attackPath: [
        'user-controlled id',
        'GET /api/invoices/[id]',
        'User.findUnique',
        'missing tenant or owner predicate'
      ],
      evidence: 'User-controlled id reaches Prisma User.findUnique without a tenantId or ownerId predicate.'
    });

    expect(findingIdentityTraits(invoice).sink).toBe('invoice.findunique');
    expect(findingIdentityTraits(user).sink).toBe('user.findunique');
    expect(findingFingerprint(invoice)).not.toBe(findingFingerprint(user));
  });

  test('extracts a qualified production sink from evidence when the attack path omits it', () => {
    const finding = makeProductionBolaFinding({
      attackPath: [
        'user-controlled id',
        'GET /api/invoices/[id]',
        'Invoice',
        'missing tenant or owner predicate'
      ]
    });

    expect(findingIdentityTraits(finding).sink).toBe('invoice.findunique');
  });

  test('extracts a production AI tool sink before a generic impact description', () => {
    const deleteUser = makeAiToolFinding();
    const disableUser = makeAiToolFinding({
      attackPath: ['untrusted user input', 'disableUser', 'destructive or privileged action'],
      evidence: 'disableUser tool is reachable without an allowlist or policy guardrails.'
    });

    expect(findingIdentityTraits(deleteUser).sink).toBe('deleteuser');
    expect(findingIdentityTraits(disableUser).sink).toBe('disableuser');
    expect(findingFingerprint(deleteUser)).not.toBe(findingFingerprint(disableUser));
  });

  test('keeps fingerprints stable when affectedRoutes are permuted', () => {
    const original = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]', 'POST /api/orders/[id]'],
      attackPath: ['GET /api/invoices/[id]', 'Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });
    const permuted = makeFinding({
      affectedRoutes: ['POST /api/orders/[id]', 'GET /api/invoices/[id]'],
      attackPath: ['GET /api/invoices/[id]', 'Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });
    const materiallyDifferentRoute = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]', 'GET /api/payments/[id]'],
      attackPath: ['GET /api/invoices/[id]', 'Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });

    expect(findingFingerprint(original)).toBe(findingFingerprint(permuted));
    expect(findingFingerprint(original)).not.toBe(findingFingerprint(materiallyDifferentRoute));
  });

  test('keeps fingerprints stable when attackPath sink candidates are permuted', () => {
    const original = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['Invoice.findUnique', 'Order.findUnique'],
      evidence: 'Prisma Invoice.findUnique and Order.findUnique lack tenantId.'
    });
    const permuted = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['Order.findUnique', 'Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique and Order.findUnique lack tenantId.'
    });

    expect(findingFingerprint(original)).toBe(findingFingerprint(permuted));
  });

  test('ignores route-like noise in attackPath and evidence when affectedRoutes already define the route', () => {
    const baseline = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['GET /api/invoices/[id]', 'Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });
    const noisy = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: [
        'GET /api/invoices/[id]',
        'GET /api/payments/[id]',
        'Invoice.findUnique'
      ],
      evidence: 'Prisma Invoice.findUnique lacks tenantId and mentions GET /api/admin/users.'
    });

    expect(findingFingerprint(baseline)).toBe(findingFingerprint(noisy));
  });

  test('ignores extra sink-like noise in attackPath when the material sink is unchanged', () => {
    const baseline = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });
    const noisy = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['Invoice.findUnique', 'Order.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });

    expect(findingFingerprint(baseline)).toBe(findingFingerprint(noisy));
  });

  test('changes fingerprint when the material sink changes', () => {
    const invoice = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['Invoice.findUnique'],
      evidence: 'Prisma Invoice.findUnique lacks tenantId.'
    });
    const user = makeFinding({
      affectedRoutes: ['GET /api/invoices/[id]'],
      attackPath: ['User.findUnique'],
      evidence: 'Prisma User.findUnique lacks tenantId.'
    });

    expect(findingFingerprint(invoice)).not.toBe(findingFingerprint(user));
  });

  test('normalizes route parameters while retaining the HTTP method', () => {
    const numeric = routeFingerprint('get', '/api/invoices/123');

    expect(numeric).toBe(routeFingerprint('GET', '/api/invoices/[id]'));
    expect(numeric).toBe(routeFingerprint('GET', '/api/invoices/:id'));
    expect(numeric).not.toBe(routeFingerprint('POST', '/api/invoices/:id'));
  });

  test('changes identity when framework or file role changes', () => {
    const nextRoute = makeFinding();
    const expressRoute = makeFinding({ affectedFiles: ['src/routes/invoices.ts'] });
    const testRoute = makeFinding({ affectedFiles: ['src/routes/foo.test.ts'] });
    const sourceFile = makeFinding({ affectedFiles: ['lib/invoices.ts'] });

    expect(findingIdentityTraits(nextRoute)).toMatchObject({ framework: 'nextjs', fileRole: 'api_route' });
    expect(findingIdentityTraits(expressRoute)).toMatchObject({ framework: 'express', fileRole: 'route_handler' });
    expect(findingIdentityTraits(testRoute)).toMatchObject({ framework: 'express', fileRole: 'test' });
    expect(findingIdentityTraits(sourceFile)).toMatchObject({ framework: 'unknown', fileRole: 'source_file' });
    expect(findingFingerprint(testRoute)).not.toBe(findingFingerprint(expressRoute));
    expect(new Set([nextRoute, expressRoute, testRoute, sourceFile].map(findingFingerprint))).toHaveLength(4);
  });

  test('derives composite control families from all known rule and evidence tokens', () => {
    const composite = makeAiToolFinding();
    const tenantControl = isolatedFinding('control', {
      ruleId: 'BP-RULE-001',
      evidence: 'The query is missing a tenantId ownership predicate.'
    });
    const webhookControl = isolatedFinding('control', {
      ruleId: 'BP-RULE-001',
      evidence: 'The callback is missing webhook signature verification.'
    });

    expect(findingIdentityTraits(composite).controlTags).toEqual([
      'ai_guardrails',
      'tool_safety'
    ]);
    expect(findingFingerprint(tenantControl)).not.toBe(findingFingerprint(webhookControl));
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
    expect(result.score).toBe(0.725);
    expect(result.signals).toContain('same_rule');
    expect(result.signals).toEqual([...result.signals].sort());
  });

  test('reports the same-rule weight as 0.30', () => {
    const result = compareFindingSimilarity(
      isolatedFinding('alpha', { ruleId: 'BP-CUSTOM-001' }),
      isolatedFinding('beta', { ruleId: 'BP-CUSTOM-001' })
    );

    expect(result.components.same_rule).toBe(0.3);
    expect(result.score).toBe(0.3);
  });

  test('reports the same-control-family weight as 0.20 for composite rules', () => {
    const result = compareFindingSimilarity(
      isolatedFinding('alpha', { ruleId: 'BP-RULE-AI-TOOL-001' }),
      isolatedFinding('beta', { ruleId: 'BP-TOOL-999' })
    );

    expect(result.components.same_control_family).toBe(0.2);
    expect(result.score).toBe(0.2);
    expect(result.signals).toContain('same_control_family');
  });

  test('reports the same-sink weight as 0.20', () => {
    const result = compareFindingSimilarity(
      isolatedFinding('alpha', { attackPath: ['GET /alpha', 'SharedSink'] }),
      isolatedFinding('beta', { attackPath: ['GET /beta', 'SharedSink'] })
    );

    expect(result.components.same_sink).toBe(0.2);
    expect(result.score).toBe(0.2);
  });

  test('reports the maximum route-token Jaccard weight as 0.15', () => {
    const result = compareFindingSimilarity(
      isolatedFinding('alpha', {
        affectedRoutes: ['GET /shared/[id]'],
        attackPath: ['GET /shared/[id]', 'AlphaSink']
      }),
      isolatedFinding('beta', {
        affectedRoutes: ['POST /shared/:id'],
        attackPath: ['POST /shared/:id', 'BetaSink']
      })
    );

    expect(result.components.route_tokens).toBe(0.15);
    expect(result.score).toBe(0.15);
  });

  test('reports the same-framework-and-file-role weight as 0.10', () => {
    const result = compareFindingSimilarity(
      isolatedFinding('alpha', {
        affectedFiles: ['app/api/alpha/route.ts'],
        affectedRoutes: ['GET /alpha/one']
      }),
      isolatedFinding('beta', {
        affectedFiles: ['app/api/beta/route.ts'],
        affectedRoutes: ['GET /beta/two']
      })
    );

    expect(result.components.same_framework_file_role).toBe(0.1);
    expect(result.score).toBe(0.1);
  });

  test('reports the maximum evidence-tag overlap weight as 0.05', () => {
    const result = compareFindingSimilarity(
      isolatedFinding('alpha', { evidence: 'sharedmarker' }),
      isolatedFinding('beta', { evidence: 'sharedmarker' })
    );

    expect(result.components.evidence_tags).toBe(0.05);
    expect(result.score).toBe(0.05);
  });

  test('identifies exact fingerprints and excludes them from similar findings', () => {
    const current = makeFinding();
    const exact = makeFinding({ id: 'rerun-generated-id', title: 'Same finding, new prose' });

    expect(compareFindingSimilarity(current, exact).exactMatch).toBe(true);
    expect(findSimilarFindings(current, [exact])).toEqual([]);
  });

  test('includes a non-exact match at the exact default threshold of 0.75', () => {
    const current = isolatedFinding('alpha', {
      ruleId: 'BP-AI-001',
      attackPath: ['GET /alpha', 'SharedSink'],
      evidence: 'sharedmarker'
    });
    const previous = isolatedFinding('beta', {
      ruleId: 'BP-AI-001',
      attackPath: ['GET /beta', 'SharedSink'],
      evidence: 'sharedmarker'
    });

    const matches = findSimilarFindings(current, [previous]);

    expect(matches).toHaveLength(1);
    expect(matches[0]?.score).toBe(0.75);
  });

  test('sorts different scores descending', () => {
    const current = makeFinding();
    const high = makeFinding({
      id: 'orders',
      affectedRoutes: ['GET /api/orders/[id]'],
      affectedFiles: ['app/api/orders/[id]/route.ts'],
      attackPath: ['GET /api/orders/[id]', 'Invoice']
    });
    const low = makeFinding({
      id: 'profiles',
      affectedRoutes: ['GET /profiles/[id]'],
      affectedFiles: ['lib/profiles.ts'],
      attackPath: ['GET /profiles/[id]', 'Profile'],
      evidence: 'profilemarker'
    });

    const matches = findSimilarFindings(current, [low, high], 0.5);

    expect(matches).toHaveLength(2);
    expect(matches[0]?.score).toBeGreaterThan(matches[1]?.score ?? 0);
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

    const forward = findSimilarFindings(current, candidates, 0.7);
    const reverse = findSimilarFindings(current, [...candidates].reverse(), 0.7);

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

  test('requires score and signals for similar_to edges while preserving defaults for other edges', () => {
    const graph = vaultGraphSchema.parse({
      schemaVersion: 1,
      generatedAt: '2026-06-28T00:00:00.000Z',
      project: 'breachproof',
      currentRunId: 'run-1',
      nodes: [],
      edges: [
        {
          id: 'finding-run',
          from: 'finding:invoice',
          to: 'run:1',
          type: 'observed_in',
          label: 'observed in',
          evidence: 'Recorded in run 1'
        },
        {
          id: 'finding-similar',
          from: 'finding:invoice',
          to: 'finding:orders',
          type: 'similar_to',
          label: 'similar to',
          evidence: 'Shares the same route and sink signals',
          score: 0.83,
          signals: ['same_rule', 'same_sink']
        }
      ],
      timeline: [],
      summary: {
        nodes: 0,
        edges: 2,
        newIssues: 0,
        fixedIssues: 0,
        reopenedIssues: 0,
        repeatedIssues: 0
      }
    });

    expect(graph.edges[0]?.signals).toEqual([]);
    expect(graph.edges[0]?.score).toBeUndefined();
    expect(graph.edges[1]?.score).toBe(0.83);
    expect(graph.edges[1]?.signals).toEqual(['same_rule', 'same_sink']);
    expect(() =>
      vaultEdgeSchema.parse({
        id: 'missing-score',
        from: 'finding:invoice',
        to: 'finding:orders',
        type: 'similar_to',
        label: 'similar to',
        evidence: 'Incomplete similar edge',
        signals: ['same_rule']
      })
    ).toThrow();
    expect(() =>
      vaultEdgeSchema.parse({
        id: 'missing-signals',
        from: 'finding:invoice',
        to: 'finding:orders',
        type: 'similar_to',
        label: 'similar to',
        evidence: 'Incomplete similar edge',
        score: 0.5,
        signals: []
      })
    ).toThrow();
  });

  test('parses every stored event, snapshot, history, and patch-memory schema', () => {
    const run = {
      id: 'run-1',
      mode: 'local' as const,
      scopeHash: 'a'.repeat(64),
      startedAt: '2026-06-28T00:00:00.000Z',
      completedAt: '2026-06-28T00:01:00.000Z',
      reportPath: 'reports/vault/index.html'
    };
    const finding = makeFinding();
    const findingEvent = {
      id: 'finding-event-1',
      runId: run.id,
      fingerprint: findingFingerprint(finding),
      lifecycleInput: 'observed' as const,
      ruleId: finding.ruleId,
      finding,
      verificationStatus: 'not_run' as const,
      observedAt: run.completedAt
    };
    const patch = {
      id: 'patch-event-1',
      runId: run.id,
      findingFingerprint: findingEvent.fingerprint,
      patternId: 'tenant-scope-query',
      ruleId: finding.ruleId,
      framework: 'nextjs',
      fileRole: 'api_route',
      strategy: 'add-tenant-predicate',
      changePattern: 'where id plus tenantId',
      outcome: 'verified_fixed' as const,
      patchFile: 'reports/patches/invoice.diff',
      testFile: 'tests/invoice.test.ts',
      verificationEvidence: 'Cross-tenant request denied',
      observedAt: run.completedAt
    };
    const replay = {
      id: 'replay-event-1',
      runId: run.id,
      findingFingerprint: findingEvent.fingerprint,
      replayId: 'invoice-cross-tenant',
      status: 'passed' as const,
      evidence: 'Tenant B invoice was not returned to Tenant A',
      artifactPath: 'reports/evidence/invoice/replay.json',
      localOnly: true,
      observedAt: run.completedAt
    };
    const snapshot = {
      run,
      findings: [
        {
          finding,
          fingerprint: findingEvent.fingerprint,
          lifecycleInput: 'observed' as const
        }
      ],
      patches: [patch],
      replays: [replay]
    };
    const history = { runs: [run], findings: [findingEvent], patches: [patch], replays: [replay] };
    const memory = {
      patternId: patch.patternId,
      ruleId: patch.ruleId,
      framework: patch.framework,
      fileRole: patch.fileRole,
      strategy: patch.strategy,
      changePattern: patch.changePattern,
      regressionTestArtifact: patch.testFile,
      verificationRunId: run.id,
      verificationEvidence: patch.verificationEvidence,
      findingFingerprints: [findingEvent.fingerprint],
      reopenedCount: 0,
      outcome: 'verified_fixed' as const
    };

    expect(vaultRunEventSchema.parse(run)).toEqual(run);
    expect(vaultFindingEventSchema.parse(findingEvent)).toEqual(findingEvent);
    expect(vaultPatchEventSchema.parse(patch)).toEqual(patch);
    expect(vaultReplayEventSchema.parse(replay)).toEqual(replay);
    expect(vaultRunSnapshotSchema.parse(snapshot)).toEqual(snapshot);
    expect(vaultHistorySchema.parse(history)).toEqual(history);
    expect(vaultPatchMemorySchema.parse(memory)).toEqual(memory);
  });
});

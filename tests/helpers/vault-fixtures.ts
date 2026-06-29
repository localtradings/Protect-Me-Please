import type { Finding } from '../../src/core/types.js';
import type { VaultRunSnapshot } from '../../src/vault/types.js';

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'generated-id',
    ruleId: 'BP-BOLA-002',
    title: 'Tenant escape through invoice lookup',
    severity: 'high',
    status: 'validated',
    fixStatus: 'suggested',
    proofMode: 'static_trace',
    affectedFiles: ['app/api/invoices/[id]/route.ts'],
    affectedRoutes: ['GET /api/invoices/[id]'],
    attackPath: ['GET /api/invoices/[id]', 'Invoice'],
    evidence: 'Prisma Invoice lookup lacks tenantId',
    exploitabilityReasoning: 'A request-controlled invoice id reaches an Invoice lookup without tenant isolation.',
    recommendation: 'Scope the Invoice lookup to the authenticated principal tenantId.',
    patchStatus: 'suggested',
    verificationStatus: 'not_run',
    validation: {
      mode: 'local',
      destructive: false,
      productionTouched: false,
      summary: 'Static trace with local invoice and tenant fixtures.'
    },
    ...overrides
  };
}

const snapshotTimestamps: Record<string, { startedAt: string; completedAt: string }> = {
  'day-1': {
    startedAt: '2026-06-01T09:59:00.000Z',
    completedAt: '2026-06-01T10:00:00.000Z'
  },
  'day-2-repeat': {
    startedAt: '2026-06-02T09:59:00.000Z',
    completedAt: '2026-06-02T10:00:00.000Z'
  },
  'day-2-fixed': {
    startedAt: '2026-06-02T10:59:00.000Z',
    completedAt: '2026-06-02T11:00:00.000Z'
  },
  'day-5': {
    startedAt: '2026-06-05T09:59:00.000Z',
    completedAt: '2026-06-05T10:00:00.000Z'
  },
  'day-6-empty': {
    startedAt: '2026-06-06T09:59:00.000Z',
    completedAt: '2026-06-06T10:00:00.000Z'
  }
};

function timestampsFor(runId: string): { startedAt: string; completedAt: string } {
  return (
    snapshotTimestamps[runId] ?? {
      startedAt: '2026-06-30T09:59:00.000Z',
      completedAt: '2026-06-30T10:00:00.000Z'
    }
  );
}

export function makeSnapshot(
  runId: string,
  lifecycleInput: 'observed' | 'verified_fixed'
): VaultRunSnapshot {
  const timestamps = timestampsFor(runId);
  const finding =
    lifecycleInput === 'verified_fixed'
      ? makeFinding({
          status: 'fixed',
          fixStatus: 'verified_fixed',
          patchStatus: 'verified_fixed',
          verificationStatus: 'passed'
        })
      : makeFinding();
  const patchOutcome = lifecycleInput === 'verified_fixed' ? 'verified_fixed' : 'suggested';

  return {
    run: {
      id: runId,
      mode: 'local',
      scopeHash: 'a'.repeat(64),
      startedAt: timestamps.startedAt,
      completedAt: timestamps.completedAt,
      reportPath: 'reports/vault/index.html'
    },
    findings: [
      {
        finding,
        fingerprint: 'invoice-fingerprint',
        lifecycleInput
      }
    ],
    patches: [
      {
        id: `patch-${runId}`,
        runId,
        findingFingerprint: 'invoice-fingerprint',
        patternId: 'tenant-scope-query',
        ruleId: finding.ruleId,
        framework: 'nextjs',
        fileRole: 'api_route',
        strategy: lifecycleInput === 'verified_fixed' ? 'verified-fix' : 'investigate',
        changePattern: lifecycleInput === 'verified_fixed' ? 'add tenant predicate' : 'document missing tenant predicate',
        outcome: patchOutcome,
        verificationEvidence:
          lifecycleInput === 'verified_fixed'
            ? 'Cross-tenant request denied after fix'
            : 'Static trace still lacks tenant predicate',
        observedAt: timestamps.completedAt
      }
    ],
    replays: [
      {
        id: `replay-${runId}`,
        runId,
        findingFingerprint: 'invoice-fingerprint',
        replayId: `replay-${runId}`,
        status: lifecycleInput === 'verified_fixed' ? 'passed' : 'not_run',
        evidence:
          lifecycleInput === 'verified_fixed'
            ? 'Replay denied cross-tenant access'
            : 'Replay not run',
        localOnly: true,
        observedAt: timestamps.completedAt
      }
    ]
  };
}

export function makeProductionBolaFinding(overrides: Partial<Finding> = {}): Finding {
  return makeFinding({
    ruleId: 'BP-BOLA-001',
    title: 'Broken object-level authorization path is reachable',
    affectedRoutes: ['/api/invoices/[id]'],
    attackPath: [
      'user-controlled id',
      'GET /api/invoices/[id]',
      'Invoice.findUnique',
      'missing tenant or owner predicate'
    ],
    evidence: 'User-controlled id reaches Prisma Invoice.findUnique without a tenantId or ownerId predicate.',
    ...overrides
  });
}

export function makeAiToolFinding(overrides: Partial<Finding> = {}): Finding {
  return makeFinding({
    ruleId: 'BP-RULE-AI-TOOL-001',
    title: 'Dangerous AI tool call lacks guardrails',
    severity: 'critical',
    affectedFiles: ['src/agents/user-tools.ts'],
    affectedRoutes: ['POST /api/agents/execute'],
    attackPath: ['untrusted user input', 'deleteUser', 'destructive or privileged action'],
    evidence: 'deleteUser tool is reachable without an allowlist or policy guardrails.',
    ...overrides
  });
}

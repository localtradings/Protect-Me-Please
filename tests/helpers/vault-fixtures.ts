import type {
  Finding,
  PatchSummary,
  SystemMap,
  Verification
} from '../../src/core/types.js';
import type { PatchTournamentSummary } from '../../src/agents/patch-tournament.js';
import type { EvidenceArtifactSummary } from '../../src/proof/evidence.js';
import type { InvariantResultsArtifact } from '../../src/proof/invariants.js';
import type { BuildVaultGraphInput } from '../../src/vault/graph.js';
import { findingFingerprint } from '../../src/vault/fingerprint.js';
import type {
  VaultFindingEvent,
  VaultHistory,
  VaultRunSnapshot
} from '../../src/vault/types.js';

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
        patchFile:
          lifecycleInput === 'verified_fixed'
            ? 'reports/patches/invoice/verified.patch'
            : undefined,
        testFile:
          lifecycleInput === 'verified_fixed'
            ? 'reports/evidence/generated-id/regression.test.ts'
            : undefined,
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
        artifactPath:
          lifecycleInput === 'verified_fixed'
            ? 'reports/evidence/generated-id/actual-after.json'
            : undefined,
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

function findingEvent(
  snapshot: VaultRunSnapshot,
  id: string,
  index = 0
): VaultFindingEvent {
  const item = snapshot.findings[index];
  if (!item) throw new Error(`Missing finding ${index} in ${snapshot.run.id}`);
  return {
    id,
    runId: snapshot.run.id,
    fingerprint: item.fingerprint,
    lifecycleInput: item.lifecycleInput,
    ruleId: item.finding.ruleId,
    finding: item.finding,
    verificationStatus:
      item.lifecycleInput === 'verified_fixed'
        ? 'verified_fixed'
        : item.finding.verificationStatus,
    observedAt: snapshot.run.completedAt
  };
}

export function makePatchHistory(
  outcomes: Array<'suggested' | 'patch_created' | 'test_added' | 'verified_fixed' | 'needs_human_review'>
): VaultHistory {
  const day1 = makeSnapshot('day-1', 'observed');
  const day2 = makeSnapshot('day-2-fixed', 'verified_fixed');
  const day5 = makeSnapshot('day-5', 'observed');

  return {
    runs: [day1.run, day2.run, day5.run],
    findings: [
      findingEvent(day1, 'finding-day-1'),
      findingEvent(day2, 'finding-day-2-fixed'),
      findingEvent(day5, 'finding-day-5')
    ],
    patches: outcomes.map((outcome, index) => ({
      id: `patch-memory-${String(index + 1).padStart(2, '0')}`,
      runId: 'day-2-fixed',
      findingFingerprint: 'invoice-fingerprint',
      patternId: 'tenant-scope-query',
      ruleId: 'BP-BOLA-002',
      framework: 'nextjs',
      fileRole: 'api_route',
      strategy: 'add-tenant-predicate',
      changePattern: 'where id plus tenantId',
      outcome,
      patchFile: `reports/patches/invoice/${String(index + 1).padStart(2, '0')}.patch`,
      testFile:
        outcome === 'verified_fixed'
          ? 'reports/evidence/generated-id/regression.test.ts'
          : undefined,
      verificationEvidence:
        outcome === 'verified_fixed'
          ? 'Cross-tenant request denied after the tenant predicate was added.'
          : `${outcome} is not verification evidence.`,
      observedAt: `2026-06-02T11:${String(index).padStart(2, '0')}:00.000Z`
    })),
    replays: [day2.replays[0]!]
  };
}

export function makeGraphInput(): BuildVaultGraphInput {
  const workspace = '/Users/example/Protect-Me-Please';
  const day1 = makeSnapshot('day-1', 'observed');
  const day2Repeat = makeSnapshot('day-2-repeat', 'observed');
  const day2Fixed = makeSnapshot('day-2-fixed', 'verified_fixed');
  const day5 = makeSnapshot('day-5', 'observed');
  const currentFinding = makeFinding({
    affectedFiles: [`${workspace}/app/api/invoices/[id]/route.ts`],
    attackPath: ['GET /api/invoices/[id]', 'Invoice.findUnique']
  });
  for (const snapshot of [day1, day2Repeat, day2Fixed, day5]) {
    snapshot.findings[0] = {
      finding: currentFinding,
      fingerprint: 'invoice-fingerprint',
      lifecycleInput: snapshot.findings[0]?.lifecycleInput ?? 'observed'
    };
  }
  day5.findings[0] = {
    finding: currentFinding,
    fingerprint: 'invoice-fingerprint',
    lifecycleInput: 'observed'
  };
  const similarFinding = makeFinding({
    id: 'prior-orders-finding',
    title: 'Tenant escape through order lookup',
    affectedFiles: ['app/api/invoices/orders/[id]/route.ts'],
    affectedRoutes: ['GET /api/invoices/orders/[id]'],
    attackPath: ['GET /api/invoices/orders/[id]', 'Invoice.findUnique']
  });
  const similarFingerprint = findingFingerprint(similarFinding);

  const systemMap: SystemMap = {
    product: 'BreachProof',
    projectName: 'protect-me-please',
    workspace,
    generatedAt: '2026-06-05T10:01:00.000Z',
    languages: ['typescript'],
    frameworks: ['nextjs'],
    packageManifests: ['package.json'],
    dependencies: { next: '15.0.0' },
    routes: [
      {
        id: 'next-invoice-route',
        path: '/api/invoices/[id]',
        method: 'GET',
        file: `${workspace}/app/api/invoices/[id]/route.ts`,
        framework: 'nextjs',
        authDetected: true,
        ownershipCheckDetected: false,
        bodyFields: [],
        dangerousBodyFields: [],
        prismaModels: ['Invoice'],
        webhookSignatureDetected: false,
        uploadValidationDetected: false,
        sourceSummary: 'Authenticated invoice route without a tenant predicate.'
      },
      {
        id: 'next-webhook-route', path: '/api/webhooks/provider', method: 'POST',
        file: `${workspace}/app/api/webhooks/provider/route.ts`, framework: 'nextjs',
        authDetected: false, ownershipCheckDetected: false, bodyFields: [], dangerousBodyFields: [], prismaModels: [],
        webhookSignatureDetected: true, uploadValidationDetected: false, sourceSummary: 'Signed webhook route.'
      },
      {
        id: 'next-upload-route', path: '/api/upload', method: 'POST',
        file: `${workspace}/app/api/upload/route.ts`, framework: 'nextjs',
        authDetected: true, ownershipCheckDetected: true, bodyFields: [], dangerousBodyFields: [], prismaModels: [],
        webhookSignatureDetected: false, uploadValidationDetected: true, sourceSummary: 'Validated upload route.'
      }
    ],
    dataModels: [{ name: 'Invoice', fields: ['id', 'tenantId'], file: `${workspace}/prisma/schema.prisma` }],
    authBoundaries: [{ routeId: 'next-invoice-route', mechanism: 'requireUser', file: `${workspace}/src/session.ts` }],
    aiToolCalls: [{ name: 'summarizeInvoice', file: `${workspace}/app/api/invoices/[id]/route.ts`, routePath: '/api/invoices/[id]', dangerous: false, guardrailsDetected: true }],
    docker: { files: [], services: [] },
    ci: { workflows: [], unsafeTriggers: [] },
    filesScanned: 1
  };

  const invariantResults: InvariantResultsArtifact = {
    generatedAt: '2026-06-05T10:02:00.000Z',
    invariantFile: 'breachproof.invariants.yml',
    invariants: [
      {
        id: 'tenant-isolation',
        description: 'Users can only access records owned by their own tenant.',
        status: 'failed',
        routes: ['GET /api/invoices/[id]'],
        evidence: ['GET /api/invoices/[id] has auth but no detected ownership predicate.'],
        connectedArtifacts: {
          systemMapRoutes: 1,
          reachabilityEdges: 1,
          attackGraphNodes: 2,
          validationPlanItems: 1,
          relatedFindings: [currentFinding.id]
        }
      }
    ],
    summary: { total: 1, passed: 0, failed: 1, manualReview: 0 }
  };

  const patchSummary: PatchSummary = {
    generatedAt: '2026-06-05T10:03:00.000Z',
    apply: false,
    items: [
      {
        findingId: currentFinding.id,
        status: 'verified_fixed',
        patchFile: 'reports/patches/invoice/verified.patch',
        testFile: 'reports/evidence/generated-id/regression.test.ts',
        summary: 'Added tenantId to the Invoice lookup.'
      }
    ]
  };

  const patchTournament: PatchTournamentSummary = {
    generatedAt: '2026-06-05T10:03:30.000Z',
    items: [
      {
        findingId: currentFinding.id,
        recommended: 'candidate-a',
        directory: 'reports/patches/generated-id',
        candidates: [
          {
            candidate: 'candidate-a',
            file: 'reports/patches/generated-id/candidate-a.patch',
            strategy: 'Add a tenant predicate to the Invoice query.',
            fixesOriginalValidation: true,
            smallestSafeDiff: true,
            addsRegressionTest: true,
            avoidsUnrelatedRewrite: true,
            score: 96
          }
        ]
      }
    ]
  };

  const verification: Verification = {
    generatedAt: '2026-06-05T10:04:00.000Z',
    items: [
      {
        findingId: currentFinding.id,
        status: 'verified_fixed',
        proofMode: 'http_replay_local_only',
        productionTouched: false,
        destructive: false,
        summary: 'Local replay denied the cross-tenant request.'
      }
    ]
  };

  const evidence: EvidenceArtifactSummary = {
    generatedAt: '2026-06-05T10:05:00.000Z',
    evidenceRoot: 'reports/evidence',
    items: [
      {
        findingId: currentFinding.id,
        directory: 'reports/evidence/generated-id',
        proofMode: 'http_replay_local_only',
        replayable: true,
        status: 'verified_fixed'
      }
    ]
  };

  const history: VaultHistory = {
    runs: [day1.run, day2Repeat.run, day2Fixed.run, day5.run],
    findings: [
      findingEvent(day1, 'finding-day-1'),
      {
        id: 'finding-similar-day-1',
        runId: day1.run.id,
        fingerprint: similarFingerprint,
        lifecycleInput: 'observed',
        ruleId: similarFinding.ruleId,
        finding: similarFinding,
        verificationStatus: 'not_run',
        observedAt: '2026-06-01T10:00:30.000Z'
      },
      findingEvent(day2Repeat, 'finding-day-2-repeat'),
      findingEvent(day2Fixed, 'finding-day-2-fixed'),
      findingEvent(day5, 'finding-day-5')
    ],
    patches: [
      {
        ...day2Fixed.patches[0]!,
        strategy: 'add-tenant-predicate',
        changePattern: 'where id plus tenantId'
      }
    ],
    replays: [day2Fixed.replays[0]!]
  };

  return {
    project: 'protect-me-please',
    currentRunId: 'day-5',
    systemMap,
    findings: [currentFinding],
    invariantResults,
    patchSummary,
    patchTournament,
    verification,
    evidence,
    history
  };
}

import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { initializeStateStore } from '../../src/core/state.js';
import {
  findingSchema,
  productName,
  systemMapSchema,
  verificationSchema,
  type Finding,
  type SystemMap
} from '../../src/core/types.js';
import type { EvidenceArtifactSummary } from '../../src/proof/evidence.js';
import type { InvariantResultsArtifact } from '../../src/proof/invariants.js';
import { findingFingerprint, findingIdentityTraits } from '../../src/vault/fingerprint.js';
import { buildVaultGraph } from '../../src/vault/graph.js';
import { buildPatchMemory, projectLifecycle } from '../../src/vault/history.js';
import { appendVaultSnapshot, readVaultHistory } from '../../src/vault/store.js';
import type {
  VaultGraph,
  VaultPatchMemory,
  VaultRunSnapshot,
  VaultTimelineEvent
} from '../../src/vault/types.js';

const demoFixtureSchema = z
  .object({
    runId: z.string().min(1),
    completedAt: z.string().datetime(),
    findings: z.array(findingSchema),
    verification: verificationSchema
  })
  .strict();

type DemoFixture = z.infer<typeof demoFixtureSchema>;

async function loadFixture(directory: string, file: string): Promise<DemoFixture> {
  const raw = JSON.parse(await readFile(path.join(directory, file), 'utf8')) as unknown;
  return demoFixtureSchema.parse(raw);
}

function startedAt(completedAt: string): string {
  return new Date(new Date(completedAt).getTime() - 60_000).toISOString();
}

function lifecycleInput(finding: Finding): 'observed' | 'verified_fixed' {
  return finding.status === 'fixed' ||
    finding.fixStatus === 'verified_fixed' ||
    finding.patchStatus === 'verified_fixed'
    ? 'verified_fixed'
    : 'observed';
}

function snapshotFor(fixture: DemoFixture): VaultRunSnapshot {
  const findings = fixture.findings.map((finding) => ({
    finding,
    fingerprint: findingFingerprint(finding),
    lifecycleInput: lifecycleInput(finding)
  }));
  const fixed = findings.filter((entry) => entry.lifecycleInput === 'verified_fixed');

  return {
    run: {
      id: fixture.runId,
      mode: 'local',
      scopeHash: 'd'.repeat(64),
      startedAt: startedAt(fixture.completedAt),
      completedAt: fixture.completedAt,
      reportPath: `reports/vault/${fixture.runId}.html`
    },
    findings,
    patches: fixed.map((entry) => {
      const traits = findingIdentityTraits(entry.finding);
      return {
        id: `patch-${fixture.runId}-${entry.fingerprint}`,
        runId: fixture.runId,
        findingFingerprint: entry.fingerprint,
        patternId: 'tenant-scope-query',
        ruleId: traits.ruleId,
        framework: traits.framework,
        fileRole: traits.fileRole,
        strategy: 'add-tenant-predicate',
        changePattern: 'where id plus tenantId',
        outcome: 'verified_fixed',
        patchFile: 'reports/patches/invoice-day-2/verified.patch',
        testFile: 'reports/evidence/invoice-day-2/regression.test.ts',
        verificationEvidence: 'Tenant predicate blocked the cross-tenant replay.',
        observedAt: fixture.completedAt
      };
    }),
    replays: fixed.map((entry) => ({
      id: `replay-${fixture.runId}-${entry.fingerprint}`,
      runId: fixture.runId,
      findingFingerprint: entry.fingerprint,
      replayId: `tenant-replay-${fixture.runId}`,
      status: 'passed',
      evidence: 'Local replay denied cross-tenant access after the fix.',
      artifactPath: 'reports/evidence/invoice-day-2/actual-after.json',
      localOnly: true,
      observedAt: fixture.completedAt
    }))
  };
}

function routeForFinding(finding: Finding): SystemMap['routes'][number] {
  const routeLabel = finding.affectedRoutes[0] ?? 'GET /unknown';
  const [method = 'GET', routePath = '/unknown'] = routeLabel.split(/\s+/, 2);
  const traits = findingIdentityTraits(finding);
  return {
    id: `route-${traits.route.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '')}`,
    path: routePath,
    method,
    file: finding.affectedFiles[0] ?? 'unknown',
    framework: traits.framework === 'nextjs' ? 'nextjs' : 'unknown',
    authDetected: true,
    ownershipCheckDetected: false,
    bodyFields: [],
    dangerousBodyFields: [],
    prismaModels: ['Invoice'],
    webhookSignatureDetected: false,
    uploadValidationDetected: false,
    sourceSummary: finding.evidence
  };
}

function systemMapFor(workspace: string, fixture: DemoFixture): SystemMap {
  const routesById = new Map(
    fixture.findings.map((finding) => {
      const route = routeForFinding(finding);
      return [route.id, route] as const;
    })
  );
  return systemMapSchema.parse({
    product: productName,
    projectName: 'breachproof-vault-history-demo',
    workspace,
    generatedAt: fixture.completedAt,
    languages: ['TypeScript'],
    frameworks: ['nextjs'],
    packageManifests: ['package.json'],
    dependencies: {},
    routes: [...routesById.values()],
    dataModels: [
      {
        name: 'Invoice',
        fields: ['id', 'tenantId'],
        file: 'prisma/schema.prisma'
      }
    ],
    authBoundaries: [...routesById.values()].map((route) => ({
      routeId: route.id,
      mechanism: 'session',
      file: route.file
    })),
    aiToolCalls: [],
    docker: { files: [], services: [] },
    ci: { workflows: [], unsafeTriggers: [] },
    filesScanned: fixture.findings.length
  });
}

function invariantsFor(fixture: DemoFixture): InvariantResultsArtifact {
  return {
    generatedAt: fixture.completedAt,
    invariantFile: 'breachproof.invariants.yml',
    invariants: [
      {
        id: 'tenant-isolation',
        description: 'Users can only access records owned by their own tenant.',
        status: 'failed',
        routes: fixture.findings.flatMap((finding) => finding.affectedRoutes),
        evidence: fixture.findings.map((finding) => finding.evidence),
        connectedArtifacts: {
          systemMapRoutes: fixture.findings.length,
          reachabilityEdges: fixture.findings.length,
          attackGraphNodes: fixture.findings.length * 2,
          validationPlanItems: fixture.findings.length,
          relatedFindings: fixture.findings.map((finding) => finding.id)
        }
      }
    ],
    summary: { total: 1, passed: 0, failed: 1, manualReview: 0 }
  };
}

function evidenceFor(fixture: DemoFixture): EvidenceArtifactSummary {
  return {
    generatedAt: fixture.completedAt,
    evidenceRoot: 'reports/evidence',
    items: fixture.findings.map((finding) => ({
      findingId: finding.id,
      directory: `reports/evidence/${finding.id}`,
      proofMode: finding.proofMode,
      replayable: finding.proofMode === 'http_replay_local_only',
      status:
        fixture.verification.items.find((item) => item.findingId === finding.id)
          ?.status ?? finding.verificationStatus
    }))
  };
}

export async function buildVaultHistoryDemo(directory: string): Promise<{
  timeline: VaultTimelineEvent[];
  graph: VaultGraph;
  patchMemory: VaultPatchMemory[];
}> {
  const fixtures = await Promise.all(
    ['day-1.json', 'day-2.json', 'day-5.json'].map((file) =>
      loadFixture(directory, file)
    )
  );
  const workspace = await mkdtemp(path.join(tmpdir(), 'breachproof-vault-demo-'));
  const db = initializeStateStore(workspace);
  try {
    for (const fixture of fixtures) appendVaultSnapshot(db, snapshotFor(fixture));
    const history = readVaultHistory(db);
    const current = fixtures.at(-1)!;
    const systemMap = systemMapFor(workspace, current);
    const invariantResults = invariantsFor(current);
    const patchMemory = buildPatchMemory(history);
    const graph = buildVaultGraph({
      project: systemMap.projectName,
      currentRunId: current.runId,
      systemMap,
      findings: current.findings,
      invariantResults,
      patchSummary: {
        generatedAt: current.completedAt,
        apply: false,
        items: []
      },
      patchTournament: { generatedAt: current.completedAt, items: [] },
      verification: current.verification,
      evidence: evidenceFor(current),
      history
    });
    return { timeline: projectLifecycle(history), graph, patchMemory };
  } finally {
    db.close();
    await rm(workspace, { recursive: true, force: true });
  }
}

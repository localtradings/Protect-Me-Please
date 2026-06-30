import { createHash } from 'node:crypto';
import { access, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import type { PatchTournamentSummary } from '../agents/patch-tournament.js';
import { initializeStateStore } from '../core/state.js';
import {
  patchSummarySchema,
  reportSchema,
  systemMapSchema,
  verificationSchema,
  type Finding,
  type PatchSummary,
  type ProtectMode,
  type SystemMap,
  type Verification
} from '../core/types.js';
import type { EvidenceArtifactSummary } from '../proof/evidence.js';
import type { InvariantResultsArtifact } from '../proof/invariants.js';
import { findingFingerprint, findingIdentityTraits } from './fingerprint.js';
import { buildVaultGraph } from './graph.js';
import { buildPatchMemory } from './history.js';
import { writeVaultNotes, type VaultNoteSummary } from './markdown.js';
import { safeSlug } from './redaction.js';
import { renderRouteProfile } from './route-profile.js';
import { appendVaultSnapshot, readVaultHistory } from './store.js';
import {
  vaultGraphSchema,
  vaultHistorySchema,
  vaultRunSnapshotSchema,
  type VaultGraph,
  type VaultHistory,
  type VaultRunSnapshot
} from './types.js';

const UI_ASSET_NAMES = ['vault-graph.js', 'vault.css'] as const;

export interface VaultRouteProfile {
  routeId: string;
  html: string;
}

export interface WriteVaultReportInput {
  workspace: string;
  reportsDir: string;
  graph: VaultGraph;
  routeProfiles: readonly VaultRouteProfile[];
  uiAssetsDir?: string;
}

export interface VaultReportOutput {
  indexFile: string;
  graphFile: string;
  timelineFile: string;
  routeProfileFiles: string[];
  assetFiles: string[];
}

export interface BuildVaultOutputsInput {
  workspace: string;
  reportsDir: string;
  mode: ProtectMode;
  scopeHash: string;
  systemMap: SystemMap;
  findings: Finding[];
  invariantResults: InvariantResultsArtifact;
  patchSummary: PatchSummary;
  patchTournament: PatchTournamentSummary;
  verification: Verification;
  evidence: EvidenceArtifactSummary;
  startedAt?: string;
  completedAt?: string;
}

export interface BuiltVaultOutput extends VaultReportOutput {
  graph: VaultGraph;
  history: VaultHistory;
  notes: VaultNoteSummary;
  paths: string[];
}

const invariantResultsSchema = z
  .object({
    generatedAt: z.string().datetime(),
    invariantFile: z.string(),
    invariants: z.array(
      z.object({
        id: z.string(),
        description: z.string(),
        status: z.enum(['passed', 'failed', 'manual_review']),
        routes: z.array(z.string()),
        evidence: z.array(z.string()),
        connectedArtifacts: z.object({
          systemMapRoutes: z.number().int().nonnegative(),
          reachabilityEdges: z.number().int().nonnegative(),
          attackGraphNodes: z.number().int().nonnegative(),
          validationPlanItems: z.number().int().nonnegative(),
          relatedFindings: z.array(z.string())
        })
      })
    ),
    summary: z.object({
      total: z.number().int().nonnegative(),
      passed: z.number().int().nonnegative(),
      failed: z.number().int().nonnegative(),
      manualReview: z.number().int().nonnegative()
    })
  })
  .strict();

const patchTournamentSummarySchema = z
  .object({
    generatedAt: z.string().datetime(),
    items: z.array(
      z
        .object({
          findingId: z.string(),
          recommended: z.string(),
          candidates: z.array(
            z
              .object({
                candidate: z.string(),
                file: z.string(),
                strategy: z.string(),
                fixesOriginalValidation: z.boolean(),
                smallestSafeDiff: z.boolean(),
                addsRegressionTest: z.boolean(),
                avoidsUnrelatedRewrite: z.boolean(),
                score: z.number()
              })
              .strict()
          ),
          directory: z.string()
        })
        .strict()
    )
  })
  .strict();

const evidenceArtifactSummarySchema = z
  .object({
    generatedAt: z.string().datetime(),
    evidenceRoot: z.string(),
    items: z.array(
      z
        .object({
          findingId: z.string(),
          directory: z.string(),
          proofMode: z.enum([
            'static_trace',
            'local_fixture',
            'temp_patch_verify',
            'http_replay_local_only',
            'manual_review'
          ]),
          replayable: z.boolean(),
          status: z.string()
        })
        .strict()
    )
  })
  .strict();

export function serializeEmbeddedJson(value: unknown): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new TypeError('Embedded value must be JSON-serializable.');
  }
  return serialized.replace(/[<>&\u2028\u2029]/g, (character) => {
    switch (character) {
      case '<':
        return '\\u003c';
      case '>':
        return '\\u003e';
      case '&':
        return '\\u0026';
      case '\u2028':
        return '\\u2028';
      case '\u2029':
        return '\\u2029';
      default:
        return character;
    }
  });
}

function stableJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableJsonValue);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, stableJsonValue(item)])
  );
}

function stableReadableJson(value: unknown): string {
  return `${JSON.stringify(stableJsonValue(value), null, 2)}\n`;
}

async function missingUiAssets(directory: string): Promise<string[]> {
  const results = await Promise.all(
    UI_ASSET_NAMES.map(async (assetName) => {
      try {
        await access(path.join(directory, assetName));
        return undefined;
      } catch {
        return assetName;
      }
    })
  );
  return results.filter((assetName): assetName is (typeof UI_ASSET_NAMES)[number] =>
    Boolean(assetName)
  );
}

async function resolveUiAssetsDirectory(override?: string): Promise<string> {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  const candidates = override
    ? [path.resolve(override)]
    : [
        path.resolve(moduleDirectory, '../vault-ui'),
        path.resolve(moduleDirectory, '../../dist/vault-ui')
      ];
  const checked: Array<{ directory: string; missing: string[] }> = [];

  for (const candidate of candidates) {
    const missing = await missingUiAssets(candidate);
    if (missing.length === 0) return candidate;
    checked.push({ directory: candidate, missing });
  }

  const details = checked
    .map(({ directory, missing }) => `${missing.join(', ')} in ${directory}`)
    .join('; ');
  throw new Error(
    `Vault UI bundle is incomplete: missing ${details}. Run "npm run build:vault-ui" before packaging the Vault report.`
  );
}

function renderIndex(graph: VaultGraph): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'self' data: blob:; script-src 'self'; style-src 'self'; style-src-elem 'self' 'unsafe-inline'; style-src-attr 'unsafe-inline'; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
  <title>BreachProof Vault</title>
  <link rel="stylesheet" href="./assets/vault.css">
</head>
<body>
  <main id="breachproof-vault"></main>
  <script type="application/json" id="breachproof-vault-data">${serializeEmbeddedJson(graph)}</script>
  <script src="./assets/vault-graph.js" defer></script>
</body>
</html>
`;
}

export async function writeVaultReport(
  input: WriteVaultReportInput
): Promise<VaultReportOutput> {
  const graph = vaultGraphSchema.parse(input.graph);
  const reportDirectory = path.join(path.resolve(input.workspace), input.reportsDir, 'vault');
  const assetsDirectory = path.join(reportDirectory, 'assets');
  const routeProfilesDirectory = path.join(reportDirectory, 'route-profiles');
  const indexFile = path.join(reportDirectory, 'index.html');
  const graphFile = path.join(reportDirectory, 'graph.json');
  const timelineFile = path.join(reportDirectory, 'timeline.json');
  const uiAssetsDirectory = await resolveUiAssetsDirectory(input.uiAssetsDir);

  await Promise.all([
    mkdir(assetsDirectory, { recursive: true }),
    mkdir(routeProfilesDirectory, { recursive: true })
  ]);

  const assetFiles = UI_ASSET_NAMES.map((assetName) =>
    path.join(assetsDirectory, assetName)
  );
  const usedProfileNames = new Set<string>();
  const profiles = input.routeProfiles
    .map((profile) => ({ profile, slug: safeSlug(profile.routeId) }))
    .sort(
      (left, right) =>
        left.slug.localeCompare(right.slug) ||
        left.profile.routeId.localeCompare(right.profile.routeId) ||
        left.profile.html.localeCompare(right.profile.html)
    );
  const writtenProfileFiles: string[] = [];

  for (const { profile, slug } of profiles) {
    let suffix = 1;
    let fileName = `${slug}.html`;
    while (usedProfileNames.has(fileName)) {
      suffix += 1;
      fileName = `${slug}-${suffix}.html`;
    }
    usedProfileNames.add(fileName);
    const profileFile = path.join(routeProfilesDirectory, fileName);
    await writeFile(profileFile, profile.html, 'utf8');
    writtenProfileFiles.push(profileFile);
  }
  const routeProfileFiles = writtenProfileFiles.sort((left, right) =>
    left.localeCompare(right)
  );

  await Promise.all([
    writeFile(indexFile, renderIndex(graph), 'utf8'),
    writeFile(graphFile, stableReadableJson(graph), 'utf8'),
    writeFile(timelineFile, stableReadableJson(graph.timeline), 'utf8'),
    ...UI_ASSET_NAMES.map((assetName) =>
      copyFile(
        path.join(uiAssetsDirectory, assetName),
        path.join(assetsDirectory, assetName)
      )
    )
  ]);

  return {
    indexFile,
    graphFile,
    timelineFile,
    routeProfileFiles,
    assetFiles
  };
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function lifecycleInput(
  finding: Finding,
  verification: Verification
): 'observed' | 'verified_fixed' {
  const verificationItem = verification.items.find(
    (item) => item.findingId === finding.id
  );
  return finding.status === 'fixed' ||
    finding.fixStatus === 'verified_fixed' ||
    finding.patchStatus === 'verified_fixed' ||
    verificationItem?.status === 'verified_fixed'
    ? 'verified_fixed'
    : 'observed';
}

function replayStatus(status: string): VaultRunSnapshot['replays'][number]['status'] {
  const normalized = status.trim().toLowerCase();
  if (
    normalized === 'passed' ||
    normalized === 'verified' ||
    normalized === 'verified_fixed' ||
    normalized === 'confirmed' ||
    normalized === 'confirmed_local'
  ) {
    return 'passed';
  }
  if (normalized === 'failed') return 'failed';
  if (normalized.includes('human') || normalized.includes('manual')) {
    return 'manual_review';
  }
  return 'not_run';
}

function snapshotFor(input: BuildVaultOutputsInput): VaultRunSnapshot {
  const completedAt =
    input.completedAt ??
    [
      input.systemMap.generatedAt,
      input.invariantResults.generatedAt,
      input.patchSummary.generatedAt,
      input.patchTournament.generatedAt,
      input.verification.generatedAt,
      input.evidence.generatedAt
    ].sort().at(-1)!;
  const startedAt = input.startedAt ?? input.systemMap.generatedAt;
  const runId = `vault-run-${sha256(
    `${input.systemMap.projectName}\u0000${completedAt}`
  ).slice(0, 24)}`;
  const findingsById = new Map(input.findings.map((finding) => [finding.id, finding]));
  const findingsByFingerprint = new Map<
    string,
    VaultRunSnapshot['findings'][number]
  >();

  for (const finding of [...input.findings].sort((left, right) =>
    left.id.localeCompare(right.id)
  )) {
    const fingerprint = findingFingerprint(finding);
    const existing = findingsByFingerprint.get(fingerprint);
    const nextLifecycle = lifecycleInput(finding, input.verification);
    if (!existing || (existing.lifecycleInput === 'observed' && nextLifecycle === 'verified_fixed')) {
      findingsByFingerprint.set(fingerprint, {
        finding,
        fingerprint,
        lifecycleInput: nextLifecycle
      });
    }
  }

  const patches = input.patchSummary.items.flatMap((item) => {
    const finding = findingsById.get(item.findingId);
    if (!finding) return [];
    const fingerprint = findingFingerprint(finding);
    const traits = findingIdentityTraits(finding);
    const tournamentItem = input.patchTournament.items.find(
      (candidate) => candidate.findingId === item.findingId
    );
    const recommended = tournamentItem?.candidates.find(
      (candidate) => candidate.candidate === tournamentItem.recommended
    );
    const verificationItem = input.verification.items.find(
      (candidate) => candidate.findingId === item.findingId
    );
    const strategy = recommended?.strategy ?? item.summary;
    const patternId = `patch-pattern-${sha256(
      JSON.stringify([
        traits.ruleId,
        traits.framework,
        traits.fileRole,
        strategy
      ])
    ).slice(0, 24)}`;
    return [
      {
        id: `vault-patch-${sha256(
          `${runId}\u0000${fingerprint}\u0000${patternId}\u0000${item.findingId}`
        ).slice(0, 24)}`,
        runId,
        findingFingerprint: fingerprint,
        patternId,
        ruleId: traits.ruleId,
        framework: traits.framework,
        fileRole: traits.fileRole,
        strategy,
        changePattern: item.summary,
        outcome: item.status,
        patchFile: item.patchFile,
        testFile: item.testFile,
        verificationEvidence:
          verificationItem?.summary ?? 'Verification evidence is unavailable.',
        observedAt: completedAt
      }
    ];
  });

  const replays = input.evidence.items.flatMap((item) => {
    const finding = findingsById.get(item.findingId);
    if (!finding) return [];
    const fingerprint = findingFingerprint(finding);
    const status = replayStatus(item.status);
    const replayId = `replay-${safeSlug(item.findingId)}`;
    return [
      {
        id: `vault-replay-${sha256(
          `${runId}\u0000${fingerprint}\u0000${replayId}\u0000${item.directory}`
        ).slice(0, 24)}`,
        runId,
        findingFingerprint: fingerprint,
        replayId,
        status,
        evidence: `${item.proofMode}: ${item.status}`,
        artifactPath: item.replayable
          ? path.posix.join(item.directory.replace(/\\/g, '/'), 'actual-after.json')
          : undefined,
        localOnly: true,
        observedAt: completedAt
      }
    ];
  });

  return vaultRunSnapshotSchema.parse({
    run: {
      id: runId,
      mode: input.mode,
      scopeHash: input.scopeHash,
      startedAt,
      completedAt,
      reportPath: path.posix.join(input.reportsDir.replace(/\\/g, '/'), 'final-report.json')
    },
    findings: [...findingsByFingerprint.values()],
    patches,
    replays
  });
}

function notePaths(notes: VaultNoteSummary): string[] {
  return [
    ...notes.findings,
    ...notes.routes,
    ...notes.invariants,
    ...notes.patches,
    ...notes.replays,
    ...notes.runs,
    ...notes.daily,
    notes.summaryPath
  ];
}

async function projectVaultOutputs(
  input: BuildVaultOutputsInput,
  snapshot: VaultRunSnapshot,
  history: VaultHistory
): Promise<BuiltVaultOutput> {
  const patchMemory = buildPatchMemory(history);
  const graph = buildVaultGraph({
    project: input.systemMap.projectName,
    currentRunId: snapshot.run.id,
    systemMap: input.systemMap,
    findings: input.findings,
    invariantResults: input.invariantResults,
    patchSummary: input.patchSummary,
    patchTournament: input.patchTournament,
    verification: input.verification,
    evidence: input.evidence,
    history
  });
  const noteInput = {
    workspace: input.workspace,
    graph,
    history,
    systemMap: input.systemMap,
    invariantResults: input.invariantResults,
    patchMemory
  };
  const notes = await writeVaultNotes(noteInput);
  const routeProfiles = [...input.systemMap.routes]
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((route) => ({ routeId: route.id, html: renderRouteProfile({ ...noteInput, route }) }));
  const report = await writeVaultReport({
    workspace: input.workspace,
    reportsDir: input.reportsDir,
    graph,
    routeProfiles
  });

  return {
    ...report,
    graph,
    history,
    notes,
    paths: [
      ...notePaths(notes),
      report.indexFile,
      report.graphFile,
      report.timelineFile,
      ...report.routeProfileFiles,
      ...report.assetFiles
    ]
  };
}

export async function recordAndBuildVault(
  rawInput: BuildVaultOutputsInput
): Promise<BuiltVaultOutput> {
  const input = {
    ...rawInput,
    workspace: path.resolve(rawInput.workspace),
    systemMap: systemMapSchema.parse(rawInput.systemMap),
    invariantResults: invariantResultsSchema.parse(rawInput.invariantResults),
    patchSummary: patchSummarySchema.parse(rawInput.patchSummary),
    patchTournament: patchTournamentSummarySchema.parse(rawInput.patchTournament),
    verification: verificationSchema.parse(rawInput.verification),
    evidence: evidenceArtifactSummarySchema.parse(rawInput.evidence)
  };
  const snapshot = snapshotFor(input);
  const db = initializeStateStore(input.workspace);
  try {
    appendVaultSnapshot(db, snapshot);
    const history = readVaultHistory(db);
    return await projectVaultOutputs(input, snapshot, history);
  } finally {
    db.close();
  }
}

async function readRequiredJson(file: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(file, 'utf8')) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new Error(
        `Required Vault input is missing: ${file}. Run breachproof run --auto first.`,
        { cause: error }
      );
    }
    throw error;
  }
}

function historyWithDetachedSnapshot(
  history: VaultHistory,
  snapshot: VaultRunSnapshot
): VaultHistory {
  if (history.runs.some((run) => run.id === snapshot.run.id)) return history;
  return vaultHistorySchema.parse({
    runs: [...history.runs, snapshot.run],
    findings: [
      ...history.findings,
      ...snapshot.findings.map((entry) => ({
        id: `vault_finding_event_${sha256(
          `${snapshot.run.id}\u0000${entry.fingerprint}\u0000${entry.lifecycleInput}`
        )}`,
        runId: snapshot.run.id,
        fingerprint: entry.fingerprint,
        lifecycleInput: entry.lifecycleInput,
        ruleId: entry.finding.ruleId,
        finding: entry.finding,
        verificationStatus:
          entry.lifecycleInput === 'verified_fixed'
            ? 'verified_fixed'
            : entry.finding.verificationStatus,
        observedAt: snapshot.run.completedAt
      }))
    ],
    patches: [...history.patches, ...snapshot.patches],
    replays: [...history.replays, ...snapshot.replays]
  });
}

export async function rebuildVaultFromReports(
  workspace: string,
  reportsDir: string
): Promise<BuiltVaultOutput> {
  const root = path.resolve(workspace);
  const reportRoot = path.join(root, reportsDir);
  const [
    rawSystemMap,
    rawReport,
    rawInvariantResults,
    rawPatchSummary,
    rawPatchTournament,
    rawVerification,
    rawEvidence
  ] = await Promise.all(
    [
      'system-map.json',
      'final-report.json',
      'invariant-results.json',
      'patch-summary.json',
      'patch-tournament.json',
      'verification.json',
      'evidence-summary.json'
    ].map((file) => readRequiredJson(path.join(reportRoot, file)))
  );
  const systemMap = systemMapSchema.parse(rawSystemMap);
  const report = reportSchema.parse(rawReport);
  const input: BuildVaultOutputsInput = {
    workspace: root,
    reportsDir,
    mode: report.mode,
    scopeHash: sha256(`vault-rebuild\u0000${root}\u0000${report.mode}`),
    systemMap,
    findings: report.findings,
    invariantResults: invariantResultsSchema.parse(rawInvariantResults),
    patchSummary: patchSummarySchema.parse(rawPatchSummary),
    patchTournament: patchTournamentSummarySchema.parse(rawPatchTournament),
    verification: verificationSchema.parse(rawVerification),
    evidence: evidenceArtifactSummarySchema.parse(rawEvidence),
    startedAt: systemMap.generatedAt,
    completedAt: report.generatedAt
  };
  const snapshot = snapshotFor(input);
  const db = initializeStateStore(root);
  try {
    const history = historyWithDetachedSnapshot(readVaultHistory(db), snapshot);
    return await projectVaultOutputs(input, snapshot, history);
  } finally {
    db.close();
  }
}

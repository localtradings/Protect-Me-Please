import path from 'node:path';
import type { PatchTournamentSummary } from '../agents/patch-tournament.js';
import type {
  Finding,
  PatchSummary,
  SystemMap,
  Verification
} from '../core/types.js';
import type { EvidenceArtifactSummary } from '../proof/evidence.js';
import type { InvariantResultsArtifact } from '../proof/invariants.js';
import { findingFingerprint } from './fingerprint.js';
import { classifyObservedLifecycle, projectLifecycle } from './history.js';
import { findSimilarFindings } from './similarity.js';
import {
  vaultEdgeSchema,
  vaultGraphSchema,
  vaultNodeSchema,
  type VaultEdge,
  type VaultEdgeType,
  type VaultFindingEvent,
  type VaultGraph,
  type VaultHistory,
  type VaultNode,
  type VaultTimelineEvent
} from './types.js';

export interface BuildVaultGraphInput {
  project: string;
  currentRunId: string;
  systemMap: SystemMap;
  findings: Finding[];
  invariantResults: InvariantResultsArtifact;
  patchSummary: PatchSummary;
  patchTournament: PatchTournamentSummary;
  verification: Verification;
  evidence: EvidenceArtifactSummary;
  history: VaultHistory;
}

interface FindingOccurrence {
  nodeId: string;
  runId: string;
  fingerprint: string;
  finding: Finding;
  observedAt: string;
  eventId?: string;
}

function stableSlug(value: string): string {
  return (
    value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'item'
  );
}

function safeText(value: string, workspace: string): string {
  const normalizedWorkspace = workspace.replace(/\\/g, '/').replace(/\/$/, '');
  return value
    .replace(/\\/g, '/')
    .split(normalizedWorkspace)
    .join('<workspace>');
}

function safeRelativePath(value: string, workspace: string): string {
  const normalized = value.replace(/\\/g, '/');
  const normalizedWorkspace = workspace.replace(/\\/g, '/').replace(/\/$/, '');
  let relative = normalized;
  if (relative === normalizedWorkspace) relative = path.posix.basename(normalizedWorkspace);
  if (relative.startsWith(`${normalizedWorkspace}/`)) {
    relative = relative.slice(normalizedWorkspace.length + 1);
  } else if (path.posix.isAbsolute(relative) || /^[A-Za-z]:\//.test(relative)) {
    relative = path.posix.basename(relative);
  }
  const segments = relative
    .split('/')
    .filter((segment) => segment && segment !== '.' && segment !== '..');
  return segments.join('/') || 'artifact';
}

function sortedUnique(values: Array<string | undefined>, workspace: string): string[] {
  return [
    ...new Set(
      values
        .filter((value): value is string => Boolean(value))
        .map((value) => safeRelativePath(value, workspace))
    )
  ].sort();
}

function routeLabel(method: string, routePath: string): string {
  return `${method.toUpperCase()} ${routePath}`;
}

function routeReferences(finding: Finding): Set<string> {
  return new Set(
    [...finding.affectedRoutes, ...finding.attackPath].map((reference) =>
      reference.trim().replace(/\s+/g, ' ')
    )
  );
}

function routeMatchesFinding(
  route: SystemMap['routes'][number],
  finding: Finding
): boolean {
  const references = routeReferences(finding);
  return (
    references.has(route.id) ||
    references.has(route.path) ||
    references.has(routeLabel(route.method, route.path))
  );
}

function generatedAt(input: BuildVaultGraphInput): string {
  const timestamps = [
    input.systemMap.generatedAt,
    input.invariantResults.generatedAt,
    input.patchSummary.generatedAt,
    input.patchTournament.generatedAt,
    input.verification.generatedAt,
    input.evidence.generatedAt,
    ...input.history.runs.flatMap((run) => [run.startedAt, run.completedAt])
  ];
  return [...timestamps].sort().at(-1) ?? '1970-01-01T00:00:00.000Z';
}

function occurrenceForFinding(
  occurrences: FindingOccurrence[],
  findingId: string,
  currentRunId?: string
): FindingOccurrence | undefined {
  return [...occurrences]
    .filter(
      (occurrence) =>
        occurrence.finding.id === findingId &&
        (!currentRunId || occurrence.runId === currentRunId)
    )
    .sort(
      (left, right) =>
        right.observedAt.localeCompare(left.observedAt) ||
        right.nodeId.localeCompare(left.nodeId)
    )[0];
}

function latestOccurrence(
  occurrences: FindingOccurrence[],
  fingerprint: string,
  beforeOrAt?: string
): FindingOccurrence | undefined {
  return [...occurrences]
    .filter(
      (occurrence) =>
        occurrence.fingerprint === fingerprint &&
        (!beforeOrAt || occurrence.observedAt <= beforeOrAt)
    )
    .sort(
      (left, right) =>
        right.observedAt.localeCompare(left.observedAt) ||
        right.nodeId.localeCompare(left.nodeId)
    )[0];
}

function sortedMetadata(metadata: Record<string, string>, workspace: string): Record<string, string> {
  return Object.fromEntries(
    Object.entries(metadata)
      .map(([key, value]) => [key, safeText(value, workspace)] as const)
      .sort(([left], [right]) => left.localeCompare(right))
  );
}

function projectedLifecycleInput(finding: Finding): VaultFindingEvent['lifecycleInput'] {
  return finding.status === 'fixed' ||
    finding.fixStatus === 'verified_fixed' ||
    finding.patchStatus === 'verified_fixed'
    ? 'verified_fixed'
    : 'observed';
}

function projectedVerificationStatus(
  finding: Finding
): VaultFindingEvent['verificationStatus'] {
  return projectedLifecycleInput(finding) === 'verified_fixed'
    ? 'verified_fixed'
    : finding.verificationStatus;
}

function findingProjectionOrder(left: Finding, right: Finding): number {
  return (
    left.id.localeCompare(right.id) ||
    left.title.localeCompare(right.title) ||
    left.ruleId.localeCompare(right.ruleId) ||
    left.evidence.localeCompare(right.evidence)
  );
}

function overlayDetachedCurrentFindings(input: BuildVaultGraphInput): VaultHistory {
  const currentRun = input.history.runs.find((run) => run.id === input.currentRunId);
  const observedAt = currentRun?.completedAt ?? generatedAt(input);
  const currentEvents = input.history.findings.filter(
    (event) => event.runId === input.currentRunId
  );
  const currentFingerprints = new Set(currentEvents.map((event) => event.fingerprint));
  const currentFindingIds = new Set(currentEvents.map((event) => event.finding.id));
  const detachedByFingerprint = new Map<string, Finding>();
  for (const finding of [...input.findings].sort(findingProjectionOrder)) {
    const fingerprint = findingFingerprint(finding);
    if (
      currentFingerprints.has(fingerprint) ||
      currentFindingIds.has(finding.id) ||
      detachedByFingerprint.has(fingerprint)
    ) {
      continue;
    }
    detachedByFingerprint.set(fingerprint, finding);
  }
  if (detachedByFingerprint.size === 0) return input.history;

  const projectedFindings = [...input.history.findings];
  for (const [fingerprint, finding] of detachedByFingerprint) {
    projectedFindings.push({
      id: `${input.currentRunId}:${fingerprint}`,
      runId: input.currentRunId,
      fingerprint,
      lifecycleInput: projectedLifecycleInput(finding),
      ruleId: finding.ruleId,
      finding,
      verificationStatus: projectedVerificationStatus(finding),
      observedAt
    });
  }
  return {
    ...input.history,
    findings: projectedFindings
  };
}

export function buildVaultGraph(input: BuildVaultGraphInput): VaultGraph {
  const workspace = input.systemMap.workspace;
  const lifecycleHistory = overlayDetachedCurrentFindings(input);
  const nodesById = new Map<string, VaultNode>();
  const edgesById = new Map<string, VaultEdge>();

  const addNode = (candidate: Omit<VaultNode, 'metadata'> & { metadata?: Record<string, string> }): VaultNode => {
    const node = vaultNodeSchema.parse({
      ...candidate,
      label: safeText(candidate.label, workspace),
      route: candidate.route ? safeText(candidate.route, workspace) : undefined,
      notePath: candidate.notePath
        ? safeRelativePath(candidate.notePath, workspace)
        : undefined,
      profilePath: candidate.profilePath
        ? safeRelativePath(candidate.profilePath, workspace)
        : undefined,
      metadata: sortedMetadata(candidate.metadata ?? {}, workspace)
    });
    const existing = nodesById.get(node.id);
    if (existing && JSON.stringify(existing) !== JSON.stringify(node)) {
      throw new Error(`Duplicate node ID with conflicting data: ${node.id}`);
    }
    if (!existing) nodesById.set(node.id, node);
    return existing ?? node;
  };

  const addEdge = (candidate: {
    from: string;
    to: string;
    type: VaultEdgeType;
    label: string;
    evidence: string;
    artifactPaths?: Array<string | undefined>;
    score?: number;
    signals?: string[];
  }): void => {
    const id = `edge:${candidate.type}:${candidate.from}:${candidate.to}`;
    const artifactPaths = sortedUnique(candidate.artifactPaths ?? [], workspace);
    // Task 4 requires every emitted edge to carry real source artifacts.
    if (artifactPaths.length === 0) return;
    const evidence = safeText(candidate.evidence, workspace).trim();
    const edge = vaultEdgeSchema.parse({
      id,
      from: candidate.from,
      to: candidate.to,
      type: candidate.type,
      label: candidate.label,
      evidence,
      artifactPaths,
      score: candidate.score,
      signals: [...new Set(candidate.signals ?? [])].sort()
    });
    const existing = edgesById.get(id);
    if (!existing) {
      edgesById.set(id, edge);
      return;
    }
    if (existing.type === 'similar_to' && edge.type === 'similar_to' && existing.score !== edge.score) {
      throw new Error(`Duplicate edge ID with conflicting score: ${id}`);
    }
    const merged = vaultEdgeSchema.parse({
      ...existing,
      evidence: [...new Set([existing.evidence, edge.evidence])].sort().join(' | '),
      artifactPaths: [...new Set([...existing.artifactPaths, ...edge.artifactPaths])].sort(),
      signals: [...new Set([...existing.signals, ...edge.signals])].sort()
    });
    edgesById.set(id, merged);
  };

  const addAsset = (artifactPath: string, status: string): VaultNode => {
    const relativePath = safeRelativePath(artifactPath, workspace);
    return addNode({
      id: `asset:${relativePath}`,
      type: 'asset',
      label: path.posix.basename(relativePath),
      status,
      metadata: { path: relativePath }
    });
  };

  const timeline = projectLifecycle(lifecycleHistory).map((event) => ({
    ...event,
    title: safeText(event.title, workspace),
    evidence: event.evidence ? safeText(event.evidence, workspace) : undefined,
    artifactPaths: sortedUnique(event.artifactPaths, workspace)
  })) as VaultTimelineEvent[];
  const timelineBySourceEvent = new Map(
    timeline
      .filter((event) => event.id.startsWith('timeline:') && !event.id.includes(':not_observed'))
      .map((event) => [event.id.slice('timeline:'.length), event] as const)
  );

  for (const run of [...input.history.runs].sort((left, right) => left.id.localeCompare(right.id))) {
    const runNode = addNode({
      id: `run:${run.id}`,
      type: 'run',
      label: run.id,
      status: run.id === input.currentRunId ? 'current' : 'historical',
      runId: run.id,
      notePath: `.breachproof/vault/runs/${stableSlug(run.id)}.md`,
      metadata: { mode: run.mode, scopeHash: run.scopeHash }
    });
    const report = addAsset(run.reportPath, 'run_report');
    addEdge({
      from: runNode.id,
      to: report.id,
      type: 'proved_by',
      label: 'reported by',
      evidence: `Run ${run.id} produced its local Vault report.`,
      artifactPaths: [run.reportPath]
    });
  }
  if (!nodesById.has(`run:${input.currentRunId}`)) {
    addNode({
      id: `run:${input.currentRunId}`,
      type: 'run',
      label: input.currentRunId,
      status: 'current',
      runId: input.currentRunId,
      notePath: `.breachproof/vault/runs/${stableSlug(input.currentRunId)}.md`
    });
  }

  const routeNodes = new Map<string, VaultNode>();
  for (const route of [...input.systemMap.routes].sort((left, right) => left.id.localeCompare(right.id))) {
    const routeNode = addNode({
      id: `route:${route.id}`,
      type: 'route',
      label: routeLabel(route.method, route.path),
      status: route.ownershipCheckDetected ? 'protected' : 'review',
      route: routeLabel(route.method, route.path),
      notePath: `.breachproof/vault/routes/${stableSlug(route.id)}.md`,
      profilePath: `reports/vault/route-profiles/${stableSlug(route.id)}.html`,
      metadata: {
        authDetected: String(route.authDetected),
        file: safeRelativePath(route.file, workspace),
        framework: route.framework,
        ownershipCheckDetected: String(route.ownershipCheckDetected)
      }
    });
    routeNodes.set(route.id, routeNode);
  }

  const occurrences: FindingOccurrence[] = [];
  const occurrenceByEventId = new Map<string, FindingOccurrence>();
  for (const event of [...lifecycleHistory.findings].sort(
    (left, right) =>
      left.observedAt.localeCompare(right.observedAt) || left.id.localeCompare(right.id)
  )) {
    const lifecycle = timelineBySourceEvent.get(event.id)?.lifecycle ?? event.lifecycleInput;
    const occurrence: FindingOccurrence = {
      nodeId: `finding:${event.id}`,
      runId: event.runId,
      fingerprint: event.fingerprint,
      finding: event.finding,
      observedAt: event.observedAt,
      eventId: event.id
    };
    addNode({
      id: occurrence.nodeId,
      type: 'finding',
      label: event.finding.title,
      status: lifecycle,
      severity: event.finding.severity,
      runId: event.runId,
      route: event.finding.affectedRoutes[0],
      notePath: `.breachproof/vault/findings/${stableSlug(event.fingerprint)}.md`,
      metadata: {
        fingerprint: event.fingerprint,
        proofMode: event.finding.proofMode,
        ruleId: event.ruleId
      }
    });
    occurrences.push(occurrence);
    occurrenceByEventId.set(event.id, occurrence);
  }

  for (const finding of input.findings) {
    const existing = occurrenceForFinding(occurrences, finding.id, input.currentRunId);
    if (existing) continue;
    const fingerprint = findingFingerprint(finding);
    const occurrence: FindingOccurrence = {
      nodeId: `finding:${input.currentRunId}:${fingerprint}`,
      runId: input.currentRunId,
      fingerprint,
      finding,
      observedAt: generatedAt(input)
    };
    addNode({
      id: occurrence.nodeId,
      type: 'finding',
      label: finding.title,
      status: classifyObservedLifecycle(lifecycleHistory, fingerprint),
      severity: finding.severity,
      runId: input.currentRunId,
      route: finding.affectedRoutes[0],
      notePath: `.breachproof/vault/findings/${stableSlug(fingerprint)}.md`,
      metadata: { fingerprint, proofMode: finding.proofMode, ruleId: finding.ruleId }
    });
    occurrences.push(occurrence);
  }

  for (const occurrence of occurrences) {
    addEdge({
      from: occurrence.nodeId,
      to: `run:${occurrence.runId}`,
      type: 'observed_in',
      label: 'observed in',
      evidence: `Finding ${occurrence.fingerprint} was recorded in run ${occurrence.runId}.`,
      artifactPaths: occurrence.finding.affectedFiles
    });
    for (const route of input.systemMap.routes.filter((candidate) =>
      routeMatchesFinding(candidate, occurrence.finding)
    )) {
      const routeNode = routeNodes.get(route.id);
      if (!routeNode) continue;
      addEdge({
        from: occurrence.nodeId,
        to: routeNode.id,
        type: 'affects',
        label: 'affects',
        evidence: occurrence.finding.evidence,
        artifactPaths: [route.file, ...occurrence.finding.affectedFiles]
      });
      addEdge({
        from: routeNode.id,
        to: occurrence.nodeId,
        type: 'reaches',
        label: 'reaches',
        evidence: occurrence.finding.attackPath.join(' -> '),
        artifactPaths: [route.file, ...occurrence.finding.affectedFiles]
      });
    }
  }

  const invariantAsset = addAsset(
    input.invariantResults.invariantFile,
    'invariant_definition'
  );
  for (const invariant of [...input.invariantResults.invariants].sort((left, right) =>
    left.id.localeCompare(right.id)
  )) {
    const invariantNode = addNode({
      id: `invariant:${invariant.id}`,
      type: 'invariant',
      label: invariant.description,
      status: invariant.status,
      runId: input.currentRunId,
      notePath: `.breachproof/vault/invariants/${stableSlug(invariant.id)}.md`,
      metadata: { invariantId: invariant.id }
    });
    addEdge({
      from: invariantNode.id,
      to: invariantAsset.id,
      type: 'proved_by',
      label: 'defined by',
      evidence: `Invariant ${invariant.id} was evaluated from the configured invariant file.`,
      artifactPaths: [input.invariantResults.invariantFile]
    });
    for (const route of input.systemMap.routes.filter((candidate) =>
      invariant.routes.includes(routeLabel(candidate.method, candidate.path))
    )) {
      const routeNode = routeNodes.get(route.id);
      if (!routeNode) continue;
      addEdge({
        from: invariantNode.id,
        to: routeNode.id,
        type: 'protects',
        label: 'protects',
        evidence: `${invariant.description} ${invariant.evidence.join(' ')}`,
        artifactPaths: [input.invariantResults.invariantFile, route.file]
      });
    }
    if (invariant.status === 'failed') {
      for (const occurrence of occurrences.filter((candidate) =>
        invariant.connectedArtifacts.relatedFindings.includes(candidate.finding.id)
      )) {
        addEdge({
          from: occurrence.nodeId,
          to: invariantNode.id,
          type: 'violates',
          label: 'violates',
          evidence: invariant.evidence.join(' '),
          artifactPaths: [input.invariantResults.invariantFile, ...occurrence.finding.affectedFiles]
        });
      }
    }
  }

  const replayNodesByRunFingerprint = new Map<string, VaultNode[]>();
  const rememberReplay = (runId: string, fingerprint: string, node: VaultNode): void => {
    const key = `${runId}\0${fingerprint}`;
    replayNodesByRunFingerprint.set(key, [
      ...(replayNodesByRunFingerprint.get(key) ?? []),
      node
    ]);
  };
  for (const replay of [...input.history.replays].sort((left, right) => left.id.localeCompare(right.id))) {
    const replayNode = addNode({
      id: `replay:${replay.id}`,
      type: 'replay',
      label: replay.replayId,
      status: replay.status,
      runId: replay.runId,
      notePath: `.breachproof/vault/replays/${stableSlug(replay.replayId)}.md`,
      metadata: { localOnly: String(replay.localOnly) }
    });
    rememberReplay(replay.runId, replay.findingFingerprint, replayNode);
    const occurrence = latestOccurrence(
      occurrences,
      replay.findingFingerprint,
      replay.observedAt
    );
    if (occurrence) {
      addEdge({
        from: occurrence.nodeId,
        to: replayNode.id,
        type: 'proved_by',
        label: 'proved by',
        evidence: replay.evidence,
        artifactPaths: [replay.artifactPath]
      });
    }
    if (replay.artifactPath) addAsset(replay.artifactPath, replay.status);
  }

  const evidenceReplayByFindingId = new Map<string, VaultNode>();
  for (const item of [...input.evidence.items].sort((left, right) =>
    left.findingId.localeCompare(right.findingId)
  )) {
    const occurrence =
      occurrenceForFinding(occurrences, item.findingId, input.currentRunId) ??
      occurrenceForFinding(occurrences, item.findingId);
    const fingerprint = occurrence?.fingerprint ?? stableSlug(item.findingId);
    const replayNode = addNode({
      id: `replay:evidence:${input.currentRunId}:${fingerprint}`,
      type: 'replay',
      label: `Evidence replay for ${item.findingId}`,
      status: item.status,
      runId: input.currentRunId,
      notePath: `.breachproof/vault/replays/${stableSlug(item.findingId)}.md`,
      metadata: { proofMode: item.proofMode, replayable: String(item.replayable) }
    });
    evidenceReplayByFindingId.set(item.findingId, replayNode);
    const asset = addAsset(item.directory, item.status);
    if (occurrence) {
      addEdge({
        from: occurrence.nodeId,
        to: replayNode.id,
        type: 'proved_by',
        label: 'proved by',
        evidence: `Replayable ${item.proofMode} evidence has status ${item.status}.`,
        artifactPaths: [item.directory]
      });
    }
    addEdge({
      from: replayNode.id,
      to: asset.id,
      type: 'proved_by',
      label: 'recorded in',
      evidence: `Replay evidence is stored in ${safeRelativePath(item.directory, workspace)}.`,
      artifactPaths: [item.directory]
    });
  }

  const testNodesByPath = new Map<string, VaultNode>();
  const addTest = (testFile: string, runId: string, status: string): VaultNode => {
    const relativePath = safeRelativePath(testFile, workspace);
    const existing = testNodesByPath.get(relativePath);
    if (existing) return existing;
    const node = addNode({
      id: `test:${relativePath}`,
      type: 'test',
      label: path.posix.basename(relativePath),
      status,
      runId,
      metadata: { path: relativePath }
    });
    testNodesByPath.set(relativePath, node);
    return node;
  };

  for (const patch of [...input.history.patches].sort((left, right) => left.id.localeCompare(right.id))) {
    const patchNode = addNode({
      id: `patch:${patch.id}`,
      type: 'patch',
      label: patch.changePattern,
      status: patch.outcome,
      runId: patch.runId,
      notePath: `.breachproof/vault/patches/${stableSlug(patch.patternId)}.md`,
      metadata: {
        fileRole: patch.fileRole,
        framework: patch.framework,
        patternId: patch.patternId,
        ruleId: patch.ruleId,
        strategy: patch.strategy
      }
    });
    if (patch.patchFile) addAsset(patch.patchFile, patch.outcome);
    const occurrence = latestOccurrence(
      occurrences,
      patch.findingFingerprint,
      patch.observedAt
    );
    if (patch.outcome === 'verified_fixed' && occurrence) {
      addEdge({
        from: occurrence.nodeId,
        to: patchNode.id,
        type: 'fixed_by',
        label: 'fixed by',
        evidence: patch.verificationEvidence,
        artifactPaths: [patch.patchFile, patch.testFile]
      });
      const replayNodes =
        replayNodesByRunFingerprint.get(`${patch.runId}\0${patch.findingFingerprint}`) ?? [];
      for (const replayNode of replayNodes.filter((node) => node.status === 'passed')) {
        addEdge({
          from: patchNode.id,
          to: replayNode.id,
          type: 'verified_by',
          label: 'verified by',
          evidence: patch.verificationEvidence,
          artifactPaths: [patch.testFile]
        });
      }
      if (patch.testFile) {
        const testNode = addTest(patch.testFile, patch.runId, 'passed');
        addEdge({
          from: patchNode.id,
          to: testNode.id,
          type: 'verified_by',
          label: 'verified by',
          evidence: patch.verificationEvidence,
          artifactPaths: [patch.testFile]
        });
      }
    }
  }

  for (const item of [...input.patchSummary.items].sort((left, right) =>
    left.findingId.localeCompare(right.findingId)
  )) {
    const occurrence =
      occurrenceForFinding(occurrences, item.findingId, input.currentRunId) ??
      occurrenceForFinding(occurrences, item.findingId);
    const fingerprint = occurrence?.fingerprint ?? stableSlug(item.findingId);
    const patchNode = addNode({
      id: `patch:summary:${input.currentRunId}:${fingerprint}:${item.status}`,
      type: 'patch',
      label: item.summary,
      status: item.status,
      runId: input.currentRunId,
      notePath: `.breachproof/vault/patches/${stableSlug(fingerprint)}.md`,
      metadata: { findingId: item.findingId, source: 'patch_summary' }
    });
    if (item.patchFile) addAsset(item.patchFile, item.status);
    const verification = input.verification.items.find(
      (candidate) => candidate.findingId === item.findingId
    );
    const verified = item.status === 'verified_fixed' && verification?.status === 'verified_fixed';
    if (verified && occurrence && verification) {
      addEdge({
        from: occurrence.nodeId,
        to: patchNode.id,
        type: 'fixed_by',
        label: 'fixed by',
        evidence: `${item.summary} ${verification.summary}`,
        artifactPaths: [item.patchFile, item.testFile]
      });
      const replayNode = evidenceReplayByFindingId.get(item.findingId);
      if (replayNode) {
        addEdge({
          from: patchNode.id,
          to: replayNode.id,
          type: 'verified_by',
          label: 'verified by',
          evidence: verification.summary,
          artifactPaths: [
            input.evidence.items.find((candidate) => candidate.findingId === item.findingId)
              ?.directory
          ]
        });
      }
      if (item.testFile) {
        const testNode = addTest(item.testFile, input.currentRunId, 'passed');
        addEdge({
          from: patchNode.id,
          to: testNode.id,
          type: 'verified_by',
          label: 'verified by',
          evidence: verification.summary,
          artifactPaths: [item.testFile]
        });
        for (const route of input.systemMap.routes.filter((candidate) =>
          routeMatchesFinding(candidate, occurrence.finding)
        )) {
          const routeNode = routeNodes.get(route.id);
          if (!routeNode) continue;
          addEdge({
            from: testNode.id,
            to: routeNode.id,
            type: 'protects',
            label: 'protects',
            evidence: `Regression test ${path.posix.basename(item.testFile)} verifies ${verification.summary}`,
            artifactPaths: [item.testFile, route.file]
          });
        }
      }
    }
  }

  for (const tournament of [...input.patchTournament.items].sort((left, right) =>
    left.findingId.localeCompare(right.findingId)
  )) {
    const directoryAsset = addAsset(
      tournament.directory,
      'tournament_candidates'
    );
    for (const candidate of [...tournament.candidates].sort((left, right) =>
      left.candidate.localeCompare(right.candidate)
    )) {
      const patchNode = addNode({
        id: `patch:tournament:${input.currentRunId}:${stableSlug(tournament.findingId)}:${stableSlug(candidate.candidate)}`,
        type: 'patch',
        label: candidate.strategy,
        status:
          candidate.candidate === tournament.recommended ? 'recommended' : 'candidate',
        runId: input.currentRunId,
        metadata: {
          candidate: candidate.candidate,
          findingId: tournament.findingId,
          score: String(candidate.score),
          source: 'patch_tournament'
        }
      });
      const candidateAsset = addAsset(candidate.file, 'candidate_patch');
      addEdge({
        from: patchNode.id,
        to: candidateAsset.id,
        type: 'proved_by',
        label: 'scored from',
        evidence: `Tournament candidate ${candidate.candidate} scored ${candidate.score}; recommendation is not verification.`,
        artifactPaths: [candidate.file, tournament.directory]
      });
      addEdge({
        from: candidateAsset.id,
        to: directoryAsset.id,
        type: 'observed_in',
        label: 'stored in',
        evidence: `Candidate ${candidate.candidate} is stored in the local tournament directory.`,
        artifactPaths: [candidate.file, tournament.directory]
      });
    }
  }

  const eventForTimeline = new Map<string, VaultHistory['findings'][number]>(
    lifecycleHistory.findings.map((event) => [`timeline:${event.id}`, event] as const)
  );
  const lastOccurrenceByFingerprint = new Map<string, FindingOccurrence>();
  const fixedOccurrenceByFingerprint = new Map<string, FindingOccurrence>();
  for (const event of timeline) {
    const source = eventForTimeline.get(event.id);
    const occurrence = source ? occurrenceByEventId.get(source.id) : undefined;
    if (!occurrence) continue;
    const previous = lastOccurrenceByFingerprint.get(event.findingFingerprint);
    if (event.lifecycle === 'repeated' && previous) {
      addEdge({
        from: occurrence.nodeId,
        to: previous.nodeId,
        type: 'repeated_from',
        label: 'repeated from',
        evidence: `Fingerprint ${event.findingFingerprint} was observed again without an intervening verified fix.`,
        artifactPaths: event.artifactPaths
      });
    }
    if (event.lifecycle === 'reopened') {
      const fixed = fixedOccurrenceByFingerprint.get(event.findingFingerprint);
      if (fixed) {
        addEdge({
          from: occurrence.nodeId,
          to: fixed.nodeId,
          type: 'reopened_from',
          label: 'reopened from',
          evidence: `Fingerprint ${event.findingFingerprint} reappeared after a verified fixed event.`,
          artifactPaths: event.artifactPaths
        });
      }
    }
    if (event.lifecycle === 'fixed') {
      fixedOccurrenceByFingerprint.set(event.findingFingerprint, occurrence);
    }
    lastOccurrenceByFingerprint.set(event.findingFingerprint, occurrence);
  }

  const priorEvents = input.history.findings.filter(
    (event) => event.runId !== input.currentRunId
  );
  for (const currentFinding of input.findings) {
    const currentOccurrence =
      occurrenceForFinding(occurrences, currentFinding.id, input.currentRunId) ??
      occurrenceForFinding(occurrences, currentFinding.id);
    if (!currentOccurrence) continue;
    for (const similarity of findSimilarFindings(
      currentFinding,
      priorEvents.map((event) => event.finding),
      0.75
    )) {
      const prior = [...priorEvents]
        .filter(
          (event) => findingFingerprint(event.finding) === similarity.previousFingerprint
        )
        .sort(
          (left, right) =>
            right.observedAt.localeCompare(left.observedAt) || right.id.localeCompare(left.id)
        )[0];
      const priorOccurrence = prior ? occurrenceByEventId.get(prior.id) : undefined;
      if (!priorOccurrence || priorOccurrence.nodeId === currentOccurrence.nodeId) continue;
      addEdge({
        from: currentOccurrence.nodeId,
        to: priorOccurrence.nodeId,
        type: 'similar_to',
        label: 'similar to',
        evidence: `Similarity score ${similarity.score} meets the 0.75 threshold using ${similarity.signals.join(', ')}.`,
        artifactPaths: [
          ...currentOccurrence.finding.affectedFiles,
          ...priorOccurrence.finding.affectedFiles
        ],
        score: similarity.score,
        signals: similarity.signals
      });
    }
  }

  const nodes = [...nodesById.values()].sort(
    (left, right) => left.type.localeCompare(right.type) || left.id.localeCompare(right.id)
  );
  const edges = [...edgesById.values()].sort(
    (left, right) =>
      left.type.localeCompare(right.type) ||
      left.from.localeCompare(right.from) ||
      left.to.localeCompare(right.to) ||
      left.id.localeCompare(right.id)
  );
  const sortedTimeline = [...timeline].sort(
    (left, right) =>
      left.timestamp.localeCompare(right.timestamp) || left.id.localeCompare(right.id)
  );
  if (new Set(nodes.map((node) => node.id)).size !== nodes.length) {
    throw new Error('Duplicate node IDs remain after graph projection.');
  }
  if (new Set(edges.map((edge) => edge.id)).size !== edges.length) {
    throw new Error('Duplicate edge IDs remain after graph projection.');
  }
  const nodeIds = new Set(nodes.map((node) => node.id));
  const dangling = edges.find((edge) => !nodeIds.has(edge.from) || !nodeIds.has(edge.to));
  if (dangling) {
    throw new Error(`Dangling edge ${dangling.id}: ${dangling.from} -> ${dangling.to}`);
  }

  return vaultGraphSchema.parse({
    schemaVersion: 1,
    generatedAt: generatedAt(input),
    project: safeText(input.project, workspace),
    currentRunId: input.currentRunId,
    nodes,
    edges,
    timeline: sortedTimeline,
    summary: {
      nodes: nodes.length,
      edges: edges.length,
      newIssues: sortedTimeline.filter((event) => event.lifecycle === 'new').length,
      fixedIssues: sortedTimeline.filter((event) => event.lifecycle === 'fixed').length,
      reopenedIssues: sortedTimeline.filter((event) => event.lifecycle === 'reopened').length,
      repeatedIssues: sortedTimeline.filter((event) => event.lifecycle === 'repeated').length
    }
  });
}

import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import YAML from 'yaml';
import type { SystemMap } from '../core/types.js';
import type { InvariantResultsArtifact } from '../proof/invariants.js';
import { redactVaultText, safeSlug } from './redaction.js';
import type {
  VaultEdge,
  VaultGraph,
  VaultHistory,
  VaultNode,
  VaultNodeType,
  VaultPatchMemory
} from './types.js';

const noteCategories = [
  'findings',
  'routes',
  'invariants',
  'patches',
  'replays',
  'runs',
  'daily'
] as const;

type NoteCategory = (typeof noteCategories)[number];
type GraphNoteCategory = Exclude<NoteCategory, 'daily'>;

const categoryByNodeType: Partial<Record<VaultNodeType, GraphNoteCategory>> = {
  finding: 'findings',
  route: 'routes',
  invariant: 'invariants',
  patch: 'patches',
  replay: 'replays',
  run: 'runs'
};

export interface WriteVaultNotesInput {
  workspace: string;
  graph: VaultGraph;
  history: VaultHistory;
  systemMap: SystemMap;
  invariantResults: InvariantResultsArtifact;
  patchMemory: VaultPatchMemory[];
}

export interface VaultNoteSummary {
  findings: string[];
  routes: string[];
  invariants: string[];
  patches: string[];
  replays: string[];
  runs: string[];
  daily: string[];
  summaryPath: string;
}

interface NodeGroup {
  slug: string;
  nodes: VaultNode[];
}

function compareText(left: string, right: string): number {
  return left.localeCompare(right);
}

function redacted(input: WriteVaultNotesInput, value: string): string {
  return redactVaultText(value, input.workspace);
}

function markdownText(input: WriteVaultNotesInput, value: string): string {
  return redacted(input, value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r?\n/g, ' ')
    .trim();
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort(compareText);
}

function frontMatter(
  input: WriteVaultNotesInput,
  values: Record<string, string | number | boolean | string[] | undefined>
): string {
  const entries = Object.entries(values)
    .filter((entry): entry is [string, string | number | boolean | string[]] =>
      entry[1] !== undefined
    )
    .map(([key, value]) => [
      key,
      typeof value === 'string'
        ? redacted(input, value)
        : Array.isArray(value)
          ? uniqueSorted(value.map((item) => redacted(input, item)))
          : value
    ] as const);
  return `---\n${YAML.stringify(Object.fromEntries(entries)).trimEnd()}\n---`;
}

function bullets(
  input: WriteVaultNotesInput,
  values: string[],
  emptyMessage: string
): string {
  const safeValues = uniqueSorted(values.map((value) => markdownText(input, value))).filter(Boolean);
  if (safeValues.length === 0) return emptyMessage;
  return safeValues.map((value) => `- ${value}`).join('\n');
}

function orderedBullets(
  input: WriteVaultNotesInput,
  values: string[],
  emptyMessage: string
): string {
  const safeValues = values.map((value) => markdownText(input, value)).filter(Boolean);
  if (safeValues.length === 0) return emptyMessage;
  return safeValues.map((value) => `- ${value}`).join('\n');
}

function markdownLinkLabel(input: WriteVaultNotesInput, value: string): string {
  return markdownText(input, value)
    .replace(/\\/g, '\\\\')
    .replace(/\[/g, '\\[')
    .replace(/\]/g, '\\]')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function nodeGroupKey(node: VaultNode): string {
  const notePath = node.notePath?.replace(/\\/g, '/');
  if (notePath) {
    const basename = notePath.split('/').at(-1) ?? node.id;
    return safeSlug(basename.replace(/\.md$/i, ''));
  }
  return safeSlug(node.id);
}

function groupsFor(input: WriteVaultNotesInput, type: VaultNodeType): NodeGroup[] {
  const groups = new Map<string, VaultNode[]>();
  for (const node of input.graph.nodes.filter((candidate) => candidate.type === type)) {
    const slug = nodeGroupKey(node);
    groups.set(slug, [...(groups.get(slug) ?? []), node]);
  }
  return [...groups.entries()]
    .sort(([leftSlug, leftNodes], [rightSlug, rightNodes]) => {
      if (type === 'finding') {
        const leftCurrent = leftNodes.some((node) => node.runId === input.graph.currentRunId);
        const rightCurrent = rightNodes.some((node) => node.runId === input.graph.currentRunId);
        if (leftCurrent !== rightCurrent) return leftCurrent ? -1 : 1;
      }
      return compareText(leftSlug, rightSlug);
    })
    .map(([slug, nodes]) => ({
      slug,
      nodes: [...nodes].sort((left, right) => compareText(left.id, right.id))
    }));
}

function nodeById(input: WriteVaultNotesInput): Map<string, VaultNode> {
  return new Map(input.graph.nodes.map((node) => [node.id, node]));
}

function edgesFor(input: WriteVaultNotesInput, nodeIds: Set<string>): VaultEdge[] {
  return input.graph.edges.filter(
    (edge) => nodeIds.has(edge.from) || nodeIds.has(edge.to)
  );
}

function connectedNodes(
  input: WriteVaultNotesInput,
  sourceNodes: VaultNode[],
  targetType: VaultNodeType,
  maximumDepth = 2
): VaultNode[] {
  const nodes = nodeById(input);
  const visited = new Set(sourceNodes.map((node) => node.id));
  let frontier = [...visited];
  const matches = new Map<string, VaultNode>();

  for (let depth = 0; depth < maximumDepth && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const edge of input.graph.edges) {
      const neighbor = frontier.includes(edge.from)
        ? edge.to
        : frontier.includes(edge.to)
          ? edge.from
          : undefined;
      if (!neighbor || visited.has(neighbor)) continue;
      visited.add(neighbor);
      next.push(neighbor);
      const node = nodes.get(neighbor);
      if (node?.type === targetType) matches.set(node.id, node);
    }
    frontier = next;
  }

  return [...matches.values()].sort((left, right) => compareText(left.id, right.id));
}

function wikiLink(input: WriteVaultNotesInput, node: VaultNode): string {
  const category = categoryByNodeType[node.type];
  if (!category || !node.notePath) {
    const artifactPath = node.metadata.path;
    if ((node.type === 'test' || node.type === 'asset') && artifactPath) {
      const relativeArtifact = redacted(input, artifactPath)
        .replace(/\\/g, '/')
        .split('/')
        .filter((segment) => segment && segment !== '.' && segment !== '..')
        .map((segment) => encodeURIComponent(segment))
        .join('/');
      if (relativeArtifact) {
        return `[${markdownLinkLabel(input, node.label)}](../../../${relativeArtifact})`;
      }
    }
    return markdownText(input, node.label);
  }
  const label = markdownText(input, node.label).replace(/\|/g, '\\|').replace(/\]\]/g, '] ]');
  return `[[../../${category}/${nodeGroupKey(node)}|${label}]]`;
}

function nodeLinks(
  input: WriteVaultNotesInput,
  nodes: VaultNode[],
  emptyMessage: string
): string {
  if (nodes.length === 0) return emptyMessage;
  return nodes
    .map((node) => `- ${wikiLink(input, node)} - ${markdownText(input, node.status)}`)
    .join('\n');
}

function findingFingerprints(nodes: VaultNode[]): string[] {
  return uniqueSorted(
    nodes.map((node) => node.metadata.fingerprint).filter((value): value is string => Boolean(value))
  );
}

function findingEvents(input: WriteVaultNotesInput, nodes: VaultNode[]) {
  const fingerprints = new Set(findingFingerprints(nodes));
  return input.history.findings
    .filter((event) => fingerprints.has(event.fingerprint))
    .sort(
      (left, right) =>
        compareText(left.observedAt, right.observedAt) || compareText(left.id, right.id)
    );
}

function latestFindingNode(
  input: WriteVaultNotesInput,
  group: NodeGroup,
  latestEvent: VaultHistory['findings'][number] | undefined
): VaultNode {
  if (latestEvent) {
    const exactNode = group.nodes.find((node) => node.id === `finding:${latestEvent.id}`);
    if (exactNode) return exactNode;
    const runNode = [...group.nodes]
      .filter(
        (node) =>
          node.runId === latestEvent.runId &&
          node.metadata.fingerprint === latestEvent.fingerprint
      )
      .sort((left, right) => compareText(left.id, right.id))
      .at(-1);
    if (runNode) return runNode;
  }

  const completedAtByRun = new Map(
    input.history.runs.map((run) => [run.id, run.completedAt] as const)
  );
  return [...group.nodes].sort((left, right) => {
    const leftTimestamp = left.runId ? (completedAtByRun.get(left.runId) ?? '') : '';
    const rightTimestamp = right.runId ? (completedAtByRun.get(right.runId) ?? '') : '';
    return compareText(leftTimestamp, rightTimestamp) || compareText(left.id, right.id);
  }).at(-1)!;
}

function renderFindingNote(input: WriteVaultNotesInput, group: NodeGroup): string {
  const events = findingEvents(input, group.nodes);
  const latestEvent = events.at(-1);
  const latestNode = latestFindingNode(input, group, latestEvent);
  const latestTimelineEvent = latestEvent
    ? input.graph.timeline
        .filter(
          (event) =>
            event.findingFingerprint === latestEvent.fingerprint &&
            event.runId === latestEvent.runId
        )
        .sort(
          (left, right) =>
            compareText(left.timestamp, right.timestamp) || compareText(left.id, right.id)
        )
        .at(-1)
    : undefined;
  const displayTitle = latestEvent?.finding.title ?? latestNode.label;
  const displayStatus = latestNode.status || latestTimelineEvent?.lifecycle || 'unknown';
  const displaySeverity = latestEvent?.finding.severity ?? latestNode.severity;
  const fingerprints = findingFingerprints(group.nodes);
  const fingerprintSet = new Set(fingerprints);
  const timeline = input.graph.timeline.filter((event) =>
    fingerprintSet.has(event.findingFingerprint)
  );
  const routes = connectedNodes(input, group.nodes, 'route', 1);
  const invariants = connectedNodes(input, group.nodes, 'invariant', 1);
  const replays = connectedNodes(input, group.nodes, 'replay', 2);
  const patches = connectedNodes(input, group.nodes, 'patch', 1);
  const tests = connectedNodes(input, group.nodes, 'test', 2);
  const runs = connectedNodes(input, group.nodes, 'run', 1);
  const groupIds = new Set(group.nodes.map((node) => node.id));
  const similar = edgesFor(input, groupIds)
    .filter((edge) => edge.type === 'similar_to')
    .map((edge) => nodeById(input).get(groupIds.has(edge.from) ? edge.to : edge.from))
    .filter((node): node is VaultNode => node?.type === 'finding');
  const evidence = uniqueSorted([
    ...events.map((event) => event.finding.evidence),
    ...edgesFor(input, groupIds).map((edge) => edge.evidence)
  ]);

  return `${frontMatter(input, {
    type: 'finding',
    id: fingerprints[0] ?? latestNode.id,
    title: displayTitle,
    status: displayStatus,
    severity: displaySeverity,
    generated_at: input.graph.generatedAt,
    runs: uniqueSorted(group.nodes.map((node) => node.runId).filter((value): value is string => Boolean(value)))
  })}

# ${markdownText(input, displayTitle)}

## Lifecycle

${orderedBullets(
  input,
  timeline.map(
    (event) => `${event.timestamp} - ${event.lifecycle} in ${event.runId}${event.evidence ? `: ${event.evidence}` : ''}`
  ),
  `Current status: ${markdownText(input, displayStatus)}. No lifecycle events recorded.`
)}

## Routes

${nodeLinks(input, routes, 'No related routes recorded.')}

## Evidence

${bullets(input, evidence, 'No evidence recorded.')}

## Attack Path

${orderedBullets(
  input,
  events.flatMap((event) => event.finding.attackPath).map((step, index) => `${index + 1}. ${step}`),
  'No attack path recorded.'
)}

## Invariants

${nodeLinks(input, invariants, 'No violated or related invariants recorded.')}

## Replays

${nodeLinks(input, replays, 'No replay evidence recorded.')}

## Patches

${nodeLinks(input, patches, 'No patch history recorded.')}

## Regression Tests

${nodeLinks(input, tests, 'No regression tests recorded.')}

## Similar Findings

${nodeLinks(input, similar, 'No similar findings recorded.')}

## Verification

${orderedBullets(
  input,
  events.flatMap((event) => [
    `${event.observedAt} - ${event.verificationStatus}`,
    event.finding.validation.summary
  ]),
  latestEvent
    ? `Latest verification: ${markdownText(input, latestEvent.verificationStatus)}.`
    : 'No verification history recorded.'
)}

## Runs

${nodeLinks(input, runs, 'No run links recorded.')}

## Data Handling

No request body values are stored. Only redacted control names and local artifact references are included.
`;
}

function routeForGroup(
  input: WriteVaultNotesInput,
  group: NodeGroup
): SystemMap['routes'][number] | undefined {
  const routeIds = new Set(group.nodes.map((node) => node.id.replace(/^route:/, '')));
  return input.systemMap.routes.find((route) => routeIds.has(route.id));
}

function renderRouteNote(input: WriteVaultNotesInput, group: NodeGroup): string {
  const node = group.nodes[0]!;
  const route = routeForGroup(input, group);
  const findings = connectedNodes(input, group.nodes, 'finding', 1);
  const invariants = connectedNodes(input, group.nodes, 'invariant', 1);
  const assets = connectedNodes(input, group.nodes, 'asset', 2);
  const tests = connectedNodes(input, group.nodes, 'test', 1);
  const relatedFingerprints = new Set(findingFingerprints(findings));
  const timeline = input.graph.timeline.filter((event) =>
    relatedFingerprints.has(event.findingFingerprint)
  );
  const authBoundaries = route
    ? input.systemMap.authBoundaries.filter((boundary) => boundary.routeId === route.id)
    : [];
  const aiTools = route
    ? input.systemMap.aiToolCalls.filter((tool) => tool.routePath === route.path)
    : [];

  return `${frontMatter(input, {
    type: 'route',
    id: route?.id ?? node.id,
    title: node.label,
    status: node.status,
    generated_at: input.graph.generatedAt,
    framework: route?.framework,
    method: route?.method,
    path: route?.path
  })}

# ${markdownText(input, node.label)}

## Route

- Method: ${markdownText(input, route?.method ?? 'Unavailable')}
- Path: ${markdownText(input, route?.path ?? 'Unavailable')}
- Framework: ${markdownText(input, route?.framework ?? 'Unavailable')}
- Source role: route handler
- Source file: ${markdownText(input, route?.file ?? node.metadata.file ?? 'Unavailable')}
- Summary: ${markdownText(input, route?.sourceSummary ?? 'No source summary available.')}

## Authentication Boundaries

- Authentication detected: ${route ? (route.authDetected ? 'yes' : 'no') : 'unavailable'}
${bullets(
  input,
  authBoundaries.map((boundary) => `${boundary.mechanism} in ${boundary.file}`),
  'No explicit authentication boundary records.'
)}

## Authorization And Tenant Controls

- Ownership check detected: ${route ? (route.ownershipCheckDetected ? 'yes' : 'no') : 'unavailable'}
- Tenant scoping status: ${route ? (route.ownershipCheckDetected ? 'detected' : 'not detected') : 'unavailable'}

## Request-Controlled Privileged Fields

${bullets(input, route?.dangerousBodyFields ?? [], 'No privileged request fields detected.')}

No request body values are stored.

## Data Access

${bullets(input, route?.prismaModels ?? [], 'No connected data models detected.')}

## Connected Models

${bullets(
  input,
  (route?.prismaModels ?? []).flatMap((modelName) => {
    const model = input.systemMap.dataModels.find((candidate) => candidate.name === modelName);
    return model
      ? [`${model.name}: ${model.fields.join(', ')} (${model.file})`]
      : [modelName];
  }),
  'No connected models.'
)}

## Jobs, Uploads, Webhooks, And AI Tools

- Jobs: No connected jobs represented by the current system map.
- Upload validation: ${route ? (route.uploadValidationDetected ? 'detected' : 'not detected') : 'unavailable'}
- Webhook signature verification: ${route ? (route.webhookSignatureDetected ? 'detected' : 'not detected') : 'unavailable'}
${bullets(
  input,
  aiTools.map(
    (tool) => `${tool.name}: dangerous=${String(tool.dangerous)}, guardrails=${String(tool.guardrailsDetected)}`
  ),
  'No connected AI tools.'
)}

## Findings

${nodeLinks(input, findings, 'No current or historical findings recorded.')}

## Invariants

${nodeLinks(input, invariants, 'No related invariants recorded.')}

## Assets

${nodeLinks(input, assets, 'No related assets recorded.')}

## Regression Tests

${nodeLinks(input, tests, 'No regression tests recorded.')}

## Timeline

${orderedBullets(
  input,
  timeline.map((event) => `${event.timestamp} - ${event.lifecycle}: ${event.title}`),
  'No route finding timeline recorded.'
)}
`;
}

function renderInvariantNote(input: WriteVaultNotesInput, group: NodeGroup): string {
  const node = group.nodes[0]!;
  const invariantId = node.metadata.invariantId ?? node.id.replace(/^invariant:/, '');
  const invariant = input.invariantResults.invariants.find((item) => item.id === invariantId);
  return `${frontMatter(input, {
    type: 'invariant',
    id: invariantId,
    title: invariant?.description ?? node.label,
    status: invariant?.status ?? node.status,
    generated_at: input.graph.generatedAt
  })}

# ${markdownText(input, invariantId)}

## Definition

${markdownText(input, invariant?.description ?? node.label)}

## Routes

${nodeLinks(input, connectedNodes(input, group.nodes, 'route', 1), 'No protected routes recorded.')}

## Evidence

${bullets(input, invariant?.evidence ?? [], 'No invariant evidence recorded.')}

## Related Findings

${nodeLinks(input, connectedNodes(input, group.nodes, 'finding', 1), 'No related findings recorded.')}

## Connected Artifact Counts

- System map routes: ${invariant?.connectedArtifacts.systemMapRoutes ?? 0}
- Reachability edges: ${invariant?.connectedArtifacts.reachabilityEdges ?? 0}
- Attack graph nodes: ${invariant?.connectedArtifacts.attackGraphNodes ?? 0}
- Validation plan items: ${invariant?.connectedArtifacts.validationPlanItems ?? 0}
`;
}

function renderPatchNote(input: WriteVaultNotesInput, group: NodeGroup): string {
  const node = group.nodes[0]!;
  const patternIds = uniqueSorted(
    group.nodes.map((item) => item.metadata.patternId).filter((value): value is string => Boolean(value))
  );
  const nodeIds = new Set(group.nodes.map((item) => item.id.replace(/^patch:/, '')));
  const events = input.history.patches.filter(
    (event) => nodeIds.has(event.id) || patternIds.includes(event.patternId)
  );
  const memory = input.patchMemory.filter((item) => patternIds.includes(item.patternId));
  return `${frontMatter(input, {
    type: 'patch',
    id: patternIds[0] ?? node.id,
    title: node.label,
    status: node.status,
    generated_at: input.graph.generatedAt
  })}

# ${markdownText(input, node.label)}

## Patch History

${orderedBullets(
  input,
  events.map(
    (event) => `${event.observedAt} - ${event.outcome}: ${event.strategy} (${event.changePattern})`
  ),
  'No structured patch events recorded.'
)}

## Successful Pattern Memory

${bullets(
  input,
  memory.map(
    (item) => `${item.outcome}: ${item.strategy}; test ${item.regressionTestArtifact}; reopened ${item.reopenedCount} time(s)`
  ),
  'No verified patch memory recorded.'
)}

## Verification

${orderedBullets(
  input,
  [...events.map((event) => event.verificationEvidence), ...memory.map((item) => item.verificationEvidence)],
  'No verification evidence recorded.'
)}

## Findings

${nodeLinks(input, connectedNodes(input, group.nodes, 'finding', 1), 'No linked findings recorded.')}

## Replays

${nodeLinks(input, connectedNodes(input, group.nodes, 'replay', 1), 'No linked replays recorded.')}

## Regression Tests

${nodeLinks(input, connectedNodes(input, group.nodes, 'test', 1), 'No linked regression tests recorded.')}
`;
}

function renderReplayNote(input: WriteVaultNotesInput, group: NodeGroup): string {
  const node = group.nodes[0]!;
  const replayIds = new Set([
    ...group.nodes.map((item) => item.id.replace(/^replay:/, '')),
    ...group.nodes.map((item) => item.label)
  ]);
  const events = input.history.replays.filter(
    (event) => replayIds.has(event.id) || replayIds.has(event.replayId)
  );
  return `${frontMatter(input, {
    type: 'replay',
    id: node.label,
    title: node.label,
    status: node.status,
    generated_at: input.graph.generatedAt,
    local_only: events.length > 0 ? events.every((event) => event.localOnly) : undefined
  })}

# ${markdownText(input, node.label)}

## Replay History

${bullets(
  input,
  events.map(
    (event) => `${event.observedAt} - ${event.status}: ${event.evidence}; artifact ${event.artifactPath ?? 'unavailable'}`
  ),
  'No structured replay events recorded.'
)}

## Findings

${nodeLinks(input, connectedNodes(input, group.nodes, 'finding', 1), 'No linked findings recorded.')}

## Runs

${nodeLinks(input, connectedNodes(input, group.nodes, 'run', 2), 'No linked runs recorded.')}

## Artifacts

${nodeLinks(input, connectedNodes(input, group.nodes, 'asset', 1), 'No replay artifacts recorded.')}
`;
}

function renderRunNote(input: WriteVaultNotesInput, group: NodeGroup): string {
  const node = group.nodes[0]!;
  const runId = node.runId ?? node.id.replace(/^run:/, '');
  const run = input.history.runs.find((item) => item.id === runId);
  const timeline = input.graph.timeline.filter((event) => event.runId === runId);
  return `${frontMatter(input, {
    type: 'run',
    id: runId,
    title: node.label,
    status: node.status,
    generated_at: input.graph.generatedAt,
    mode: run?.mode
  })}

# ${markdownText(input, node.label)}

## Run

- Started: ${markdownText(input, run?.startedAt ?? 'Unavailable')}
- Completed: ${markdownText(input, run?.completedAt ?? 'Unavailable')}
- Mode: ${markdownText(input, run?.mode ?? 'Unavailable')}
- Report: ${markdownText(input, run?.reportPath ?? 'Unavailable')}

## Finding Lifecycle

${bullets(
  input,
  timeline.map((event) => `${event.timestamp} - ${event.lifecycle}: ${event.title}`),
  'No finding lifecycle events recorded.'
)}

## Findings

${nodeLinks(input, connectedNodes(input, group.nodes, 'finding', 1), 'No findings recorded for this run.')}

## Patches

${bullets(
  input,
  input.history.patches
    .filter((event) => event.runId === runId)
    .map((event) => `${event.outcome}: ${event.changePattern}`),
  'No patch events recorded for this run.'
)}

## Replays

${bullets(
  input,
  input.history.replays
    .filter((event) => event.runId === runId)
    .map((event) => `${event.status}: ${event.evidence}`),
  'No replay events recorded for this run.'
)}
`;
}

function renderDailyNote(input: WriteVaultNotesInput, date: string): string {
  const runs = input.history.runs
    .filter((run) => run.completedAt.slice(0, 10) === date)
    .sort((left, right) => compareText(left.completedAt, right.completedAt));
  const runIds = new Set(runs.map((run) => run.id));
  const runNodes = input.graph.nodes.filter(
    (node) => node.type === 'run' && node.runId && runIds.has(node.runId)
  );
  const timeline = input.graph.timeline.filter((event) => runIds.has(event.runId));
  return `${frontMatter(input, {
    type: 'daily',
    id: date,
    title: `Vault daily memory ${date}`,
    generated_at: input.graph.generatedAt,
    run_count: runs.length
  })}

# Vault Daily Memory - ${markdownText(input, date)}

## Runs

${nodeLinks(input, runNodes, 'No runs recorded for this day.')}

## Finding Lifecycle

${bullets(
  input,
  timeline.map((event) => `${event.timestamp} - ${event.lifecycle}: ${event.title}`),
  'No finding lifecycle events recorded for this day.'
)}

## Patches

${bullets(
  input,
  input.history.patches
    .filter((event) => runIds.has(event.runId))
    .map((event) => `${event.observedAt} - ${event.outcome}: ${event.changePattern}`),
  'No patch events recorded for this day.'
)}

## Replays

${bullets(
  input,
  input.history.replays
    .filter((event) => runIds.has(event.runId))
    .map((event) => `${event.observedAt} - ${event.status}: ${event.evidence}`),
  'No replay events recorded for this day.'
)}
`;
}

function renderGroupNote(
  input: WriteVaultNotesInput,
  category: GraphNoteCategory,
  group: NodeGroup
): string {
  switch (category) {
    case 'findings':
      return renderFindingNote(input, group);
    case 'routes':
      return renderRouteNote(input, group);
    case 'invariants':
      return renderInvariantNote(input, group);
    case 'patches':
      return renderPatchNote(input, group);
    case 'replays':
      return renderReplayNote(input, group);
    case 'runs':
      return renderRunNote(input, group);
  }
}

function relativeVaultPath(absolutePath: string, workspace: string): string {
  return path.relative(workspace, absolutePath).split(path.sep).join('/');
}

export async function writeVaultNotes(
  input: WriteVaultNotesInput
): Promise<VaultNoteSummary> {
  const vaultRoot = path.join(input.workspace, '.breachproof', 'vault');
  await Promise.all(
    noteCategories.map((category) =>
      mkdir(path.join(vaultRoot, category), { recursive: true })
    )
  );

  const output: VaultNoteSummary = {
    findings: [],
    routes: [],
    invariants: [],
    patches: [],
    replays: [],
    runs: [],
    daily: [],
    summaryPath: path.join(vaultRoot, 'state-summary.json')
  };

  const graphCategories: Array<[GraphNoteCategory, VaultNodeType]> = [
    ['findings', 'finding'],
    ['routes', 'route'],
    ['invariants', 'invariant'],
    ['patches', 'patch'],
    ['replays', 'replay'],
    ['runs', 'run']
  ];
  for (const [category, type] of graphCategories) {
    for (const group of groupsFor(input, type)) {
      const file = path.join(vaultRoot, category, `${group.slug}.md`);
      await writeFile(file, renderGroupNote(input, category, group), 'utf8');
      output[category].push(file);
    }
  }

  const dates = uniqueSorted(input.history.runs.map((run) => run.completedAt.slice(0, 10)));
  for (const date of dates) {
    const file = path.join(vaultRoot, 'daily', `${safeSlug(date)}.md`);
    await writeFile(file, renderDailyNote(input, date), 'utf8');
    output.daily.push(file);
  }

  const categories = Object.fromEntries(
    noteCategories.map((category) => [
      category,
      output[category].map((file) => relativeVaultPath(file, input.workspace)).sort(compareText)
    ])
  );
  const stateSummary = {
    schemaVersion: 1,
    generatedAt: redacted(input, input.graph.generatedAt),
    project: redacted(input, input.graph.project),
    currentRunId: redacted(input, input.graph.currentRunId),
    graph: input.graph.summary,
    categories
  };
  await writeFile(output.summaryPath, `${JSON.stringify(stateSummary, null, 2)}\n`, 'utf8');

  return output;
}

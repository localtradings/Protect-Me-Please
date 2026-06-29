import type { SystemMap } from '../core/types.js';
import type { WriteVaultNotesInput } from './markdown.js';
import { redactVaultText, safeSlug } from './redaction.js';
import type { VaultEdge, VaultNode } from './types.js';

export interface RouteProfileInput extends WriteVaultNotesInput {
  route: SystemMap['routes'][number];
}

function escapeHtml(value: string, workspace: string): string {
  return redactVaultText(value, workspace)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function routeLabel(route: RouteProfileInput['route']): string {
  return `${route.method.toUpperCase()} ${route.path}`;
}

function routeMatchesFinding(
  route: RouteProfileInput['route'],
  finding: RouteProfileInput['history']['findings'][number]['finding']
): boolean {
  const references = new Set(
    [...finding.affectedRoutes, ...finding.attackPath].map((value) => value.trim())
  );
  return references.has(route.id) || references.has(route.path) || references.has(routeLabel(route));
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function list(
  input: RouteProfileInput,
  values: string[],
  emptyMessage: string
): string {
  const items = uniqueSorted(values);
  if (items.length === 0) {
    return `<p class="empty">${escapeHtml(emptyMessage, input.workspace)}</p>`;
  }
  return `<ul>${items
    .map((value) => `<li>${escapeHtml(value, input.workspace)}</li>`)
    .join('')}</ul>`;
}

function statusCard(
  input: RouteProfileInput,
  label: string,
  status: string,
  detail: string
): string {
  const className = safeSlug(status);
  return `<article class="status-card status-${className}">
    <p class="eyebrow">${escapeHtml(label, input.workspace)}</p>
    <strong>${escapeHtml(status, input.workspace)}</strong>
    <p>${escapeHtml(detail, input.workspace)}</p>
  </article>`;
}

function relatedFindingNodes(input: RouteProfileInput): VaultNode[] {
  const routeNodeId = `route:${input.route.id}`;
  const ids = new Set<string>();
  for (const edge of input.graph.edges) {
    if (edge.from === routeNodeId && edge.to.startsWith('finding:')) ids.add(edge.to);
    if (edge.to === routeNodeId && edge.from.startsWith('finding:')) ids.add(edge.from);
  }
  return input.graph.nodes
    .filter((node) => ids.has(node.id) && node.type === 'finding')
    .sort((left, right) => left.id.localeCompare(right.id));
}

function directRelationships(
  input: RouteProfileInput,
  direction: 'inbound' | 'outbound'
): VaultEdge[] {
  const routeNodeId = `route:${input.route.id}`;
  return input.graph.edges
    .filter((edge) =>
      direction === 'inbound' ? edge.to === routeNodeId : edge.from === routeNodeId
    )
    .sort(
      (left, right) =>
        left.type.localeCompare(right.type) ||
        left.from.localeCompare(right.from) ||
        left.to.localeCompare(right.to)
    );
}

function relationshipList(
  input: RouteProfileInput,
  edges: VaultEdge[],
  emptyMessage: string
): string {
  return list(
    input,
    edges.map(
      (edge) =>
        `${edge.type}: ${edge.from} -> ${edge.to}; ${edge.evidence}; artifacts: ${edge.artifactPaths.join(', ')}`
    ),
    emptyMessage
  );
}

export function renderRouteProfile(input: RouteProfileInput): string {
  const { route } = input;
  const routeNode = input.graph.nodes.find(
    (node) => node.type === 'route' && node.id === `route:${route.id}`
  );
  const routeNodeId = routeNode?.id ?? `route:${route.id}`;
  const routeHref = `../index.html#node=${encodeURIComponent(
    redactVaultText(routeNodeId, input.workspace)
  )}`;
  const findingNodes = relatedFindingNodes(input);
  const graphFingerprints = findingNodes
    .map((node) => node.metadata.fingerprint)
    .filter((value): value is string => Boolean(value));
  const findingEvents = input.history.findings
    .filter(
      (event) =>
        graphFingerprints.includes(event.fingerprint) || routeMatchesFinding(route, event.finding)
    )
    .sort(
      (left, right) =>
        left.observedAt.localeCompare(right.observedAt) || left.id.localeCompare(right.id)
    );
  const fingerprints = new Set([
    ...graphFingerprints,
    ...findingEvents.map((event) => event.fingerprint)
  ]);
  const findings = findingEvents.map(
    (event) =>
      `${event.observedAt} - ${event.finding.title} [${event.verificationStatus}] (${event.runId}): ${event.finding.evidence}`
  );
  const invariants = input.invariantResults.invariants
    .filter((invariant) => invariant.routes.includes(routeLabel(route)))
    .sort((left, right) => left.id.localeCompare(right.id));
  const replays = input.history.replays
    .filter((replay) => fingerprints.has(replay.findingFingerprint))
    .sort(
      (left, right) =>
        left.observedAt.localeCompare(right.observedAt) || left.id.localeCompare(right.id)
    );
  const patches = input.history.patches
    .filter((patch) => fingerprints.has(patch.findingFingerprint))
    .sort(
      (left, right) =>
        left.observedAt.localeCompare(right.observedAt) || left.id.localeCompare(right.id)
    );
  const patchMemory = input.patchMemory
    .filter(
      (memory) =>
        memory.findingFingerprints.some((fingerprint) => fingerprints.has(fingerprint)) ||
        (memory.framework === route.framework && patches.some((patch) => patch.fileRole === memory.fileRole))
    )
    .sort((left, right) => left.patternId.localeCompare(right.patternId));
  const authBoundaries = input.systemMap.authBoundaries.filter(
    (boundary) => boundary.routeId === route.id
  );
  const models = route.prismaModels.map((name) => {
    const model = input.systemMap.dataModels.find((candidate) => candidate.name === name);
    return model
      ? `${model.name}: ${model.fields.join(', ')} (${model.file})`
      : name;
  });
  const aiTools = input.systemMap.aiToolCalls.filter(
    (tool) => tool.routePath === route.path
  );
  const regressionTests = uniqueSorted([
    ...patches.map((patch) => patch.testFile).filter((value): value is string => Boolean(value)),
    ...patchMemory.map((memory) => memory.regressionTestArtifact),
    ...input.graph.nodes
      .filter((node) => node.type === 'test')
      .filter((node) =>
        input.graph.edges.some(
          (edge) =>
            edge.type === 'protects' && edge.from === node.id && edge.to === routeNodeId
        )
      )
      .map((node) => node.metadata.path ?? node.label)
  ]);
  const sourceRoles = uniqueSorted(
    patches.map((patch) => patch.fileRole).filter(Boolean)
  );
  const sourceRole = sourceRoles.join(', ') || 'route handler';
  const inbound = directRelationships(input, 'inbound');
  const outbound = directRelationships(input, 'outbound');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(`${route.method} ${route.path} - Route security profile`, input.workspace)}</title>
  <style>
    :root { color-scheme: dark; --bg: #07090c; --panel: #10141a; --line: #29313b; --text: #eef2f6; --muted: #9aa6b2; --cyan: #4dd7e8; --amber: #f3bd58; --red: #ff6b6b; --green: #57d68d; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--bg); color: var(--text); font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    a { color: var(--cyan); }
    main { width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 28px 0 56px; }
    header { border-bottom: 1px solid var(--line); padding-bottom: 22px; }
    h1 { margin: 12px 0 6px; font-size: clamp(24px, 4vw, 40px); letter-spacing: 0; overflow-wrap: anywhere; }
    h2 { margin: 0 0 14px; font-size: 17px; letter-spacing: 0; }
    h3 { margin: 0 0 10px; font-size: 14px; letter-spacing: 0; color: var(--muted); }
    p { margin: 6px 0; overflow-wrap: anywhere; }
    code { color: var(--cyan); overflow-wrap: anywhere; }
    section { padding: 22px 0; border-bottom: 1px solid var(--line); }
    .eyebrow { margin: 0; color: var(--muted); font-size: 12px; text-transform: uppercase; }
    .summary { color: var(--muted); max-width: 88ch; }
    .meta-grid, .status-grid, .two-column { display: grid; gap: 12px; }
    .meta-grid { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 18px; }
    .status-grid { grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); }
    .two-column { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .meta, .status-card, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 14px; min-width: 0; }
    .status-card strong { display: block; margin: 4px 0; color: var(--amber); overflow-wrap: anywhere; }
    .status-detected strong, .status-protected strong, .status-verified-fixed strong, .status-passed strong { color: var(--green); }
    .status-not-detected strong, .status-failed strong, .status-review strong { color: var(--red); }
    ul { margin: 8px 0 0; padding-left: 20px; }
    li { margin: 7px 0; overflow-wrap: anywhere; }
    .empty { color: var(--muted); }
    .invariant-card { border-left: 3px solid var(--amber); }
    .invariant-card.status-passed { border-left-color: var(--green); }
    .invariant-card.status-failed { border-left-color: var(--red); }
    @media (max-width: 760px) { main { width: min(100% - 20px, 1180px); padding-top: 18px; } .two-column { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <header>
      <a href="${escapeHtml(routeHref, input.workspace)}">Back to selected route node</a>
      <p class="eyebrow">Route security profile</p>
      <h1>${escapeHtml(routeLabel(route), input.workspace)}</h1>
      <p class="summary">${escapeHtml(route.sourceSummary, input.workspace)}</p>
      <div class="meta-grid">
        <div class="meta"><span class="eyebrow">Method</span><p>${escapeHtml(route.method, input.workspace)}</p></div>
        <div class="meta"><span class="eyebrow">Path</span><p>${escapeHtml(route.path, input.workspace)}</p></div>
        <div class="meta"><span class="eyebrow">Framework</span><p>${escapeHtml(route.framework, input.workspace)}</p></div>
        <div class="meta"><span class="eyebrow">Source role</span><p>${escapeHtml(sourceRole, input.workspace)}</p></div>
        <div class="meta"><span class="eyebrow">Source file</span><p>${escapeHtml(route.file, input.workspace)}</p></div>
      </div>
    </header>

    <section>
      <h2>Security controls</h2>
      <div class="status-grid">
        ${statusCard(input, 'Authentication', route.authDetected ? 'detected' : 'not detected', 'Authentication boundary detection at this route.')}
        ${statusCard(input, 'Authorization', route.ownershipCheckDetected ? 'protected' : 'review', 'Authorization requires an ownership or tenant predicate.')}
        ${statusCard(input, 'Ownership', route.ownershipCheckDetected ? 'detected' : 'not detected', 'Object ownership control status.')}
        ${statusCard(input, 'Tenant scoping', route.ownershipCheckDetected ? 'detected' : 'not detected', 'Tenant isolation inferred from current route contracts.')}
      </div>
    </section>

    <section class="two-column">
      <div class="panel">
        <h2>Authentication and authorization boundaries</h2>
        ${list(
          input,
          authBoundaries.map((boundary) => `${boundary.mechanism} in ${boundary.file}`),
          'No explicit authentication boundary records.'
        )}
      </div>
      <div class="panel">
        <h2>Request-controlled privileged fields</h2>
        ${list(input, route.dangerousBodyFields, 'No privileged request fields detected.')}
        <p class="empty">Request body values are never stored in this profile.</p>
      </div>
    </section>

    <section class="two-column">
      <div class="panel">
        <h2>Connected models and data access</h2>
        ${list(input, models, 'No connected models.')}
      </div>
      <div class="panel">
        <h2>Jobs, uploads, webhooks, and AI tools</h2>
        <p>No connected jobs represented by the current system map.</p>
        <p>Upload validation: <strong>${route.uploadValidationDetected ? 'detected' : 'not detected'}</strong></p>
        <p>Webhook signature verification: <strong>${route.webhookSignatureDetected ? 'detected' : 'not detected'}</strong></p>
        ${list(
          input,
          aiTools.map(
            (tool) => `${tool.name}: dangerous=${String(tool.dangerous)}, guardrails=${String(tool.guardrailsDetected)} (${tool.file})`
          ),
          'No connected AI tools.'
        )}
      </div>
    </section>

    <section>
      <h2>Current and historical findings</h2>
      ${list(input, findings, 'No current or historical findings recorded for this route.')}
    </section>

    <section>
      <h2>Invariant status</h2>
      <div class="status-grid">
        ${
          invariants.length === 0
            ? '<p class="empty">No route invariants recorded.</p>'
            : invariants
                .map(
                  (invariant) => `<article class="status-card invariant-card status-${safeSlug(invariant.status)}">
                    <p class="eyebrow">${escapeHtml(invariant.id, input.workspace)}</p>
                    <strong>${escapeHtml(invariant.status, input.workspace)}</strong>
                    <p>${escapeHtml(invariant.description, input.workspace)}</p>
                    ${list(input, invariant.evidence, 'No invariant evidence recorded.')}
                  </article>`
                )
                .join('')
        }
      </div>
    </section>

    <section class="two-column">
      <div class="panel">
        <h2>Replay evidence</h2>
        ${list(
          input,
          replays.map(
            (replay) => `${replay.observedAt} - ${replay.status}: ${replay.evidence}; artifact ${replay.artifactPath ?? 'unavailable'}`
          ),
          'No replay evidence recorded.'
        )}
      </div>
      <div class="panel">
        <h2>Regression tests</h2>
        ${list(input, regressionTests, 'No regression tests recorded.')}
      </div>
    </section>

    <section class="two-column">
      <div class="panel">
        <h2>Patch memory</h2>
        ${list(
          input,
          patchMemory.map(
            (memory) => `${memory.patternId} - ${memory.outcome}: ${memory.strategy}; ${memory.changePattern}; reopened ${memory.reopenedCount} time(s)`
          ),
          'No verified patch memory recorded.'
        )}
      </div>
      <div class="panel">
        <h2>Verification history</h2>
        ${list(
          input,
          [
            ...findingEvents.map(
              (event) => `${event.observedAt} - ${event.verificationStatus}: ${event.finding.validation.summary}`
            ),
            ...patches.map(
              (patch) => `${patch.observedAt} - ${patch.outcome}: ${patch.verificationEvidence}`
            ),
            ...patchMemory.map(
              (memory) => `${memory.verificationRunId} - ${memory.outcome}: ${memory.verificationEvidence}`
            )
          ],
          'No verification history recorded.'
        )}
      </div>
    </section>

    <section class="two-column">
      <div class="panel">
        <h2>Inbound graph relationships</h2>
        ${relationshipList(input, inbound, 'No inbound graph relationships.')}
      </div>
      <div class="panel">
        <h2>Outbound graph relationships</h2>
        ${relationshipList(input, outbound, 'No outbound graph relationships.')}
      </div>
    </section>
  </main>
</body>
</html>`;
}

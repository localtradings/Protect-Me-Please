# BreachProof Vault Security Memory Graph Design

Status: approved for implementation on 2026-06-27

## Goal

Upgrade BreachProof Vault from disconnected run artifacts into an Obsidian-inspired, local security memory system with a distinctive 3D force graph. The graph must make attack paths, controls, evidence, fixes, tests, similarity, and regressions understandable without becoming a general note editor or graph database product.

The desktop visual source of truth is [breachproof-vault-reference.png](../../assets/breachproof-vault-reference.png). Implementation must reproduce its composition, visual hierarchy, node materials, path colors, inspector, controls, and timeline. The reference is not shipped as the application background; the interface is recreated as a real interactive Three.js scene.

## Product Boundary

The Vault is generated from authorized local BreachProof runs. It does not scan public targets, fetch production records, upload source code, execute destructive requests, access credentials, enable paid services, or apply patches without the existing explicit apply policy.

This feature is not:

- an Obsidian clone
- a Markdown editor
- a collaborative cloud knowledge base
- a graph database server
- a production monitoring service
- an attack execution console
- a replacement for the existing Markdown, JSON, SARIF, and HTML reports

## Visual Contract

The report is a full-viewport security instrument rather than a dashboard made from cards.

### Desktop composition

The desktop layout follows the approved reference:

1. A thin top command bar contains the BreachProof Vault identity, graph mode controls, search, and local-only status.
2. A narrow left tool rail contains orbit/reset, search, filter, neighborhood, asset visibility, settings, and fit controls.
3. The 3D graph fills the primary viewport without a decorative frame.
4. A narrow right inspector displays the selected node, evidence, history, links, route profile, and related artifacts.
5. A bottom timeline contains run playback, run markers, event markers, filters, and current-run position.
6. Zoom/orbit controls remain visible in the lower-left graph area.

No marketing copy, nested cards, gradient background, decorative blobs, generic terminal wall, or unrelated imagery is added.

### 3D node language

All production node assets are created procedurally with Three.js geometry and first-party canvas textures:

| Node type | Geometry | Color | Meaning |
| --- | --- | --- | --- |
| `route` | outlined triangular prism | cyan | request entry point |
| `finding` | extruded hexagonal warning body with alert sprite | red | active or historical weakness |
| `invariant` | faceted shield/hex body | amber | security policy or control |
| `patch` | beveled cube with check sprite | mint | proposed or verified fix pattern |
| `replay` | linked cube/ring object | violet | proof replay or similarity evidence |
| `test` | compact checked cube | mint/white | regression test artifact |
| `asset` | large hex frame around an asset glyph | cool white/cyan | protected model, data, job, or tool |
| `run` | small neutral cube | gray | historical run anchor |

Sprites are generated at runtime with `CanvasTexture`; no downloaded icon pack, model pack, font file, or stock visual asset is required. Meshes use restrained metallic/roughness values, edge outlines, and emissive materials. Bloom is applied only to selected evidence and active path elements.

### Edge language

- Active breach paths are red and use directional particles.
- Verified fix paths are mint and use restrained directional markers.
- Similarity and replay relationships are violet and curved where needed for separation.
- Historical relationships are desaturated and recede along the time axis.
- Normal topology is thin cool gray.
- Direction is always visible for attack and fix relationships.

### Interaction

- Orbit, zoom, pan, hover, click, node drag, fit-to-view, and camera reset are supported.
- Selecting a node focuses it and opens the inspector.
- Local mode shows the selected node and a configurable relationship depth.
- Global mode shows the full memory graph with label level-of-detail.
- Breach-path mode dims unrelated nodes and follows the selected path from route to asset.
- Timeline playback reveals events chronologically without changing stored history.
- Search matches node label, rule, route, file, invariant, and status.
- Filters control node type, severity, lifecycle status, run range, and edge type.
- Long labels truncate in-scene and remain fully available in the inspector and tooltip.
- Empty graphs show a quiet local-only empty state with a link to the current Markdown report.

On narrow screens the graph remains primary. The inspector and filters become drawers; the timeline remains horizontally scrollable. The desktop reference remains the fidelity target.

## Architecture

The implementation uses four explicit layers:

1. **Vault event store** records append-only run, finding, verification, patch, and replay observations in the existing local SQLite state database.
2. **Vault projectors** derive lifecycle state, similarity, patch memory, Markdown notes, route profiles, timeline events, and the typed graph.
3. **Vault report generator** writes the offline report directory and embeds the same graph payload in HTML for direct `file://` use.
4. **Vault UI bundle** renders the approved Three.js interface from the typed graph without network access.

The analyzer remains independent from the UI. Browser code consumes only validated `graph.json` data and cannot read the repository or SQLite database directly.

### Rendering stack

- `three` for scene, geometry, materials, textures, camera, and post-processing
- `3d-force-graph` for proven 3D force layout, camera interaction, node selection, and directional links
- `d3-force-3d` through the graph renderer for force behavior
- `esbuild` for a deterministic browser bundle copied into generated reports

Package metadata checked on 2026-06-27 reports MIT licenses for `three`, `3d-force-graph`, `d3-force-3d`, and `esbuild`. A third-party notices file records package, version, repository, and license. Production visual assets remain first-party procedural code.

## Persistent Layout

The persistent local Vault lives under `.breachproof/vault/`:

```text
.breachproof/vault/
  findings/<finding-fingerprint>.md
  routes/<route-fingerprint>.md
  invariants/<invariant-id>.md
  patches/<patch-pattern-id>.md
  replays/<replay-id>.md
  runs/<run-id>.md
  daily/YYYY-MM-DD.md
  state-summary.json
```

The generated report lives under `reports/vault/`:

```text
reports/vault/
  index.html
  graph.json
  timeline.json
  route-profiles/<route-fingerprint>.html
  assets/vault-graph.js
  assets/vault.css
```

`index.html` embeds a validated copy of the graph payload so it works when opened directly from disk. `graph.json` remains the canonical portable graph artifact required by integrations.

## Typed Graph Model

`VaultGraph` contains:

```ts
interface VaultGraph {
  schemaVersion: 1;
  generatedAt: string;
  project: string;
  currentRunId: string;
  nodes: VaultNode[];
  edges: VaultEdge[];
  timeline: VaultTimelineEvent[];
  summary: VaultGraphSummary;
}
```

Node types are `run`, `route`, `finding`, `invariant`, `patch`, `replay`, `test`, and `asset`.

Edge types are:

- `observed_in`
- `affects`
- `violates`
- `reaches`
- `proved_by`
- `fixed_by`
- `verified_by`
- `similar_to`
- `reopened_from`
- `repeated_from`
- `protects`

Every edge includes evidence text and source artifact references. The UI never derives security claims from visual proximity.

## Event Store

The target is local `.breachproof/state.sqlite`. The schema change is additive and append-only:

- `vault_runs` records run identity, mode, scope hash, start/end time, and report path.
- `vault_finding_events` records fingerprint, run, lifecycle event, proof mode, verification state, and source artifact.
- `vault_patch_events` records patch pattern, strategy, affected rule/stack, outcome, and verification evidence.
- `vault_replay_events` records replay identity, finding fingerprint, run, local-only state, and result.

No table, column, row, or existing state is deleted, reset, truncated, renamed, or overwritten. Inserts use stable natural identifiers and `INSERT OR IGNORE` for idempotent regeneration. The store is local development data, not a remote project. No service role key, RLS, backup operation, or production environment is involved.

## Finding Identity And Lifecycle

### Stable fingerprint

The identity fingerprint is a SHA-256 hash over normalized fields:

- rule ID
- normalized route method and path pattern
- framework
- normalized sink/model/tool
- violated invariant/control traits
- normalized affected file role, excluding workspace-specific absolute paths

Line numbers, timestamps, evidence prose, and generated IDs are excluded so harmless source movement does not create a new identity.

### Lifecycle events

- `new`: the fingerprint has no prior occurrence.
- `repeated`: the fingerprint appears again without an intervening verified fix.
- `fixed`: BreachProof has explicit `verified_fixed` evidence for the same fingerprint.
- `reopened`: a fingerprint with a prior `fixed` event appears again.
- `not_observed`: a prior fingerprint is absent from the current run but lacks verified-fix evidence. This is not displayed as fixed.

The timeline renders `new`, `fixed`, `reopened`, and `repeated` as primary security events. `not_observed` is available in details to avoid false claims.

## Similar-Bug Detection

Similarity is deterministic and offline. Exact fingerprints are excluded from similarity matching because they are handled by repeat/reopen logic.

The score is a weighted value from 0 to 1:

- same rule ID: 0.30
- same violated invariant/control family: 0.20
- same sink/model/tool: 0.20
- normalized route token Jaccard similarity: 0.15
- same framework and file role: 0.10
- overlapping evidence tags: 0.05

A score of at least 0.75 creates a `similar_to` edge. The edge stores the score and contributing signals. Results are sorted by score and stable identifier for deterministic output.

## Patch Memory

Patch memory records a reusable pattern only when verification status is `verified_fixed`. A recommended tournament candidate, generated diff, or passing static score alone is not considered successful.

Each patch memory includes:

- rule and stack traits
- strategy identifier
- normalized change pattern
- regression-test artifact
- verification run and evidence
- successful finding fingerprints
- later reopen count

When a new or similar finding appears, the Vault can display previously successful patterns. It does not edit source files or automatically apply a patch.

## Markdown Notes

Markdown notes use stable YAML front matter and relative wiki-style links so they remain usable in ordinary editors and Obsidian without requiring Obsidian.

Finding notes include lifecycle, route, evidence, attack path, invariant, replay, patch, test, similarity, verification, and run links. Route notes include auth, ownership, tenant controls, data access, findings, invariants, assets, tests, and timeline. Invariant, patch, replay, run, and daily notes expose their corresponding structured history without secrets or absolute workspace paths.

Generated content is redacted through the existing audit redaction rules. Request bodies, environment values, credentials, production records, and local absolute paths are not written into notes.

## Route Security Profiles

Every route receives a Markdown note and a static HTML profile containing:

- method, path, framework, and source role
- authentication and authorization boundaries
- ownership and tenant-scoping status
- request-controlled privileged fields
- connected models, jobs, uploads, webhooks, and AI tools
- current and historical findings
- invariant status cards
- replay evidence and regression tests
- patch memory and verification history
- inbound and outbound graph relationships

Profile pages use the same visual tokens as the graph report and link back to the selected route node in `index.html`.

## Workflow And CLI Integration

`breachproof run --auto` records the completed run, updates the persistent Vault, and writes the report after evidence, patch, and verification artifacts exist.

New commands:

```text
breachproof vault build
breachproof vault view
breachproof vault timeline
```

- `vault build` rebuilds notes and reports from local state and current artifacts.
- `vault view` prints the local report path and opens it only when `--open` is supplied.
- `vault timeline` prints deterministic lifecycle events for terminal and CI use.

CI generates and uploads the Vault report as an artifact but does not publish it publicly by default.

## Failure Handling

- Missing prior state produces a first-run Vault with `new` events.
- Missing optional artifacts produce explicit unavailable fields, not fabricated evidence.
- Invalid historical rows are rejected by schema validation and reported without deleting data.
- A browser without WebGL receives an accessible typed list, timeline, and route links.
- Large graphs use label level-of-detail, node grouping, neighborhood mode, and force cooldown.
- Empty findings still generate route, invariant, run, and asset memory.
- Bundle or report generation failure marks the run audit event failed and preserves earlier Vault history.

## Privacy And Security

- Everything remains local by default.
- No browser network requests are required.
- HTML escapes all repository-derived text before insertion.
- JSON embedded in HTML is serialized so it cannot terminate the script container.
- File links are relative and constrained to generated reports.
- Absolute paths, secrets, headers, cookies, request bodies, and environment values are excluded.
- The browser bundle is read-only and cannot apply patches or execute replays.
- Content Security Policy restricts scripts and resources to generated local assets.

## Testing And Acceptance

### Unit tests

- Zod validation for nodes, edges, timeline, and stored events
- stable fingerprints across line and workspace changes
- different identities for materially different sinks or controls
- Day 1 `new`, unresolved rerun `repeated`, Day 2 `fixed`, and Day 5 `reopened`
- similar-bug scoring and threshold explanations
- patch memory accepts only `verified_fixed`
- Markdown front matter, relative links, and redaction
- route profile content and invariant status cards
- deterministic graph ordering and edge evidence
- HTML escaping and safe JSON embedding

### Integration tests

- `run --auto --yes` writes Vault notes, SQLite events, graph, timeline, profile pages, and static assets.
- Rebuilding the same recorded run twice is idempotent and creates no duplicate Vault events.
- The default workflow does not modify analyzed source.
- A Day 1/Day 2/Day 5 fixture demonstrates new, fixed, similar, and reopened behavior.
- Existing Markdown, JSON, SARIF, proof, patch, and verification outputs remain available.

### Browser verification

Playwright verifies desktop and mobile viewports:

- WebGL canvas is nonblank by pixel inspection.
- The initial camera frames graph content.
- Orbit, zoom, focus, search, filtering, local depth, timeline playback, and inspector selection work.
- Active breach particles move in the correct source-to-target direction.
- Route profile navigation works.
- No text or controls overlap.
- WebGL-unavailable fallback remains usable.
- Screenshots match the approved reference composition and visual hierarchy.

### Required commands

```sh
npm run typecheck
npm run lint
npm test
npm run build
node dist/cli/index.js doctor
node dist/cli/index.js run --auto --yes
```

Docker verification remains conditional on a locally available daemon.

## Risks And Mitigations

- **Visual drift:** use the committed reference image and Playwright screenshots as the review baseline.
- **Large bundle:** build one minified offline graph asset and report its size in tests.
- **Graph overload:** default to local neighborhood mode and progressive labels.
- **False lifecycle claims:** require explicit verification for `fixed`; absence means `not_observed`.
- **False similarity:** expose score components and retain the 0.75 threshold in typed output.
- **WebGL compatibility:** provide an accessible non-WebGL fallback.
- **License ambiguity:** use only the verified MIT rendering stack and first-party procedural assets; record notices.
- **Sensitive report leakage:** keep Vault outputs ignored locally and CI uploads private to the workflow artifact by default.

## Implementation Skills And Tools

Implementation should use:

- test-driven development for the event store, projectors, and render contracts
- the frontend app builder guidance for the production interface
- Three.js and the proven 3D force engine rather than hand-written graph physics
- Playwright/frontend debugging guidance for visual and interaction verification
- image generation only for design comparison or documentation imagery, not runtime graph truth
- official package documentation and metadata for dependency-specific behavior

No paid API, billing page, account area, remote database, destructive database operation, or production target is required.

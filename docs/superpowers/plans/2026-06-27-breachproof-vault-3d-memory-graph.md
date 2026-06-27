# BreachProof Vault 3D Memory Graph Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the approved local BreachProof Vault with append-only security history, deterministic regression and similarity detection, Markdown memory, route profiles, and the exact approved interactive 3D graph experience.

**Architecture:** Existing proof artifacts feed an append-only SQLite event store. Pure projectors derive lifecycle, similarity, patch memory, Markdown notes, route profiles, and a typed `graph.json`; an offline Three.js/3d-force-graph bundle renders the approved full-screen report without network access or repository write access.

**Tech Stack:** TypeScript 6, Node.js 20+, Zod 4, better-sqlite3, Three.js, 3d-force-graph, Lucide, esbuild, Vitest, Playwright, static HTML/CSS.

---

## Execution Preconditions

- Work from `/Users/lanceianleanillo/Dowwnload/GitHub/Protect-Me-Please`.
- Preserve all existing uncommitted Proof Mode work. Do not reset, restore, or overwrite it.
- The approved design is `docs/superpowers/specs/2026-06-27-breachproof-vault-security-memory-graph-design.md`.
- The exact desktop reference is `docs/assets/breachproof-vault-reference.png`.
- Database target: local `.breachproof/state.sqlite` only.
- Database operation type: additive schema plus append-only inserts.
- Destructive operations: none.
- Remote database, RLS, service role key, and production data: none.
- Source changes remain artifact-only unless the existing explicit `--apply` policy is used.

## File Map

### Contracts and deterministic history

- Create `src/vault/types.ts`: Zod schemas and exported Vault types.
- Create `src/vault/fingerprint.ts`: stable finding and route identities.
- Create `src/vault/similarity.ts`: explainable weighted similar-bug scoring.
- Create `src/vault/history.ts`: lifecycle projection and patch-memory selection.
- Create `src/vault/store.ts`: append-only SQLite writes and reads.

### Projections and reports

- Create `src/vault/graph.ts`: typed nodes, edges, and timeline projection.
- Create `src/vault/markdown.ts`: Markdown notes and daily indexes.
- Create `src/vault/route-profile.ts`: route profile HTML.
- Create `src/vault/report.ts`: offline report directory writer and safe graph embedding.
- Create `src/vault/redaction.ts`: Vault-specific path and content redaction adapter.

### Browser renderer

- Create `src/vault/ui/entry.ts`: graph boot, modes, selection, search, and timeline.
- Create `src/vault/ui/node-assets.ts`: procedural Three.js node meshes and canvas sprites.
- Create `src/vault/ui/graph-style.ts`: node/link materials and visibility rules.
- Create `src/vault/ui/fallback.ts`: accessible non-WebGL report.
- Create `src/vault/ui/vault.css`: approved full-screen visual system.
- Create `scripts/build-vault-ui.mjs`: esbuild browser bundle.

### Integration, tests, and docs

- Modify `src/core/state.ts`, `src/core/workflow.ts`, `src/core/types.ts`, `src/cli/index.ts`, and `src/index.ts`.
- Modify `package.json`, `package-lock.json`, `.gitignore`, `.github/workflows/ci.yml`, `README.md`, `docs/architecture.md`, `docs/ci.md`, and `docs/safety-model.md`.
- Create `THIRD_PARTY_NOTICES.md`.
- Create `tests/core/vault-*.test.ts`, `tests/browser/vault-report.test.ts`, `playwright.config.ts`, and Day 1/2/5 fixture JSON.

## Task 0: Checkpoint The Existing Proof Mode Foundation

**Files:**
- Existing dirty files shown by `git status --short`
- Exclude: `.superpowers/`

- [ ] **Step 1: Verify the existing foundation before changing it**

Run:

```sh
git status --short
npm run typecheck
npm run lint
npm test
npm run build
node dist/cli/index.js doctor
```

Expected: all verification commands pass; the worktree remains dirty only with the known Proof Mode implementation and `.superpowers/` brainstorming files.

- [ ] **Step 2: Keep brainstorming output out of every commit**

Run:

```sh
git status --short
```

Expected: `.superpowers/` may remain untracked. Never include it in a `git add` path or commit.

- [ ] **Step 3: Commit the verified Proof Mode foundation separately**

Stage the already-existing implementation by responsibility and use clear summaries. Do not stage Vault files that do not exist yet. At minimum, preserve these boundaries:

```sh
git add src/agents src/proof src/reporting src/core package.json package-lock.json
git commit -m "feat: add BreachProof proof mode engines"
git add src/cli tests plugins
git commit -m "test: cover proof mode commands and plugins"
git add README.md SECURITY.md docs .github .gitignore
git commit -m "docs: document and automate BreachProof proof mode"
```

Expected: existing Proof Mode changes are checkpointed in readable commits; the approved Vault design commit remains in history; no brainstorming files are committed.

## Task 1: Add The Commercially Safe 3D Build Stack

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `scripts/build-vault-ui.mjs`
- Create: `tests/core/vault-build.test.ts`

- [ ] **Step 1: Write the failing build-contract test**

```ts
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, test } from 'vitest';

describe('Vault browser build', () => {
  test('declares the approved renderer and produces an offline bundle', async () => {
    const packageJson = JSON.parse(await readFile('package.json', 'utf8')) as {
      dependencies: Record<string, string>;
      devDependencies: Record<string, string>;
      scripts: Record<string, string>;
    };
    expect(packageJson.dependencies.three).toBeTruthy();
    expect(packageJson.dependencies['3d-force-graph']).toBeTruthy();
    expect(packageJson.dependencies.lucide).toBeTruthy();
    expect(packageJson.devDependencies.esbuild).toBeTruthy();
    expect(packageJson.scripts['build:vault-ui']).toBeTruthy();
    await access(path.resolve('dist/vault-ui/vault-graph.js'));
    await access(path.resolve('dist/vault-ui/vault.css'));
  });
});
```

- [ ] **Step 2: Run the test and confirm the missing build contract**

Run: `npx vitest run tests/core/vault-build.test.ts`

Expected: FAIL because dependencies, script, and `dist/vault-ui` assets do not exist.

- [ ] **Step 3: Install the verified package versions**

Run:

```sh
npm install three@^0.185.0 3d-force-graph@^1.80.0 lucide@^1.21.0
npm install --save-dev @types/three@^0.185.0 esbuild@^0.28.1 @playwright/test@^1.61.1
```

Expected: lockfile records the packages. `three`, `3d-force-graph`, `@types/three`, and `esbuild` are MIT; Lucide is ISC; Playwright is Apache-2.0.

- [ ] **Step 4: Add deterministic browser build scripts**

Set the relevant `package.json` scripts to:

```json
{
  "scripts": {
    "build:vault-ui": "node scripts/build-vault-ui.mjs",
    "pretest": "npm run build:vault-ui",
    "build": "tsc -p tsconfig.build.json && npm run build:vault-ui",
    "test:browser": "playwright test"
  }
}
```

Create `scripts/build-vault-ui.mjs`:

```js
import { mkdir, copyFile } from 'node:fs/promises';
import { build } from 'esbuild';

await mkdir('dist/vault-ui', { recursive: true });
await build({
  entryPoints: ['src/vault/ui/entry.ts'],
  outfile: 'dist/vault-ui/vault-graph.js',
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  sourcemap: false,
  legalComments: 'eof'
});
await copyFile('src/vault/ui/vault.css', 'dist/vault-ui/vault.css');
```

Create temporary compiling entry points in the same step:

```ts
// src/vault/ui/entry.ts
export function startVaultGraph(): void {}
```

```css
/* src/vault/ui/vault.css */
:root { color-scheme: dark; }
```

- [ ] **Step 5: Build and pass the contract test**

Run:

```sh
npm run build:vault-ui
npx vitest run tests/core/vault-build.test.ts
```

Expected: PASS and `dist/vault-ui/` contains both assets.

- [ ] **Step 6: Commit the rendering toolchain**

```sh
git add package.json package-lock.json scripts/build-vault-ui.mjs src/vault/ui/entry.ts src/vault/ui/vault.css tests/core/vault-build.test.ts
git commit -m "build: add offline Vault 3D renderer pipeline"
```

## Task 2: Define Vault Contracts, Fingerprints, And Similarity

**Files:**
- Create: `src/vault/types.ts`
- Create: `src/vault/fingerprint.ts`
- Create: `src/vault/similarity.ts`
- Create: `tests/helpers/vault-fixtures.ts`
- Create: `tests/core/vault-identity.test.ts`

- [ ] **Step 1: Write failing identity and similarity tests**

```ts
import { describe, expect, test } from 'vitest';
import { findingFingerprint, routeFingerprint } from '../../src/vault/fingerprint.js';
import { compareFindingSimilarity } from '../../src/vault/similarity.js';
import { makeFinding } from '../helpers/vault-fixtures.js';

describe('Vault identities', () => {
  test('ignores workspace and generated finding IDs', () => {
    expect(findingFingerprint(makeFinding())).toBe(findingFingerprint(makeFinding({ id: 'other-id', affectedFiles: ['/tmp/repo/app/api/invoices/[id]/route.ts'] })));
  });

  test('changes when the protected sink changes', () => {
    expect(findingFingerprint(makeFinding())).not.toBe(findingFingerprint(makeFinding({ attackPath: ['GET /api/invoices/[id]', 'User'] })));
  });

  test('normalizes route parameters', () => {
    expect(routeFingerprint('GET', '/api/invoices/123')).toBe(routeFingerprint('GET', '/api/invoices/[id]'));
  });

  test('explains a similar bug without treating it as identical', () => {
    const result = compareFindingSimilarity(makeFinding(), makeFinding({ id: 'new', affectedRoutes: ['GET /api/orders/[id]'], affectedFiles: ['app/api/orders/[id]/route.ts'], attackPath: ['GET /api/orders/[id]', 'Invoice'] }));
    expect(result.score).toBeGreaterThanOrEqual(0.75);
    expect(result.signals).toContain('same_rule');
  });
});
```

Create `tests/helpers/vault-fixtures.ts` with the complete shared finding builder:

```ts
import type { Finding } from '../../src/core/types.js';

export function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'generated-id',
    ruleId: 'BP-BOLA-002',
    title: 'Tenant escape',
    severity: 'high',
    status: 'validated',
    fixStatus: 'suggested',
    proofMode: 'static_trace',
    affectedFiles: ['app/api/invoices/[id]/route.ts'],
    affectedRoutes: ['GET /api/invoices/[id]'],
    attackPath: ['GET /api/invoices/[id]', 'Invoice'],
    evidence: 'Prisma Invoice lookup lacks tenantId',
    exploitabilityReasoning: 'Request id reaches Invoice',
    recommendation: 'Add tenantId',
    patchStatus: 'suggested',
    verificationStatus: 'not_run',
    validation: { mode: 'local', destructive: false, productionTouched: false, summary: 'static trace' },
    ...overrides
  };
}
```

- [ ] **Step 2: Run the test and confirm missing modules**

Run: `npx vitest run tests/core/vault-identity.test.ts`

Expected: FAIL with unresolved `src/vault/fingerprint.ts` and `src/vault/similarity.ts`.

- [ ] **Step 3: Define the validated graph and event contracts**

Create `src/vault/types.ts` with Zod schemas for:

```ts
export const vaultNodeTypeSchema = z.enum(['run', 'route', 'finding', 'invariant', 'patch', 'replay', 'test', 'asset']);
export const vaultEdgeTypeSchema = z.enum(['observed_in', 'affects', 'violates', 'reaches', 'proved_by', 'fixed_by', 'verified_by', 'similar_to', 'reopened_from', 'repeated_from', 'protects']);
export const vaultLifecycleSchema = z.enum(['new', 'repeated', 'fixed', 'reopened', 'not_observed']);

export const vaultNodeSchema = z.object({
  id: z.string(), type: vaultNodeTypeSchema, label: z.string(), status: z.string(),
  severity: severitySchema.optional(), runId: z.string().optional(), route: z.string().optional(),
  notePath: z.string().optional(), profilePath: z.string().optional(), metadata: z.record(z.string(), z.string()).default({})
});

export const vaultEdgeSchema = z.object({
  id: z.string(), from: z.string(), to: z.string(), type: vaultEdgeTypeSchema,
  label: z.string(), evidence: z.string(), score: z.number().min(0).max(1).optional(), artifactPaths: z.array(z.string()).default([])
});

export const vaultGraphSchema = z.object({
  schemaVersion: z.literal(1), generatedAt: z.string().datetime(), project: z.string(), currentRunId: z.string(),
  nodes: z.array(vaultNodeSchema), edges: z.array(vaultEdgeSchema), timeline: z.array(vaultTimelineEventSchema),
  summary: z.object({ nodes: z.number(), edges: z.number(), newIssues: z.number(), fixedIssues: z.number(), reopenedIssues: z.number(), repeatedIssues: z.number() })
});
```

Also export inferred types and explicit `VaultRunEvent`, `VaultFindingEvent`, `VaultPatchEvent`, `VaultReplayEvent`, and `FindingSimilarity` interfaces used by later tasks.

- [ ] **Step 4: Implement stable normalization and weighted similarity**

`findingFingerprint()` must hash normalized `ruleId`, method/path, framework inferred from file, terminal attack-path sink, control tags, and file role. `compareFindingSimilarity()` must use weights `0.30/0.20/0.20/0.15/0.10/0.05`, return sorted signal names, and never mark exact fingerprints as similar.

Core signatures:

```ts
export function routeFingerprint(method: string, route: string): string;
export function findingFingerprint(finding: Finding): string;
export function compareFindingSimilarity(current: Finding, previous: Finding): FindingSimilarity;
export function findSimilarFindings(current: Finding, previous: Finding[], threshold = 0.75): FindingSimilarity[];
```

- [ ] **Step 5: Pass the identity tests and typecheck**

Run:

```sh
npx vitest run tests/core/vault-identity.test.ts
npm run typecheck
```

Expected: PASS; fingerprints are deterministic and similarity includes score components.

- [ ] **Step 6: Commit contracts and identity logic**

```sh
git add src/vault/types.ts src/vault/fingerprint.ts src/vault/similarity.ts tests/helpers/vault-fixtures.ts tests/core/vault-identity.test.ts
git commit -m "feat: add deterministic Vault identities and similarity"
```

## Task 3: Add Append-Only Vault Storage And Lifecycle Projection

**Files:**
- Modify: `src/core/state.ts`
- Create: `src/vault/store.ts`
- Create: `src/vault/history.ts`
- Modify: `tests/helpers/vault-fixtures.ts`
- Create: `tests/core/vault-history.test.ts`

- [ ] **Step 1: Write failing local-store lifecycle tests**

```ts
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, test } from 'vitest';
import { initializeStateStore } from '../../src/core/state.js';
import { appendVaultSnapshot, readVaultHistory } from '../../src/vault/store.js';
import { projectLifecycle } from '../../src/vault/history.js';
import { makeSnapshot } from '../helpers/vault-fixtures.js';

test('projects new, repeated, fixed, and reopened without destructive writes', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'bp-vault-history-'));
  const db = initializeStateStore(workspace);
  try {
    appendVaultSnapshot(db, makeSnapshot('day-1', 'observed'));
    appendVaultSnapshot(db, makeSnapshot('day-2-repeat', 'observed'));
    appendVaultSnapshot(db, makeSnapshot('day-2-fixed', 'verified_fixed'));
    appendVaultSnapshot(db, makeSnapshot('day-5', 'observed'));
    appendVaultSnapshot(db, makeSnapshot('day-5', 'observed'));
    expect(projectLifecycle(readVaultHistory(db)).map(event => event.lifecycle)).toEqual(['new', 'repeated', 'fixed', 'reopened']);
    expect(db.prepare('select count(*) as count from vault_finding_events').get()).toEqual({ count: 4 });
  } finally { db.close(); await rm(workspace, { recursive: true, force: true }); }
});
```

Extend `tests/helpers/vault-fixtures.ts` with:

```ts
import type { VaultRunSnapshot } from '../../src/vault/types.js';

export function makeSnapshot(runId: string, lifecycleInput: 'observed' | 'verified_fixed'): VaultRunSnapshot {
  const day = runId.startsWith('day-1') ? '01' : runId.startsWith('day-2') ? '02' : '05';
  return {
    run: {
      id: runId,
      mode: 'local',
      scopeHash: 'a'.repeat(64),
      startedAt: `2026-06-${day}T09:59:00.000Z`,
      completedAt: `2026-06-${day}T10:00:00.000Z`,
      reportPath: 'reports/vault/index.html'
    },
    findings: [{ finding: makeFinding(), fingerprint: 'invoice-fingerprint', lifecycleInput }],
    patches: [],
    replays: []
  };
}
```

- [ ] **Step 2: Run the test and verify missing schema/storage**

Run: `npx vitest run tests/core/vault-history.test.ts`

Expected: FAIL because Vault tables and APIs are absent.

- [ ] **Step 3: Add only additive local SQLite tables**

Extend `initializeStateStore()` with `CREATE TABLE IF NOT EXISTS` for:

```sql
CREATE TABLE IF NOT EXISTS vault_runs (
  id TEXT PRIMARY KEY, mode TEXT NOT NULL, scope_hash TEXT NOT NULL,
  started_at TEXT NOT NULL, completed_at TEXT NOT NULL, report_path TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_finding_events (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
  lifecycle_input TEXT NOT NULL, rule_id TEXT NOT NULL, finding_json TEXT NOT NULL,
  verification_status TEXT NOT NULL, observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vault_finding_fingerprint ON vault_finding_events(fingerprint, observed_at);
CREATE TABLE IF NOT EXISTS vault_patch_events (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, finding_fingerprint TEXT NOT NULL,
  pattern_id TEXT NOT NULL, strategy TEXT NOT NULL, outcome TEXT NOT NULL,
  patch_json TEXT NOT NULL, observed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_replay_events (
  id TEXT PRIMARY KEY, run_id TEXT NOT NULL, finding_fingerprint TEXT NOT NULL,
  replay_id TEXT NOT NULL, status TEXT NOT NULL, replay_json TEXT NOT NULL,
  observed_at TEXT NOT NULL
);
```

Do not add `DROP`, `DELETE`, `UPDATE`, reset, repair, or remote connection code.

- [ ] **Step 4: Implement idempotent append and lifecycle projection**

Expose:

```ts
export function appendVaultSnapshot(db: StateDatabase, snapshot: VaultRunSnapshot): void;
export function readVaultHistory(db: StateDatabase): VaultHistory;
export function projectLifecycle(history: VaultHistory): VaultTimelineEvent[];
export function currentLifecycleByFingerprint(history: VaultHistory): Map<string, VaultLifecycle>;
```

Use one local transaction with `INSERT OR IGNORE`. `fixed` requires `verified_fixed`; a missing observation becomes `not_observed`, never `fixed`.

- [ ] **Step 5: Pass lifecycle, idempotence, and existing state tests**

Run:

```sh
npx vitest run tests/core/vault-history.test.ts tests/core/config.test.ts
npm run typecheck
```

Expected: PASS and no existing table behavior changes.

- [ ] **Step 6: Commit the append-only store**

```sh
git add src/core/state.ts src/vault/store.ts src/vault/history.ts tests/helpers/vault-fixtures.ts tests/core/vault-history.test.ts
git commit -m "feat: persist append-only Vault security history"
```

## Task 4: Project Patch Memory, Timeline, And Typed Graph

**Files:**
- Create: `src/vault/graph.ts`
- Extend: `src/vault/history.ts`
- Modify: `tests/helpers/vault-fixtures.ts`
- Create: `tests/core/vault-graph.test.ts`

- [ ] **Step 1: Write failing graph and patch-memory tests**

```ts
test('links routes, findings, controls, evidence, verified patches, and history', () => {
  const result = buildVaultGraph(makeGraphInput());
  expect(result.nodes.map(node => node.type)).toEqual(expect.arrayContaining(['run', 'route', 'finding', 'invariant', 'patch', 'replay', 'test', 'asset']));
  expect(result.edges.map(edge => edge.type)).toEqual(expect.arrayContaining(['reaches', 'violates', 'proved_by', 'fixed_by', 'similar_to', 'reopened_from']));
  expect(result.timeline.map(event => event.lifecycle)).toEqual(expect.arrayContaining(['new', 'fixed', 'reopened']));
  expect(vaultGraphSchema.parse(result)).toEqual(result);
});

test('remembers only verified patch patterns', () => {
  const memory = buildPatchMemory(makePatchHistory(['patch_created', 'verified_fixed']));
  expect(memory).toHaveLength(1);
  expect(memory[0]?.outcome).toBe('verified_fixed');
});
```

Import `makeGraphInput` and `makePatchHistory` from `tests/helpers/vault-fixtures.ts`. Extend that helper in this task using `makeFinding()`, schema-valid empty SystemMap collections, one failed `tenant-isolation` result, one replay item, one patch item, and explicit Day 1/2/5 history. `makePatchHistory()` must create one event per supplied outcome with stable increasing timestamps.

- [ ] **Step 2: Run and confirm the projectors are absent**

Run: `npx vitest run tests/core/vault-graph.test.ts`

Expected: FAIL on missing `buildVaultGraph` and `buildPatchMemory`.

- [ ] **Step 3: Implement evidence-backed graph projection**

Expose:

```ts
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

export function buildVaultGraph(input: BuildVaultGraphInput): VaultGraph;
export function buildPatchMemory(history: VaultHistory): VaultPatchMemory[];
```

Sort nodes by `type/id`, edges by `type/from/to`, and timeline by timestamp/id. Every edge must include evidence and artifact paths; proximity alone never creates a claim.

- [ ] **Step 4: Pass graph tests and serialize deterministically**

Run:

```sh
npx vitest run tests/core/vault-graph.test.ts
npm run typecheck
```

Expected: PASS; two projections of the same input differ only when `generatedAt` is intentionally changed.

- [ ] **Step 5: Commit the graph projectors**

```sh
git add src/vault/graph.ts src/vault/history.ts tests/helpers/vault-fixtures.ts tests/core/vault-graph.test.ts
git commit -m "feat: project Vault graph timeline and patch memory"
```

## Task 5: Generate Markdown Memory And Route Profiles

**Files:**
- Create: `src/vault/redaction.ts`
- Create: `src/vault/markdown.ts`
- Create: `src/vault/route-profile.ts`
- Create: `tests/core/vault-notes.test.ts`

- [ ] **Step 1: Write failing note/profile tests**

```ts
test('writes linked notes without secrets or absolute workspace paths', async () => {
  const output = await writeVaultNotes({ workspace, graph, history, systemMap, invariantResults, patchMemory });
  const finding = await readFile(output.findings[0]!, 'utf8');
  expect(finding).toContain('type: finding');
  expect(finding).toContain('[[../../routes/');
  expect(finding).not.toContain(workspace);
  expect(finding).not.toContain('secret-value');
});

test('renders a route profile with controls, history, evidence, and invariant cards', () => {
  const html = renderRouteProfile(routeProfileFixture());
  expect(html).toContain('Route security profile');
  expect(html).toContain('tenant-isolation');
  expect(html).toContain('verified_fixed');
  expect(html).toContain('../index.html#node=');
  expect(html).not.toContain('<script>alert(1)</script>');
});
```

- [ ] **Step 2: Run and confirm generators are absent**

Run: `npx vitest run tests/core/vault-notes.test.ts`

Expected: FAIL on unresolved modules.

- [ ] **Step 3: Implement safe note generation**

Expose:

```ts
export async function writeVaultNotes(input: WriteVaultNotesInput): Promise<VaultNoteSummary>;
export function renderRouteProfile(input: RouteProfileInput): string;
export function redactVaultText(value: string, workspace: string): string;
export function safeSlug(value: string): string;
```

Write stable YAML front matter, relative wiki links, lifecycle sections, evidence links, patch outcomes, and daily/run notes. Reuse existing redaction behavior and additionally replace absolute workspace paths with `<workspace>`.

- [ ] **Step 4: Pass note tests and inspect fixture output**

Run:

```sh
npx vitest run tests/core/vault-notes.test.ts
npm run typecheck
```

Expected: PASS; generated notes are readable Markdown and route profile HTML is escaped.

- [ ] **Step 5: Commit notes and route profiles**

```sh
git add src/vault/redaction.ts src/vault/markdown.ts src/vault/route-profile.ts tests/core/vault-notes.test.ts
git commit -m "feat: generate Vault notes and route security profiles"
```

## Task 6: Package The Offline Static Vault Report

**Files:**
- Create: `src/vault/report.ts`
- Create: `tests/core/vault-report.test.ts`

- [ ] **Step 1: Write the failing offline-report test**

```ts
test('writes an offline report with safe embedded data and portable graph.json', async () => {
  const result = await writeVaultReport({ workspace, reportsDir: 'reports', graph, routeProfiles });
  const html = await readFile(result.indexFile, 'utf8');
  const json = JSON.parse(await readFile(result.graphFile, 'utf8'));
  expect(vaultGraphSchema.parse(json)).toEqual(json);
  expect(html).toContain('id="breachproof-vault-data"');
  expect(html).toContain('./assets/vault-graph.js');
  expect(html).toContain("default-src 'self' data: blob:");
  expect(html).not.toContain('</script><script>alert(1)</script>');
  await access(path.join(workspace, 'reports/vault/assets/vault-graph.js'));
});
```

- [ ] **Step 2: Run and confirm the writer is absent**

Run: `npx vitest run tests/core/vault-report.test.ts`

Expected: FAIL on missing `writeVaultReport`.

- [ ] **Step 3: Implement direct-file-safe report packaging**

Expose:

```ts
export interface VaultReportOutput {
  indexFile: string;
  graphFile: string;
  timelineFile: string;
  routeProfileFiles: string[];
  assetFiles: string[];
}

export async function writeVaultReport(input: WriteVaultReportInput): Promise<VaultReportOutput>;
export function serializeEmbeddedJson(value: unknown): string;
```

`serializeEmbeddedJson()` must replace `<`, `>`, `&`, U+2028, and U+2029 with Unicode escapes. Copy the built bundle from `dist/vault-ui/`; fail with a precise `npm run build:vault-ui` message when absent.

- [ ] **Step 4: Pass report tests**

Run:

```sh
npm run build:vault-ui
npx vitest run tests/core/vault-report.test.ts
```

Expected: PASS and the report opens without fetching `graph.json`.

- [ ] **Step 5: Commit the offline report writer**

```sh
git add src/vault/report.ts tests/core/vault-report.test.ts
git commit -m "feat: package offline Vault graph reports"
```

## Task 7: Build The Approved Procedural 3D Assets And Scene

**Files:**
- Replace: `src/vault/ui/entry.ts`
- Create: `src/vault/ui/node-assets.ts`
- Create: `src/vault/ui/graph-style.ts`
- Create: `tests/core/vault-ui-contract.test.ts`

- [ ] **Step 1: Write the failing browser-asset contract test**

```ts
test('defines a distinct procedural asset for every Vault node type', async () => {
  const source = await readFile('src/vault/ui/node-assets.ts', 'utf8');
  for (const type of ['route', 'finding', 'invariant', 'patch', 'replay', 'test', 'asset', 'run']) {
    expect(source).toContain(`case '${type}'`);
  }
  expect(source).toContain('CanvasTexture');
  expect(source).toContain('MeshStandardMaterial');
  expect(source).not.toContain('TextureLoader');
});
```

- [ ] **Step 2: Run and confirm asset factories are absent**

Run: `npx vitest run tests/core/vault-ui-contract.test.ts`

Expected: FAIL because `node-assets.ts` does not exist.

- [ ] **Step 3: Implement first-party meshes and sprites**

Use this public API:

```ts
export function createVaultNodeObject(node: VaultNode): THREE.Group;
export function createGlyphTexture(glyph: 'route' | 'alert' | 'shield' | 'check' | 'link' | 'test' | 'asset' | 'run', color: string): THREE.CanvasTexture;
export function updateVaultNodeState(object: THREE.Group, state: { selected: boolean; dimmed: boolean }): void;
```

The switch must map node types exactly to the geometry/color table in the approved spec. Use built-in geometries, `EdgesGeometry`, `LineSegments`, canvas-drawn glyphs, and `MeshStandardMaterial`; do not load external models or textures.

- [ ] **Step 4: Implement graph scene boot and active path particles**

`entry.ts` must parse `vaultGraphSchema`, create `ForceGraph3D`, configure `nodeThreeObject(createVaultNodeObject)`, set link colors/widths, add directional particles only for `reaches`, `violates`, `fixed_by`, and `similar_to`, and set a restrained bloom pass.

Core boot signature:

```ts
export function startVaultGraph(root: HTMLElement, graph: VaultGraph): VaultGraphController;
```

- [ ] **Step 5: Build, test, and inspect bundle size**

Run:

```sh
npm run build:vault-ui
npx vitest run tests/core/vault-ui-contract.test.ts
wc -c dist/vault-ui/vault-graph.js
```

Expected: PASS; bundle is nonempty and contains no remote URL dependencies.

- [ ] **Step 6: Commit the 3D scene and assets**

```sh
git add src/vault/ui/entry.ts src/vault/ui/node-assets.ts src/vault/ui/graph-style.ts tests/core/vault-ui-contract.test.ts
git commit -m "feat: render Vault with custom procedural 3D assets"
```

## Task 8: Match The Approved UI, Interactions, And Fallback

**Files:**
- Replace: `src/vault/ui/vault.css`
- Create: `src/vault/ui/fallback.ts`
- Modify: `src/vault/ui/entry.ts`
- Create: `tests/browser/vault-report.test.ts`
- Create: `playwright.config.ts`

- [ ] **Step 1: Write failing Playwright interaction tests**

```ts
test('renders the approved graph shell and focuses evidence', async ({ page }) => {
  await page.goto(reportUrl);
  await expect(page.getByText('BREACHPROOF VAULT')).toBeVisible();
  await expect(page.locator('canvas')).toBeVisible();
  await page.getByRole('button', { name: 'Breach paths' }).click();
  await page.getByPlaceholder('Search routes, findings, invariants, patches').fill('BP-BOLA-002');
  await page.getByText('BP-BOLA-002').click();
  await expect(page.getByRole('complementary')).toContainText('tenant-isolation');
  await expect(page.locator('[data-testid="vault-timeline"]')).toContainText('REOPENED');
});

test('shows an accessible fallback when WebGL is disabled', async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: true });
  const page = await context.newPage();
  await page.addInitScript(() => { HTMLCanvasElement.prototype.getContext = () => null; });
  await page.goto(reportUrl);
  await expect(page.getByRole('table', { name: 'Vault graph fallback' })).toBeVisible();
});
```

The test setup must generate a fixture report in `beforeAll` and convert its path with `pathToFileURL()`.

- [ ] **Step 2: Run and confirm the approved UI is missing**

Run: `npx playwright test tests/browser/vault-report.test.ts`

Expected: FAIL because the production shell, interactions, and fallback are not complete.

- [ ] **Step 3: Implement the exact reference composition**

`vault.css` must define stable responsive regions for:

```css
.vault-shell { position: fixed; inset: 0; display: grid; grid-template: 56px 1fr 88px / 56px 1fr 292px; background: #030507; }
.vault-topbar { grid-column: 1 / -1; }
.vault-tools { grid-row: 2; grid-column: 1; }
.vault-scene { grid-row: 2; grid-column: 2; min-width: 0; min-height: 0; }
.vault-inspector { grid-row: 2; grid-column: 3; overflow: auto; }
.vault-timeline { grid-row: 3; grid-column: 1 / -1; }
```

Use the reference colors, thin borders, compact technical typography, icon controls with tooltips, and no gradients/cards. At widths below 760px, convert tools and inspector to overlay drawers while preserving the full graph.

Import Lucide's `createIcons` and named icons for search, filter, focus, fit, play, pause, layers, settings, and fullscreen controls. Custom canvas glyphs remain limited to the 3D node assets.

- [ ] **Step 4: Implement interactions and fallback**

Complete `VaultGraphController` with:

```ts
selectNode(id: string): void;
setMode(mode: 'local' | 'global' | 'breach_path'): void;
setDepth(depth: number): void;
setRunRange(from: string, to: string): void;
search(query: string): string[];
playTimeline(): void;
pauseTimeline(): void;
fit(): void;
destroy(): void;
```

`fallback.ts` must render a semantic table, timeline, and route-profile links from the same validated graph.

- [ ] **Step 5: Pass browser tests at desktop and mobile sizes**

Run: `npx playwright test tests/browser/vault-report.test.ts`

Expected: PASS for configured `desktop-chromium` and `mobile-chromium` projects.

- [ ] **Step 6: Commit the approved UI**

```sh
git add src/vault/ui/vault.css src/vault/ui/fallback.ts src/vault/ui/entry.ts tests/browser/vault-report.test.ts playwright.config.ts
git commit -m "feat: match the approved BreachProof Vault interface"
```

## Task 9: Integrate Vault Into Workflow, CLI, And Exports

**Files:**
- Modify: `src/core/workflow.ts`
- Modify: `src/cli/index.ts`
- Modify: `src/index.ts`
- Modify: `tests/core/workflow.test.ts`
- Modify: `tests/core/cli.test.ts`

- [ ] **Step 1: Extend failing workflow and CLI smoke tests**

Add these artifact assertions to the existing workflow test:

```ts
await Promise.all([
  access(path.join(workspace, '.breachproof/vault/daily')),
  access(path.join(workspace, 'reports/vault/index.html')),
  access(path.join(workspace, 'reports/vault/graph.json')),
  access(path.join(workspace, 'reports/vault/timeline.json'))
]);
```

Add CLI assertions:

```ts
expect(await runCli(['vault', 'build'], workspace)).toContain('Vault built');
expect(await runCli(['vault', 'view'], workspace)).toContain('reports/vault/index.html');
expect(await runCli(['vault', 'timeline'], workspace)).toContain('new');
```

- [ ] **Step 2: Run and confirm commands/artifacts are absent**

Run: `npx vitest run tests/core/workflow.test.ts tests/core/cli.test.ts`

Expected: FAIL on missing Vault output and unknown `vault` command.

- [ ] **Step 3: Add one orchestration boundary**

Create and export `recordAndBuildVault()` from `src/vault/report.ts`. It accepts the already-computed workflow artifacts, opens the local store, appends the snapshot, projects history, writes notes/profiles/report, closes the DB in `finally`, and returns every written path.

Also create `rebuildVaultFromReports(workspace, reportsDir)`. It validates and loads `system-map.json`, `final-report.json`, `invariant-results.json`, `patch-summary.json`, `patch-tournament.json`, `verification.json`, and `evidence-summary.json`, then rebuilds notes/profiles/report without inserting a duplicate run.

Call it in `runAutonomousWorkflow()` after evidence, patch, and verification exist and before the final audit completion event. Add returned paths to `artifacts` without changing source-apply behavior.

- [ ] **Step 4: Add CLI commands without implicit browser opening**

Add:

```ts
const vault = program.command('vault').description('Build and inspect the local security memory graph.');
configureCommonOptions(vault.command('build')).action(buildVaultCommand);
configureCommonOptions(vault.command('view').option('--open', 'open the generated local report')).action(viewVaultCommand);
configureCommonOptions(vault.command('timeline')).action(printVaultTimelineCommand);
```

`build` calls `rebuildVaultFromReports()` and fails with `Run breachproof run --auto first` when required report artifacts are absent. `view` prints the path by default. `--open` may use the platform opener only after confirming the target is the local generated report path.

- [ ] **Step 5: Pass workflow and CLI tests**

Run:

```sh
npx vitest run tests/core/workflow.test.ts tests/core/cli.test.ts
npm run typecheck
```

Expected: PASS; fixture source bytes remain unchanged by default.

- [ ] **Step 6: Commit integration**

```sh
git add src/core/workflow.ts src/cli/index.ts src/index.ts src/vault/report.ts tests/core/workflow.test.ts tests/core/cli.test.ts
git commit -m "feat: integrate Vault reports with workflow and CLI"
```

## Task 10: Add The Day 1, Day 2, Day 5 Security Memory Demo

**Files:**
- Create: `tests/fixtures/vault-history/day-1.json`
- Create: `tests/fixtures/vault-history/day-2.json`
- Create: `tests/fixtures/vault-history/day-5.json`
- Create: `tests/helpers/vault-demo.ts`
- Create: `tests/core/vault-demo.test.ts`
- Modify: `README.md`

- [ ] **Step 1: Add fixture snapshots with explicit evidence states**

`day-1.json` contains one observed `BP-BOLA-002` invoice route finding. `day-2.json` contains the same fingerprint with `verified_fixed`. `day-5.json` contains the reopened invoice fingerprint plus a new orders route finding scoring at least 0.75 similarity.

`day-1.json` must contain this complete object:

```json
{
  "runId": "day-1",
  "completedAt": "2026-06-01T10:00:00.000Z",
  "findings": [
    {
      "id": "invoice-day-1",
      "ruleId": "BP-BOLA-002",
      "title": "Tenant escape",
      "severity": "high",
      "status": "validated",
      "fixStatus": "suggested",
      "proofMode": "static_trace",
      "affectedFiles": ["app/api/invoices/[id]/route.ts"],
      "affectedRoutes": ["GET /api/invoices/[id]"],
      "attackPath": ["GET /api/invoices/[id]", "Invoice"],
      "evidence": "Prisma Invoice lookup lacks tenantId",
      "exploitabilityReasoning": "Request id reaches Invoice",
      "recommendation": "Add tenantId",
      "patchStatus": "suggested",
      "verificationStatus": "not_run",
      "validation": { "mode": "local", "destructive": false, "productionTouched": false, "summary": "static trace" }
    }
  ],
  "verification": { "generatedAt": "2026-06-01T10:00:00.000Z", "items": [] }
}
```

`day-2.json` uses the same finding identity with `id: "invoice-day-2"`, `status: "fixed"`, `fixStatus` and `patchStatus` set to `verified_fixed`, `verificationStatus: "passed"`, and one verification item whose status is `verified_fixed`. `day-5.json` restores the invoice finding to `validated` and adds a complete `BP-BOLA-002` finding for `GET /api/orders/[id]` with the same `Invoice` sink and missing `tenantId` evidence. All timestamps are fixed ISO values on June 2 and June 5 respectively.

- [ ] **Step 2: Write the failing demo test**

```ts
test('tells the Day 1 bug, Day 2 fix, Day 5 similar and reopened story', async () => {
  const result = await buildVaultHistoryDemo(fixtureDirectory);
  expect(result.timeline.map(event => `${event.runId}:${event.lifecycle}`)).toEqual([
    'day-1:new', 'day-2:fixed', 'day-5:reopened', 'day-5:new'
  ]);
  expect(result.graph.edges.some(edge => edge.type === 'similar_to' && edge.score! >= 0.75)).toBe(true);
  expect(result.patchMemory.every(pattern => pattern.outcome === 'verified_fixed')).toBe(true);
});
```

- [ ] **Step 3: Implement the fixture demo helper using production projectors**

Create `tests/helpers/vault-demo.ts` using production store/projector APIs:

```ts
export async function buildVaultHistoryDemo(directory: string): Promise<{
  timeline: VaultTimelineEvent[];
  graph: VaultGraph;
  patchMemory: VaultPatchMemory[];
}>;
```

Do not export this helper from production code and do not create a second lifecycle implementation.

- [ ] **Step 4: Add the README demo**

Document:

```text
Day 1: /api/invoices/[id] violates tenant-isolation -> new
Day 2: tenant predicate replay is blocked -> verified fixed
Day 5: invoice issue returns -> reopened
Day 5: /api/orders/[id] has the same control/sink pattern -> similar bug detected
```

Embed a screenshot produced from the implemented report, not the generated design reference.

- [ ] **Step 5: Pass demo tests**

Run: `npx vitest run tests/core/vault-demo.test.ts`

Expected: PASS with deterministic event order and similarity evidence.

- [ ] **Step 6: Commit the demo**

```sh
git add tests/fixtures/vault-history tests/helpers/vault-demo.ts tests/core/vault-demo.test.ts README.md
git commit -m "docs: demonstrate Vault regression memory across runs"
```

## Task 11: Document Licenses, Safety, Architecture, And CI Artifacts

**Files:**
- Create: `THIRD_PARTY_NOTICES.md`
- Modify: `.gitignore`
- Modify: `.github/workflows/ci.yml`
- Modify: `docs/architecture.md`
- Modify: `docs/ci.md`
- Modify: `docs/safety-model.md`

- [ ] **Step 1: Add a failing notices/CI test**

```ts
test('documents renderer licenses and uploads the local Vault report', async () => {
  const notices = await readFile('THIRD_PARTY_NOTICES.md', 'utf8');
  const workflow = await readFile('.github/workflows/ci.yml', 'utf8');
  expect(notices).toContain('three');
  expect(notices).toContain('3d-force-graph');
  expect(notices).toContain('MIT');
  expect(workflow).toContain('reports/vault/');
  expect(workflow).toContain('npx playwright install --with-deps chromium');
});
```

- [ ] **Step 2: Run and confirm notices/CI are incomplete**

Run: `npx vitest run tests/core/vault-build.test.ts`

Expected: FAIL on missing notices and Vault CI paths.

- [ ] **Step 3: Document exact package provenance**

`THIRD_PARTY_NOTICES.md` must list package, resolved version, repository, license, and role for Three.js, 3d-force-graph, transitive d3-force-3d, Lucide, esbuild, and Playwright. State that visual meshes and node sprites are first-party procedural assets.

- [ ] **Step 4: Keep sensitive Vault outputs local and upload only CI artifacts**

Add generated Vault paths to `.gitignore`. Extend CI to install Chromium, run `npm run test:browser`, and include `reports/vault/` in the existing private workflow artifact upload. Do not publish to Pages or another public host.

- [ ] **Step 5: Update architecture and safety docs**

Document append-only local SQLite, no remote browser fetches, no automatic patch application, safe HTML embedding, WebGL fallback, and the route from proof artifacts to Vault projections.

- [ ] **Step 6: Pass docs/CI tests and commit**

Run:

```sh
npx vitest run tests/core/vault-build.test.ts
npm run lint
```

Then commit:

```sh
git add THIRD_PARTY_NOTICES.md .gitignore .github/workflows/ci.yml docs/architecture.md docs/ci.md docs/safety-model.md tests/core/vault-build.test.ts
git commit -m "docs: record Vault licenses safety and CI behavior"
```

## Task 12: Final Verification And Visual Fidelity

**Files:**
- Modify only files required by concrete failures found in this task
- Create: `docs/assets/breachproof-vault-implemented.png`

- [ ] **Step 1: Run the complete deterministic verification suite**

```sh
npm run typecheck
npm run lint
npm test
npm run build
node dist/cli/index.js doctor
node dist/cli/index.js run --auto --yes
npm run test:browser
git diff --check
```

Expected: every command passes. The run writes `reports/vault/index.html`, `graph.json`, timeline, route profiles, and static assets without modifying analyzed source.

- [ ] **Step 2: Verify the WebGL canvas and responsive framing**

Use Playwright screenshots at:

```text
1440x900
1280x720
390x844
```

For each viewport, assert the canvas contains non-background pixels, the graph bounding box intersects the viewport center, and top bar/tools/inspector/timeline do not overlap.

- [ ] **Step 3: Compare against the approved reference**

Check all required visual anchors:

- near-black full-screen scene
- top command bar
- left vertical tools
- cyan route geometry
- red active finding and particles
- amber controls
- mint verified fixes
- violet similarity/replay paths
- large protected asset geometry
- right evidence inspector
- bottom run-history timeline

Correct only measurable deviations. Do not redesign or add new visual motifs.

- [ ] **Step 4: Save the implemented screenshot and update README path**

Save the verified desktop screenshot as `docs/assets/breachproof-vault-implemented.png`. Ensure README references this implemented screenshot, not the design-generation image.

- [ ] **Step 5: Verify Docker only when the daemon is available**

Run: `docker version`

If the daemon is available, run:

```sh
docker build -t breachproof .
```

If unavailable, record that exact limitation; do not claim the image was built.

- [ ] **Step 6: Commit final verification adjustments**

```sh
git add docs/assets/breachproof-vault-implemented.png README.md
git commit -m "test: verify BreachProof Vault end to end"
```

If a product file changed to fix a concrete failure in this task, commit that fix immediately after its focused test passes, using the exact paths shown by `git status --short` and a message describing the failure. Never use `git add .`.

- [ ] **Step 7: Report completion without pushing unless requested**

Summarize artifacts, tests, screenshot result, bundle size, Docker status, and commit list. Do not push or rewrite remote history unless the user explicitly requests it.

# Architecture

BreachProof is organized as a set of deterministic local agents.

1. Scope Agent validates the approved workspace and mode.
2. Mapper Agent reads files and creates a structured system map.
3. Vulnerability Intelligence Agent normalizes OSV, CVE/NVD, GitHub advisory, KEV, EPSS, and rule-pack inputs.
4. Reachability Agent connects routes, code, imports, Prisma models, dependencies, auth, ownership checks, uploads, webhooks, jobs, and AI tools.
5. BOLA/IDOR Specialist Agent creates ownership traces and `BP-BOLA-*` findings.
6. Invariant Agent evaluates `breachproof.invariants.yml` against system, reachability, attack, and validation artifacts.
7. Local Cyber Range Composer writes fake tenants, fake users, fake records, and optional Docker Compose services.
8. Stateful API Sequence Agent creates local-only replay sequences from OpenAPI or inferred routes.
9. Attack Planner Agent creates safe validation plans.
10. Local Validation Agent produces proof evidence without destructive exploitation.
11. Fix Agent writes patch and regression-test artifacts.
12. Patch Tournament Agent writes multiple candidate fixes, scorecards, and a recommended patch.
13. Verification Agent records replay status against the original attack path or invariant.
14. Report Agent renders Markdown, JSON, SARIF, and static HTML.
15. Vault Projector records append-only security memory and renders Markdown notes, route profiles, lifecycle JSON, and the offline 3D graph.

The default workflow is:

```text
approve scope -> map -> corpus -> reachability -> range -> invariants -> evidence -> patch tournament -> verification -> final report -> Vault projection
```

## Vault Projection

Vault is a projection of artifacts already produced by the defensive workflow. The workflow sends the system map, findings, invariant results, patch summary, patch tournament, verification, and local replay-evidence summary through one orchestration boundary. That boundary:

1. computes stable finding fingerprints and a deterministic run identity
2. appends the run, finding, patch, and replay events to local SQLite
3. reads the complete local history
4. projects lifecycle events, similar findings, and verified patch memory
5. writes Markdown memory under `.breachproof/vault/`
6. writes the offline report under `reports/vault/`

The SQLite tables `vault_runs`, `vault_finding_events`, `vault_patch_events`, and `vault_replay_events` use insert-or-ignore event identities. Vault rebuilds are read-only projections and do not insert another run.

The report embeds schema-validated graph JSON with characters escaped for safe HTML script embedding. JavaScript and CSS are copied into the report; the content security policy denies network connections and remote runtime assets. Three.js node meshes and canvas sprites are generated procedurally by first-party code. If WebGL is unavailable, the same graph is rendered as an accessible semantic table and timeline.

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

The default workflow is:

```text
approve scope -> map -> corpus -> reachability -> range -> invariants -> evidence -> patch tournament -> verification -> final report
```
